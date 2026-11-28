"""Agent đa kênh (mục 2.2 tài liệu w8): reader/checkpoint/segment/health riêng mỗi kênh, lỗi một kênh không chặn kênh khác.
Nguồn giả trên Linux; dữ liệu SYNTHETIC. Không chứng minh hành vi trên Windows thật."""
import json
from pathlib import Path

import pytest
import yaml

import bronze_contract as bc
import windows_channels as wc
from agent.bronze_writer import verify_segment
from agent.multichannel import ChannelConfigError, MultiChannelAgent, resolve_channels
from agent.sources.base import SourceError
from agent.sources.fake_source import FakeEventSource
from common.config import ChannelConfig, ConfigError, load_config

ROOT = Path(__file__).resolve().parents[2]
SYSMON = list(bc.iter_raw_xml_from_file(ROOT / "poc/sysmon-collector/configs/synthetic_events.xml"))
FIX = ROOT / "tests/fixtures/windows_channels"
DEF = [next(bc.iter_raw_xml_from_file(FIX / "defender_1116.synthetic.xml")),
       next(bc.iter_raw_xml_from_file(FIX / "defender_5001.synthetic.xml"))]
PS = next(bc.iter_raw_xml_from_file(FIX / "ps4104_single.synthetic.xml"))
PS_MANY = [PS.replace("<EventRecordID>42<", f"<EventRecordID>{100 + i}<") for i in range(7)]


class Denied:
    def iter_events(self, bm):
        raise SourceError("C-006", "Access is denied.")
        yield  # pragma: no cover


def mk(tmp_path, sources, **kw):
    chans = [{"name": n, "xpath": wc.DEFAULT_XPATH[n]} for n in sources]
    seen = {}

    def factory(name, xpath):
        seen[name] = xpath
        return sources[name]
    a = MultiChannelAgent(chans, tmp_path / "home", tmp_path / "home" / "bronze", factory, **kw)
    return a, seen


def records(tmp_path):
    out = {}
    for s in sorted((tmp_path / "home" / "bronze").glob("seg-*.jsonl")):
        assert verify_segment(s) == []
        m = json.loads(s.with_suffix(".manifest.json").read_text())
        recs = [json.loads(l) for l in s.read_text(encoding="utf-8").splitlines()]
        assert len({r["channel"] for r in recs}) == 1          # mỗi segment một kênh
        out.setdefault(recs[0]["channel"], []).append((s.name, m, recs))
    return out


def test_resolve_channels_validates_and_applies_default_xpath():
    out = resolve_channels([ChannelConfig(wc.SYSMON_CHANNEL), ChannelConfig(wc.DEFENDER_CHANNEL, enabled=False),
                            ChannelConfig("microsoft-windows-powershell/operational", xpath="*")])
    assert out == [{"name": wc.SYSMON_CHANNEL, "xpath": "*"}, {"name": wc.POWERSHELL_CHANNEL, "xpath": "*"}]
    with pytest.raises(ChannelConfigError, match="CFG-006"):
        resolve_channels([ChannelConfig("Security")])
    with pytest.raises(ChannelConfigError, match="CFG-006"):
        resolve_channels([ChannelConfig(wc.SYSMON_CHANNEL, enabled=False)])


def test_each_channel_has_own_segments_checkpoint_and_source(tmp_path):
    a, seen = mk(tmp_path, {wc.SYSMON_CHANNEL: FakeEventSource(SYSMON), wc.DEFENDER_CHANNEL: FakeEventSource(DEF),
                            wc.POWERSHELL_CHANNEL: FakeEventSource([PS])})
    a.run_round(final=True)
    assert seen[wc.POWERSHELL_CHANNEL] == "*[System[(EventID=4104)]]"
    recs = records(tmp_path)
    (name, m, rs), = recs[wc.SYSMON_CHANNEL]
    assert name.startswith("seg-2") and m["schema_version"] == "bronze-event/1.0"   # tên segment Sysmon như cũ
    assert {r["source"] for r in rs} == {"SYSMON"} and len(rs) == len(SYSMON)
    (name, m, rs), = recs[wc.POWERSHELL_CHANNEL]
    assert name.startswith("seg-microsoft_windows_powershell_operational-")
    assert m["schema_version"] == "bronze-event/1.1" and m["first_record_id"] == m["last_record_id"] == 42
    assert [r["source"] for r in rs] == ["POWERSHELL"]
    assert [r["source"] for _, _, rs in recs[wc.DEFENDER_CHANNEL] for r in rs] == ["WINDOWS_DEFENDER"] * 2
    cps = sorted(p.name for p in (tmp_path / "home" / "agent").glob("checkpoint_live_*.json"))
    assert cps == ["checkpoint_live_microsoft_windows_powershell_operational.json",
                   "checkpoint_live_microsoft_windows_sysmon_operational.json",
                   "checkpoint_live_microsoft_windows_windows_defender_operational.json"]
    h = json.loads((tmp_path / "home" / "agent" / "health.json").read_text())
    assert h["state"] == "stopped" and h["events_written"] == len(SYSMON) + 3
    assert set(h["channels"]) == {wc.SYSMON_CHANNEL, wc.DEFENDER_CHANNEL, wc.POWERSHELL_CHANNEL}
    assert {"heartbeat", "last_event_at", "last_seal_at", "errors_by_code"} <= set(h)    # khóa cũ còn nguyên


def test_denied_channel_does_not_block_others_and_health_is_degraded(tmp_path):
    a, _ = mk(tmp_path, {wc.SYSMON_CHANNEL: FakeEventSource(SYSMON), wc.DEFENDER_CHANNEL: Denied()})
    a.run_round(final=False)
    assert len(records(tmp_path)[wc.SYSMON_CHANNEL][0][2]) == len(SYSMON)
    h = json.loads((tmp_path / "home" / "agent" / "health.json").read_text())
    assert h["state"] == "degraded" and h["channels"][wc.DEFENDER_CHANNEL]["state"] == "error"
    assert h["channels"][wc.DEFENDER_CHANNEL]["errors_by_code"] == {"C-006": 1}
    assert h["channels"][wc.SYSMON_CHANNEL]["state"] == "idle"
    assert a.source_failed and not a.failed


def test_all_channels_denied_is_error(tmp_path):
    a, _ = mk(tmp_path, {wc.SYSMON_CHANNEL: Denied(), wc.POWERSHELL_CHANNEL: Denied()})
    a.run_round()
    assert json.loads((tmp_path / "home" / "agent" / "health.json").read_text())["state"] == "error"


def test_round_robin_limit_resumes_from_checkpoint_without_loss(tmp_path):
    a, _ = mk(tmp_path, {wc.SYSMON_CHANNEL: FakeEventSource(SYSMON), wc.POWERSHELL_CHANNEL: FakeEventSource(PS_MANY)},
              max_events_per_run=3)
    a.run_round()
    assert a.has_backlog
    for _ in range(5):
        a.run_round()
    assert not a.has_backlog
    recs = records(tmp_path)
    ps_ids = [r["record_id"] for _, _, rs in recs[wc.POWERSHELL_CHANNEL] for r in rs]
    assert ps_ids == list(range(100, 107))                   # đủ, không trùng, đúng thứ tự
    assert sum(len(rs) for _, _, rs in recs[wc.SYSMON_CHANNEL]) == len(SYSMON)


def test_restart_continues_per_channel(tmp_path):
    srcs = {wc.SYSMON_CHANNEL: FakeEventSource(SYSMON), wc.POWERSHELL_CHANNEL: FakeEventSource(PS_MANY, stop_after=2)}
    a, _ = mk(tmp_path, srcs)
    a.run_round()
    a2, _ = mk(tmp_path, {wc.SYSMON_CHANNEL: FakeEventSource(SYSMON), wc.POWERSHELL_CHANNEL: FakeEventSource(PS_MANY)})
    a2.run_round()
    recs = records(tmp_path)
    assert sorted(r["record_id"] for _, _, rs in recs[wc.POWERSHELL_CHANNEL] for r in rs) == list(range(100, 107))
    assert sum(len(rs) for _, _, rs in recs[wc.SYSMON_CHANNEL]) == len(SYSMON)   # Sysmon không đọc lại


def test_legacy_sysmon_checkpoint_is_inherited_not_deleted(tmp_path):
    agent_dir = tmp_path / "home" / "agent"
    agent_dir.mkdir(parents=True)
    (agent_dir / "checkpoint_live.json").write_text(json.dumps({"bookmark": "1"}), encoding="utf-8")
    a, _ = mk(tmp_path, {wc.SYSMON_CHANNEL: FakeEventSource(SYSMON), wc.POWERSHELL_CHANNEL: FakeEventSource([PS])})
    a.run_round()
    assert (agent_dir / "checkpoint_live.json").exists()
    sysmon = records(tmp_path)[wc.SYSMON_CHANNEL]
    assert sum(len(rs) for _, _, rs in sysmon) == len(SYSMON) - 2      # tiếp sau bookmark "1", không đọc lại từ đầu


def test_main_live_reads_channels_from_config(tmp_path, monkeypatch):
    import agent.__main__ as am
    import agent.sources.eventlog as el
    opened = []

    class FakeLive:
        def __init__(self, channel, xpath):
            opened.append((channel, xpath))

        def iter_events(self, bm):
            return iter(())
    monkeypatch.setattr(el, "EventLogSource", FakeLive)
    cfg = tmp_path / "edr.yaml"
    cfg.write_text(yaml.safe_dump({"home": str(tmp_path / "home"), "agent": {"channels": [
        {"name": wc.SYSMON_CHANNEL}, {"name": wc.DEFENDER_CHANNEL, "enabled": False},
        {"name": wc.POWERSHELL_CHANNEL, "xpath": "*[System[(EventID=4104)]]"}]}}), encoding="utf-8")
    assert am.main(["run", "--config", str(cfg), "--live"]) == 0
    assert opened == [(wc.SYSMON_CHANNEL, "*"), (wc.POWERSHELL_CHANNEL, "*[System[(EventID=4104)]]")]


def test_main_live_rejects_unsupported_channel(tmp_path):
    import agent.__main__ as am
    cfg = tmp_path / "edr.yaml"
    cfg.write_text(yaml.safe_dump({"home": str(tmp_path / "home"), "agent": {"channels": [{"name": "Security"}]}}),
                   encoding="utf-8")
    assert am.main(["run", "--config", str(cfg), "--live"]) == 2


def _cfg(tmp_path, data):
    p = tmp_path / "c.yaml"
    p.write_text(yaml.safe_dump(data), encoding="utf-8")
    return p


def test_config_default_is_sysmon_only(tmp_path):
    assert load_config(_cfg(tmp_path, {"home": str(tmp_path)})).agent_channels == (ChannelConfig(wc.SYSMON_CHANNEL),)


def test_example_config_keeps_new_channels_disabled():
    chans = load_config(ROOT / "config/edr.example.yaml").agent_channels
    assert [(c.name, c.enabled) for c in chans] == [(wc.SYSMON_CHANNEL, True), (wc.DEFENDER_CHANNEL, False),
                                                    (wc.POWERSHELL_CHANNEL, False)]


@pytest.mark.parametrize("agent", [
    {"channels": []}, {"channels": [{"name": ""}]}, {"channels": [{"name": "x", "enabled": "yes"}]},
    {"channels": [{"name": "x", "enabled": False}]}, {"channels": [{"name": "x"}, {"name": "X"}]},
    {"channels": [{"name": "x", "foo": 1}]}, {"other": 1}, {"channels": [{"name": "x", "xpath": ""}]}])
def test_config_rejects_bad_channel_lists(tmp_path, agent):
    with pytest.raises(ConfigError):
        load_config(_cfg(tmp_path, {"home": str(tmp_path), "agent": agent}))


def test_writer_manifest_records_mixed_versions(tmp_path):
    """File mode đọc export nhiều kênh -> một writer; manifest ghi "mixed" kèm danh sách, không ghi sai 1.0."""
    from agent.bronze_writer import BronzeWriter
    w = BronzeWriter(tmp_path / "b")
    for x in (SYSMON[0], PS):
        w.append(bc.build_bronze_record(x, mode="file"))
    m = json.loads(w.seal().with_suffix(".manifest.json").read_text())
    assert m["schema_version"] == "mixed" and m["schema_versions"] == ["bronze-event/1.0", "bronze-event/1.1"]
