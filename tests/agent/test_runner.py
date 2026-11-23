import json
from pathlib import Path
from agent.runner import AgentRunner
from agent.bronze_writer import BronzeWriter, verify_segment
from agent.checkpoint import Checkpoint
from agent.sources.fake_source import FakeEventSource
import bronze_contract as bc

SYN = Path(__file__).resolve().parents[2] / "poc/sysmon-collector/configs/synthetic_events.xml"
XMLS = list(bc.iter_raw_xml_from_file(SYN))


def mk(tmp_path, src, **kw):
    return AgentRunner(src, BronzeWriter(tmp_path / "b", max_records=3),
                       Checkpoint(tmp_path / "cp.json"), tmp_path / "health.json", batch_size=2, **kw)


def ids(tmp_path):
    out = []
    for s in sorted((tmp_path / "b").glob("*.jsonl")):
        assert verify_segment(s) == []
        out += [json.loads(l)["event_id"] for l in s.read_text().splitlines()]
    return out


def test_full_run_writes_all_and_health(tmp_path):
    r = mk(tmp_path, FakeEventSource(XMLS)); r.run()
    assert len(ids(tmp_path)) == 4
    h = json.loads((tmp_path / "health.json").read_text())
    assert h["events_written"] == 4 and h["state"] == "stopped"


def test_stop_midway_then_restart_loses_nothing(tmp_path):
    mk(tmp_path, FakeEventSource(XMLS, stop_after=2)).run()
    mk(tmp_path, FakeEventSource(XMLS)).run()
    assert len(set(ids(tmp_path))) == 4


def test_crash_after_write_before_checkpoint_may_duplicate_not_lose(tmp_path):
    mk(tmp_path, FakeEventSource(XMLS)).run()
    (tmp_path / "cp.json").unlink()            # mô phỏng mất checkpoint
    mk(tmp_path, FakeEventSource(XMLS)).run()
    got = ids(tmp_path)
    assert len(got) == 8 and len(set(got)) == 4  # at-least-once; Silver dedup theo event_id


def test_bad_xml_is_counted_and_preserved_not_dropped(tmp_path):
    r = mk(tmp_path, FakeEventSource(["<Event><oops", XMLS[0]])); r.run()
    assert len(ids(tmp_path)) == 1
    h = json.loads((tmp_path / "health.json").read_text())
    assert h["errors_by_code"]["C-001"] == 1
    assert "<oops" in (tmp_path / "b" / "errors" / "collector_errors.jsonl").read_text()


def test_source_error_recorded_and_data_kept(tmp_path):
    r = mk(tmp_path, FakeEventSource(XMLS, fail_after=2)); r.run()
    h = json.loads((tmp_path / "health.json").read_text())
    assert h["errors_by_code"]["C-006"] == 1 and len(ids(tmp_path)) == 2


def test_stop_file_stops_loop(tmp_path):
    (tmp_path / "STOP").write_text("")
    r = mk(tmp_path, FakeEventSource(XMLS), stop_file=tmp_path / "STOP"); r.run()
    assert ids(tmp_path) == []


def test_corrupt_checkpoint_reported(tmp_path):
    (tmp_path / "cp.json").write_text("{bad")
    mk(tmp_path, FakeEventSource(XMLS)).run()
    h = json.loads((tmp_path / "health.json").read_text())
    assert h["errors_by_code"]["C-005"] == 1 and len(ids(tmp_path)) == 4


def test_health_last_seal_at_is_the_real_seal_time(tmp_path):
    """B6 (audit): last_seal_at là thời điểm seal segment gần nhất (khớp sealed_at của manifest), không phải giờ ghi health."""
    import time
    r = mk(tmp_path, FakeEventSource(XMLS))
    r.run(final=False)
    last = sorted((tmp_path / "b").glob("*.jsonl"))[-1]
    sealed_at = json.loads(last.with_suffix(".manifest.json").read_text())["sealed_at"]
    assert json.loads((tmp_path / "health.json").read_text())["last_seal_at"] == sealed_at
    time.sleep(0.01)
    r.run(final=False)            # không có sự kiện mới -> không seal gì -> giá trị giữ nguyên
    assert json.loads((tmp_path / "health.json").read_text())["last_seal_at"] == sealed_at


def test_health_last_seal_at_none_before_any_seal(tmp_path):
    r = mk(tmp_path, FakeEventSource([]))
    r.run()
    assert json.loads((tmp_path / "health.json").read_text())["last_seal_at"] is None


class _FailingWriter(BronzeWriter):
    """Mô phỏng đĩa đầy: append thứ `fail_at` (đếm từ 1) hoặc flush ném OSError(ENOSPC)."""
    def __init__(self, *a, fail_append_at=None, fail_flush=False, **k):
        super().__init__(*a, **k)
        self.n_append, self.fail_append_at, self.fail_flush = 0, fail_append_at, fail_flush

    def append(self, record):
        self.n_append += 1
        if self.n_append == self.fail_append_at:
            raise OSError(28, "No space left on device")
        super().append(record)

    def flush(self):
        if self.fail_flush:
            raise OSError(28, "No space left on device")
        super().flush()


def _health(tmp_path):
    return json.loads((tmp_path / "health.json").read_text())


def test_disk_write_failure_is_c004_stops_without_losing_events(tmp_path):
    """N1 (audit): hợp đồng W5 (C-004): ghi đĩa thất bại -> dừng nạp, KHÔNG nâng checkpoint quá phần đã bền, có cảnh báo.
    Trước đây run() ném OSError và health.json ghi 'stopped' với errors_by_code rỗng."""
    w = _FailingWriter(tmp_path / "b", max_records=3, fail_append_at=3)
    r = AgentRunner(FakeEventSource(XMLS), w, Checkpoint(tmp_path / "cp.json"), tmp_path / "health.json", batch_size=2)
    r.run(final=False)                                            # không được ném
    h = _health(tmp_path)
    assert h["state"] == "error" and h["errors_by_code"].get("C-004") == 1 and r.failed is True
    assert json.loads((tmp_path / "cp.json").read_text())["bookmark"] == "1"       # chỉ 2 bản ghi đầu đã bền
    mk(tmp_path, FakeEventSource(XMLS)).run()                      # đĩa ổn lại: tiếp tục từ checkpoint
    assert len(set(ids(tmp_path))) == 4                            # không mất sự kiện nào


def test_flush_failure_does_not_advance_checkpoint(tmp_path):
    w = _FailingWriter(tmp_path / "b", max_records=100, fail_flush=True)
    r = AgentRunner(FakeEventSource(XMLS), w, Checkpoint(tmp_path / "cp.json"), tmp_path / "health.json", batch_size=2)
    r.run(final=False)
    assert not (tmp_path / "cp.json").exists() and r.failed is True and _health(tmp_path)["errors_by_code"].get("C-004", 0) >= 1
    mk(tmp_path, FakeEventSource(XMLS)).run()
    assert len(set(ids(tmp_path))) == 4


def test_undecodable_xml_file_is_c003_not_a_crash(tmp_path):
    """N1 (audit): lỗi giải mã văn bản (C-003) làm run() ném UnicodeDecodeError; hợp đồng: ghi mã lỗi và không chết."""
    from agent.sources.file_source import FileEventSource
    bad = tmp_path / "bad.xml"
    bad.write_bytes(b"\x80\x81\x82 not utf-8")
    r = mk(tmp_path, FileEventSource(bad))
    r.run()
    assert _health(tmp_path)["errors_by_code"] == {"C-003": 1} and r.failed is False
    line = json.loads((tmp_path / "b" / "errors" / "collector_errors.jsonl").read_text().splitlines()[0])
    assert line["code"] == "C-003" and line["raw_xml"] is None        # có dấu vết, không bịa nội dung


def test_cli_exits_nonzero_on_write_failure_but_zero_when_healthy(tmp_path, monkeypatch):
    import agent.__main__ as cli
    monkeypatch.setenv("EDR_HOME", str(tmp_path / "home"))
    assert cli.main(["run", "--input", str(SYN)]) == 0
    monkeypatch.setenv("EDR_HOME", str(tmp_path / "home2"))
    monkeypatch.setattr(cli, "BronzeWriter", lambda d: _FailingWriter(d, fail_append_at=2))
    assert cli.main(["run", "--input", str(SYN)]) == 1


def test_source_error_sets_health_error_not_idle(tmp_path):
    """VM Windows: nguồn live lỗi A-002 ở mọi lượt poll nhưng health vẫn 'idle' và dashboard báo agent bình thường."""
    from agent.sources.base import SourceError

    class Broken:
        def iter_events(self, bm):
            raise SourceError("A-002", "error: (87, 'EvtSubscribe', 'The parameter is incorrect.')")
            yield  # pragma: no cover

    r = AgentRunner(Broken(), BronzeWriter(tmp_path / "b"), Checkpoint(tmp_path / "cp.json"), tmp_path / "health.json")
    r.run(final=False)
    h = json.loads((tmp_path / "health.json").read_text(encoding="utf-8"))
    assert h["state"] == "error" and h["errors_by_code"]["A-002"] == 1


def test_file_and_live_modes_do_not_share_a_checkpoint(tmp_path, monkeypatch):
    """VM Windows: chạy file mode (bookmark '2') rồi --live -> agent đưa '2' vào EvtCreateBookmark. Mỗi nguồn cần checkpoint riêng."""
    import agent.__main__ as am
    import agent.sources.eventlog as el
    import yaml
    seen = {}

    class FakeLive:
        def iter_events(self, bm):
            seen["bm"] = bm
            return iter(())

    monkeypatch.setattr(el, "EventLogSource", FakeLive)
    cfg = tmp_path / "edr.yaml"
    cfg.write_text(yaml.safe_dump({"home": str(tmp_path / "home")}), encoding="utf-8")
    xml = tmp_path / "e.xml"
    xml.write_text(Path("references/samples/raw/raw_process_create_event1.xml").read_text(encoding="utf-8"), encoding="utf-8")
    assert am.main(["run", "--config", str(cfg), "--input", str(xml)]) == 0
    am.main(["run", "--config", str(cfg), "--live"])
    assert seen["bm"] is None


def test_live_source_error_without_follow_exits_nonzero(tmp_path, monkeypatch):
    """AT-04: không có quyền đọc kênh -> C-006 và agent (không --follow) thoát mã khác 0, không im lặng thoát 0."""
    import agent.__main__ as am
    import agent.sources.eventlog as el
    import yaml
    from agent.sources.base import SourceError

    class Denied:
        def iter_events(self, bm):
            raise SourceError("C-006", "error: (5, 'EvtQuery', 'Access is denied.')")
            yield  # pragma: no cover

    monkeypatch.setattr(el, "EventLogSource", Denied)
    cfg = tmp_path / "edr.yaml"
    cfg.write_text(yaml.safe_dump({"home": str(tmp_path / "home")}), encoding="utf-8")
    assert am.main(["run", "--config", str(cfg), "--live"]) == 1
