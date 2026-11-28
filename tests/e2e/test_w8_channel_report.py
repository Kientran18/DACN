"""Kiểm thử w8_channel_report trên dữ liệu SYNTHETIC (fixture tests/fixtures/windows_channels). Không phải telemetry thật.
Mục tiêu: đếm đúng theo kênh, cân bằng ledger, nạp segment core chưa nạp, nối tiến trình, KHÔNG làm lộ định danh/script."""
import json
import sys
from pathlib import Path

HERE = Path(__file__).parent
sys.path.insert(0, str(HERE))
sys.path.insert(0, str(HERE.parent / "detection"))
import harness  # noqa: E402
import w8_channel_report as wr  # noqa: E402

import bronze_contract as bc  # noqa: E402
import windows_channels as wc  # noqa: E402
from agent.bronze_writer import BronzeWriter  # noqa: E402
from pipeline.silver_store import SilverStore  # noqa: E402

FIX = HERE.parents[1] / "tests/fixtures/windows_channels"
PS_IMG = "C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe"
DEF = "Microsoft-Windows-Windows Defender/Operational"
PS = "Microsoft-Windows-PowerShell/Operational"


def write_channel(bdir, channel, fixtures):
    w = BronzeWriter(bdir, name_prefix=f"{wc.channel_slug(channel)}-")
    for n in fixtures:
        for x in bc.iter_raw_xml_from_file(FIX / n):
            w.append(bc.build_bronze_record(x, mode="file"))
    return w.seal()


def setup(tmp_path, ingest_ps=True):
    bdir = tmp_path / "bronze"
    def_seg = write_channel(bdir, DEF, ["defender_1116.synthetic.xml", "defender_1117.synthetic.xml"])
    ps_seg = write_channel(bdir, PS, ["ps4104_three_parts.synthetic.xml", "ps4104_single.synthetic.xml"])
    silver = tmp_path / "silver" / "endpoint_silver.duckdb"
    silver.parent.mkdir()
    st = SilverStore(silver)
    st.ingest_segment(def_seg, "core")
    if ingest_ps:
        st.ingest_segment(ps_seg, "core")
    for t, _, row in harness.build_rows({"name": "w8", "rows": [{"id": "p", "hostname": "SYNTH-HOST", "record_id": 9001,
                                         "table": "process", "process_guid": "dddddddd-0000-0000-0000-000000000001",
                                         "pid": 3333, "image_path": PS_IMG, "timestamp": "2026-11-28T00:59:00+00:00"}]}):
        st._insert(t, row)
    st.close()
    return silver, bdir


def test_segment_name_maps_to_channel():
    assert wr.channel_of_segment("seg-microsoft_windows_powershell_operational-20261128T010000Z-0001.jsonl") == PS
    assert wr.channel_of_segment("seg-microsoft_windows_windows_defender_operational-x-0001.jsonl") == DEF
    assert wr.channel_of_segment("seg-20261128T010000Z-0001.jsonl") == "Microsoft-Windows-Sysmon/Operational"


def test_report_counts_and_ingests_missing_segment(tmp_path):
    silver, bdir = setup(tmp_path, ingest_ps=False)
    rep = wr.build_report(silver, bdir)
    assert rep["segments_ingested_by_report"] == 1                    # segment PowerShell core chưa nạp
    assert rep["bronze"]["channels"][PS]["source_values"] == {"POWERSHELL": rep["bronze"]["channels"][PS]["records"]}
    assert rep["bronze"]["channels"][DEF]["source_values"] == {"WINDOWS_DEFENDER": 2}
    assert all(c["channel_mismatch"] == 0 for c in rep["bronze"]["channels"].values())
    assert rep["ledger"][PS]["balanced"] and rep["ledger"][DEF]["balanced"]
    assert rep["silver"]["defender_by_event_id"] == {"1116": 1, "1117": 1}
    ps = rep["silver"]["powershell"]
    assert ps["multi_part_blocks"] == 1 and ps["complete_blocks_view"] >= 1
    rules = {a["rule_id"] for a in rep["alerts_after_report_ingest"]["alerts"]}
    assert "DACN-DET-201" in rules
    assert rep["alerts_after_report_ingest"]["alerts_with_process_guid_new_rules"] == 0
    assert rep["process_links"]["powershell_blocks"]["total"] >= 1


def test_since_splits_old_and_new(tmp_path):
    silver, bdir = setup(tmp_path)
    late = wr.build_report(silver, bdir, since="2030-01-01T00:00:00+00:00")["since"]
    assert late["alerts"] == [] and late["defender_events"] == [] and late["powershell_rows"] == 0
    early = wr.build_report(silver, bdir, since="2020-01-01T00:00:00+00:00")["since"]
    assert {a["rule_id"] for a in early["alerts"]} >= {"DACN-DET-201"}
    assert {e["windows_event_id"] for e in early["defender_events"]} == {1116, 1117}


def test_report_never_leaks_identity_or_script(tmp_path):
    silver, bdir = setup(tmp_path)
    rep = wr.build_report(silver, bdir, since="2020-01-01T00:00:00+00:00")
    dumped = json.dumps(rep, default=str) + wr.to_markdown(rep)
    texts = [r[0] for r in SilverStore(silver).con.execute(
        "select script_block_text from silver_powershell_scriptblock_events").fetchall()]
    for secret in ["SYNTH-HOST", "labuser", "S-1-5-21", "C:\\\\Users", "dacn_lab", PS_IMG.replace("\\", "\\\\")] + texts:
        assert secret.lower() not in dumped.lower(), secret
    assert "powershell.exe" in json.dumps(rep["process_links"]["powershell_blocks"]["candidate_images"])


def test_cli_writes_files(tmp_path):
    silver, bdir = setup(tmp_path)
    out, js = tmp_path / "r.md", tmp_path / "r.json"
    assert wr.main(["--silver", str(silver), "--bronze", str(bdir), "--out", str(out), "--json", str(js)]) == 0
    assert out.read_text(encoding="utf-8").startswith("# Báo cáo") and json.loads(js.read_text(encoding="utf-8"))["kind"]
