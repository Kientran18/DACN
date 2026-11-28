"""Vòng core phải sống sót sau exception và lộ lỗi ra status (/health)."""

import bronze_contract as bc
from agent.bronze_writer import BronzeWriter
from core.service import CoreService
from pipeline.silver_store import SilverStore

from pathlib import Path
SYN = Path(__file__).resolve().parents[2] / "poc/sysmon-collector/configs/synthetic_events.xml"


def test_run_forever_survives_exception_and_records_last_error(tmp_path):
    svc = CoreService(SilverStore(tmp_path / "s.duckdb"), tmp_path / "b", tmp_path / "m.jsonl", rules={})
    calls = []

    def cycle():
        calls.append(1)
        if len(calls) == 1:
            raise RuntimeError("boom")
        svc.stop.set()
        return {}
    svc.cycle = cycle
    svc.run_forever(interval_s=0.01)
    assert len(calls) == 2                                    # vòng sau lỗi vẫn chạy
    assert svc.status()["last_error"]["type"] == "RuntimeError"
    assert svc.status()["last_cycle_ok_utc"] is not None


def test_real_cycle_with_unreadable_manifest_quarantines_segment_instead_of_raising(tmp_path):
    bdir = tmp_path / "b"
    w = BronzeWriter(bdir)
    for i, x in enumerate(bc.iter_raw_xml_from_file(SYN)):
        w.append(bc.build_bronze_record(x, mode="file", seq=i))
    seg = w.seal()
    good = seg.with_suffix(".manifest.json").read_text()
    seg.with_suffix(".manifest.json").write_text(good[:20])         # manifest ghi dở
    svc = CoreService(SilverStore(tmp_path / "s.duckdb"), bdir, tmp_path / "m.jsonl", rules={})
    assert svc.cycle()["segments_quarantined"] == 1                  # không ném ngoại lệ
    seg.with_suffix(".manifest.json").write_text(good)               # manifest hoàn chỉnh: vòng sau nạp được
    m = svc.cycle()
    assert m["segments_ingested"] == 1 and m["records_inserted"] > 0


def test_cycle_ingest_budget_lets_detection_run_with_backlog(tmp_path):
    """Lỗi quan sát trên Windows 10 VM (2026-11-28): một vòng nạp hết hàng đợi mất 1.962 s, Detection chờ suốt thời gian đó.
    Với ngân sách, mỗi vòng nạp >= 1 segment rồi chạy Detection; hàng đợi giảm dần qua các vòng."""
    bdir = tmp_path / "b"
    xmls = list(bc.iter_raw_xml_from_file(SYN))
    for k in range(3):
        w = BronzeWriter(bdir, name_prefix=f"x{k}-")
        for i, x in enumerate(xmls):
            w.append(bc.build_bronze_record(x, mode="file", seq=i))
        w.seal()
    st = SilverStore(tmp_path / "s.duckdb")
    svc = CoreService(st, bdir, tmp_path / "m.jsonl", ingest_budget_s=0)
    m = svc.cycle()
    assert m["segments_ingested"] == 1 and m["pending_segments"] == 2
    assert st.con.execute("select count(*) from _detection_cursor").fetchone()[0] == 1     # Detection đã chạy
    svc.cycle(); m = svc.cycle()
    assert m["pending_segments"] == 0
    assert svc.status()["last_ingest"]["pending_segments"] == 0                          # /health thấy được hàng đợi
