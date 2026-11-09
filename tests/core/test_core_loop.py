"""Vòng core phải sống sót sau exception và lộ lỗi ra status (/health)."""
import json

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
