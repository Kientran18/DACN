import sys
from datetime import datetime, timezone
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent))
import harness

from detection.engine import DetectionEngine
from detection.loader import load_rules
from detection.process_context import process_context
from pipeline.silver_store import SilverStore


def test_cross_host_watermark_cannot_close_chain_and_late_event_corrects_closed_result(tmp_path):
    st = SilverStore(tmp_path / "s.duckdb")
    fx = {"name": "issue40", "rows": [
        {"id": "c", "table": "file", "timestamp": "2026-01-01T10:00:00Z"},
        {"id": "e", "table": "process", "image_path": r"C:\t\a.exe", "timestamp": "2026-01-01T10:00:20Z"},
        {"id": "other", "table": "network", "hostname": "OTHER", "timestamp": "2026-01-01T12:00:00Z"}]}
    for t, _, row in harness.build_rows(fx): st._insert(t, row)
    engine = DetectionEngine(st.con, rules=load_rules())
    assert [r.outcome for r in engine.run() if r.rule_id == "DACN-DET-010"] == ["PENDING_LATE_EVENTS"]
    close = {"name": "close", "rows": [{"id": "n", "table": "network", "timestamp": "2026-01-01T11:00:00Z"}]}
    for t, _, row in harness.build_rows(close): st._insert(t, row)
    assert [r.outcome for r in engine.run() if r.rule_id == "DACN-DET-010"] == ["NO_MATCH"]
    late = {"name": "late", "rows": [{"id": "d", "table": "file", "sysmon_event_id": 26,
                                      "operation": "FILE_DELETE", "timestamp": "2026-01-01T10:00:40Z"}]}
    for t, _, row in harness.build_rows(late): st._insert(t, row)
    assert [r.outcome for r in engine.run() if r.rule_id == "DACN-DET-010"] == ["MATCH"]
    assert engine.run() == []
    st.close()


def test_process_join_host_lifetime_and_partial_ancestry():
    at = lambda h: datetime(2026, 1, 1, h, tzinfo=timezone.utc)
    start = {"hostname": "H", "process_guid": "G", "parent_guid": "P", "sysmon_event_id": 1, "timestamp": at(1)}
    parent_other_host = {"hostname": "OTHER", "process_guid": "P", "sysmon_event_id": 1, "timestamp": at(0)}
    event = {"hostname": "H", "process_guid": "G", "timestamp": at(3)}
    assert process_context(event, [start, parent_other_host])["status"] == "PARTIAL_ANCESTRY"
    stop = {**start, "sysmon_event_id": 5, "timestamp": at(2)}
    assert process_context(event, [start, stop])["status"] == "OUTSIDE_LIFETIME"
    assert process_context({**event, "hostname": "OTHER"}, [start])["process"] is None
