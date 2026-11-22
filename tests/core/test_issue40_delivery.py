import sys
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).parents[1] / "detection"))
import harness

from core.service import CoreService
from detection.engine import DetectionEngine
from detection.loader import load_rules
from pipeline.silver_store import SilverStore


def test_restart_after_evaluation_before_publish_delivers_once_and_ack_is_atomic(tmp_path, monkeypatch):
    import core.service as module
    st = SilverStore(tmp_path / "s.duckdb")
    fx = {"name": "outbox", "rows": [{"id": "p", "table": "process", "timestamp": "2026-01-01T10:00:00Z",
           "image_path": r"C:\lab\powershell.exe", "command_line": "powershell -enc AAAAAAAA"}]}
    for t, _, row in harness.build_rows(fx): st._insert(t, row)
    rules = load_rules()
    engine = DetectionEngine(st.con, rules=rules)
    assert any(r.rule_id == "DACN-DET-001" for r in engine.run())
    # Giả lập crash: close/reopen sau commit evaluation, trước AlertBuilder.
    st.close(); st = SilverStore(tmp_path / "s.duckdb")
    # Rule bị gỡ sau restart: outbox vẫn giữ metadata version cũ để giao đúng alert.
    svc = CoreService(st, tmp_path / "bronze", tmp_path / "metrics.jsonl", rules={})
    real = module.build_from_results
    def fail_after_build(*args):
        real(*args)
        raise RuntimeError("crash before ack")
    monkeypatch.setattr(module, "build_from_results", fail_after_build)
    with pytest.raises(RuntimeError): svc.cycle()
    assert st.con.execute("select count(*) from alerts").fetchone()[0] == 0
    assert st.con.execute("select count(*) from _detection_outbox").fetchone()[0] > 0
    monkeypatch.setattr(module, "build_from_results", real)
    assert svc.cycle()["alerts_created"] == 1
    assert st.con.execute("select count(*) from _detection_outbox").fetchone()[0] == 0
    assert svc.cycle()["alerts_created"] == 0
    st.close()
