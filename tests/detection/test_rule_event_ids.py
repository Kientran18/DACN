"""U6 (audit): rule single/ioc dùng Event ID có bảng Silver (5, 15, 23, 26) không được làm engine KeyError;
rule ĐANG BẬT dùng Event ID không có bảng Silver phải bị loader từ chối ngay, không đợi tới lúc chạy."""
import pytest

from detection.engine import DetectionEngine
from detection.loader import RuleError, validate_rule
from pipeline.silver_store import SilverStore
from validator_poc import SUPPORTED_SYSMON_IDS


def rule(ids, status="enabled"):
    r = {"rule_id": "DACN-DET-990", "rule_version": 1, "name": "t", "description": "synthetic", "type": "single",
         "severity": "low", "status": status, "sysmon_event_ids": ids,
         "match": {"all": [{"field": "image_path", "op": "endswith_any", "value": ["\\x.exe"]}]}}
    if status == "blocked":
        r["blocked_reason"] = "test"
    return r


@pytest.mark.parametrize("eid", sorted(SUPPORTED_SYSMON_IDS))
def test_engine_handles_every_event_id_the_validator_routes_to_silver(tmp_path, eid):
    st = SilverStore(tmp_path / "s.duckdb")
    r = validate_rule(rule([eid]))
    assert DetectionEngine(st.con, rules={r["rule_id"]: r}).run() == []


def test_enabled_rule_with_event_id_without_silver_table_is_rejected():
    with pytest.raises(RuleError, match="sysmon_event_ids"):
        validate_rule(rule([4]))
    validate_rule(rule([4], status="blocked"))      # rule bị chặn không chạy nên vẫn nạp được
