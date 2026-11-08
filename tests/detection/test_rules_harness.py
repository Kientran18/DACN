import sys
from datetime import datetime, timezone, timedelta
from pathlib import Path

import pytest
import yaml

sys.path.insert(0, str(Path(__file__).parent))
import harness  # noqa: E402

from detection.engine import DetectionEngine  # noqa: E402
from detection.evaluator import evaluate_single  # noqa: E402
from detection.ioc import IocStore  # noqa: E402
from detection.loader import RuleError, load_rules, validate_rule  # noqa: E402
from detection.ml.interface import NullDetector  # noqa: E402
from detection.paths import normalize_path  # noqa: E402
from pipeline.silver_store import SilverStore  # noqa: E402


def test_label_matrix_all_expected_equal_observed(tmp_path):
    rows = harness.matrix(tmp_path)
    assert rows, "không có fixture"
    bad = [r for r in rows if not r["ok"]]
    assert not bad, bad


def test_all_shipped_rules_load_and_default_alert_only():
    rules = load_rules()
    assert {"DACN-DET-001", "DACN-DET-003", "DACN-DET-010"} <= set(rules)
    assert all(r["response_policy"] == "alert_only" for r in rules.values())


@pytest.mark.parametrize("patch", [
    {"rule_id": "DET-1"}, {"severity": "urgent"}, {"extra": 1}, {"rule_version": 0},
    {"mitre_technique_ids": ["T1059.001"], "mitre_basis": None},
])
def test_invalid_rules_are_rejected(patch):
    base = dict(yaml.safe_load(Path("src/detection/rules/dacn-det-001.yaml").read_text(encoding="utf-8")))
    base.update(patch)
    base = {k: v for k, v in base.items() if v is not None}
    with pytest.raises(RuleError):
        validate_rule(base, "t")


def test_blocked_rule_requires_reason_and_correlation_requires_window():
    base = {"rule_id": "DACN-DET-008", "rule_version": 1, "name": "n", "description": "d",
            "type": "single", "severity": "low", "status": "blocked", "sysmon_event_ids": [11]}
    with pytest.raises(RuleError):
        validate_rule(base, "t")
    with pytest.raises(RuleError):
        validate_rule({**base, "status": "enabled", "type": "correlation"}, "t")


def test_missing_required_field_is_insufficient_not_benign():
    rule = load_rules()["DACN-DET-003"]
    r = evaluate_single(rule, {"event_id": "e", "target_object": "", "process_guid": "g"})
    assert r.outcome == "INSUFFICIENT_TELEMETRY" and r.missing_fields == ["target_object"]


@pytest.mark.parametrize("raw,exp", [
    ('"C:/Users/X/A.EXE"', "c:\\users\\x\\a.exe"), ("\\\\?\\C:\\a.exe", "c:\\a.exe"),
    ("\\Device\\HarddiskVolume3\\a.exe", None), ("", None), (None, None)])
def test_normalize_path(raw, exp):
    assert normalize_path(raw) == exp


def _engine_with_hash(tmp_path, sha, ioc):
    st = SilverStore(tmp_path / "s.duckdb")
    fx = {"name": "ioc", "rows": [{"id": "p", "table": "process", "file_sha256": sha}]}
    for t, _, row in harness.build_rows(fx):
        st._insert(t, row)
    return DetectionEngine(st.con, rules=load_rules(), ioc=ioc)


def _ioc_file(tmp_path, sha, allow=(), expires=None):
    d = {"version": "test-1", "ioc_hashes": [{"sha256": sha, "source": "test-team", "note": "synthetic", "expires": expires}],
         "allowlist_hashes": list(allow)}
    p = tmp_path / "ioc.yaml"; p.write_text(yaml.safe_dump(d)); return p


def test_ioc_match_and_reason_states_hash_is_not_proof(tmp_path):
    sha = "a" * 64
    res = [r for r in _engine_with_hash(tmp_path, sha, IocStore(_ioc_file(tmp_path, sha))).run() if r.rule_id == "DACN-DET-101"]
    assert len(res) == 1 and "không đủ" in res[0].severity_reason


def test_allowlist_wins_over_ioc(tmp_path):
    sha = "b" * 64
    eng = _engine_with_hash(tmp_path, sha, IocStore(_ioc_file(tmp_path, sha, allow=[sha])))
    assert [r for r in eng.run() if r.rule_id == "DACN-DET-101"] == []


def test_expired_ioc_ignored(tmp_path):
    sha = "c" * 64
    past = (datetime.now(timezone.utc) - timedelta(days=1)).isoformat()
    eng = _engine_with_hash(tmp_path, sha, IocStore(_ioc_file(tmp_path, sha, expires=past)))
    assert [r for r in eng.run() if r.rule_id == "DACN-DET-101"] == []


def test_rule_version_bump_creates_new_evaluation(tmp_path):
    st = SilverStore(tmp_path / "s.duckdb")
    fx = {"name": "v", "rows": [{"id": "p", "table": "process", "image_path": "C:\\a\\powershell.exe",
                                 "command_line": "powershell.exe -enc AAAA"}]}
    for t, _, row in harness.build_rows(fx):
        st._insert(t, row)
    rules = load_rules()
    eng = DetectionEngine(st.con, rules=rules)
    assert len([r for r in eng.run() if r.rule_id == "DACN-DET-001"]) == 1
    rules["DACN-DET-001"]["rule_version"] = 2
    assert len([r for r in eng.run() if r.rule_id == "DACN-DET-001"]) == 1
    assert st.con.execute("select count(*) from _detection_results where rule_id='DACN-DET-001'").fetchone()[0] == 2


def test_pending_upgrades_to_match_when_delete_arrives(tmp_path):
    st = SilverStore(tmp_path / "s.duckdb")
    f = yaml.safe_load(Path("tests/detection/fixtures/det010_pending.yaml").read_text(encoding="utf-8"))
    for t, _, row in harness.build_rows(f):
        st._insert(t, row)
    eng = DetectionEngine(st.con, rules=load_rules())
    assert [r.outcome for r in eng.run() if r.rule_id == "DACN-DET-010"] == ["PENDING_LATE_EVENTS"]
    extra = {"name": f["name"], "rows": [{"id": "d", "table": "file", "sysmon_event_id": 26, "file_path": "C:\\t\\a.exe",
                                          "timestamp": "2026-01-01T10:01:00+00:00", "record_id": 99}]}
    for t, _, row in harness.build_rows(extra):
        row["record_id"] = 99; st._insert(t, row)
    assert [r.outcome for r in eng.run() if r.rule_id == "DACN-DET-010"] == ["MATCH"]
    assert st.con.execute("select count(*) from _detection_results where rule_id='DACN-DET-010'").fetchone()[0] == 1


def test_ml_off_by_default_and_never_triggers_response():
    assert NullDetector().score({"x": 1}) is None
    from detection.ml.interface import AnomalyResult
    assert AnomalyResult(0.9, "f1", "m1").triggers_response is False
