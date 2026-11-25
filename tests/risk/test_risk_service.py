"""RiskService: gom thành phần từ alerts / _ml_signals / coverage_gaps / allowlist / candidate static.
Dữ liệu SYNTHETIC; không phải telemetry thật."""
import ast
import sys
from datetime import datetime, timedelta, timezone
from pathlib import Path

import pytest

HERE = Path(__file__).resolve().parent
sys.path.insert(0, str(HERE.parent / "detection"))
import harness  # noqa: E402

from alerts.store import AlertStore  # noqa: E402
from detection.ioc import IocStore  # noqa: E402
from detection.loader import load_rules  # noqa: E402
from detection.ml.signals import INSUFFICIENT, SCORED, MLSignalStore  # noqa: E402
from pipeline.silver_store import SilverStore  # noqa: E402
from risk.config import load_risk_config  # noqa: E402
from risk.service import RiskService  # noqa: E402

ROOT = Path(__file__).resolve().parents[2]
G1, G2 = "11111111-1111-1111-1111-111111111111", "22222222-2222-2222-2222-222222222222"
SHA = "a" * 64
T0 = datetime(2026, 1, 1, 10, tzinfo=timezone.utc)


def alert(store, key, rule_id, severity, t, guid=G1, host="LABHOST", source="RULE", status=None, matched=None):
    aid = store.insert_alert(detection_dedup_key=key, group_key=key, first_seen_utc=t, last_seen_utc=t,
                             detection_source=source, rule_id=rule_id, rule_version=1, rule_name=rule_id,
                             severity=severity, severity_reason="synthetic", hostname=host, process_guid=guid,
                             contributing_event_ids=[], matched_fields=matched or {})
    if status == "FALSE_POSITIVE":
        store.transition(aid, "TRIAGED", actor="a", note="n")
        store.transition(aid, "FALSE_POSITIVE", actor="a", note="lành tính")
    return aid


@pytest.fixture
def env(tmp_path):
    st = SilverStore(tmp_path / "s.duckdb")
    ids = {}
    for t, rid, row in harness.build_rows({"name": "risk", "rows": [
            {"id": "p1", "table": "process", "process_guid": G1, "file_sha256": SHA,
             "image_path": "C:\\lab\\tool.exe", "timestamp": "2026-01-01T10:00:00+00:00"},
            {"id": "p2", "table": "process", "process_guid": G2, "image_path": "C:\\lab\\other.exe",
             "timestamp": "2026-01-01T10:00:00+00:00"}]}):
        st._insert(t, row)
        ids[rid] = row["event_id"]
    return {"st": st, "store": AlertStore(st.con), "rules": load_rules(), "cfg": load_risk_config(), "ids": ids,
            "tmp": tmp_path}


def svc(env, **kw):
    return RiskService(env["st"].con, env["rules"], env["cfg"], **kw)


def test_process_subject_combines_rule_and_correlation(env):
    alert(env["store"], "k1", "DACN-DET-001", "medium", T0)
    alert(env["store"], "k2", "DACN-DET-010", "high", T0 + timedelta(seconds=5))   # DET-010 là correlation
    r = svc(env).process("LABHOST", G1)
    cats = {c["category"] for c in r["components"]}
    assert cats == {"RULE", "CORRELATION"}
    assert r["score"] == 25 + 54 + 10 and r["level"] == "critical"
    assert r["subject"] == {"kind": "process", "hostname": "LABHOST", "process_guid": G1}
    assert r["triggers_response"] is False


def test_ml_disabled_is_listed_not_scored(env):
    alert(env["store"], "k1", "DACN-DET-001", "medium", T0)
    r = svc(env).process("LABHOST", G1)
    assert {x["source"] for x in r["not_evaluated"]} == {"ML_STATIC", "ML_BEHAVIOR"}
    assert all("DISABLED" in x["reason"] for x in r["not_evaluated"])


def test_ml_signals_contribute_and_insufficient_is_explained(env):
    ml = MLSignalStore(env["st"].con)
    ml.record("ML_BEHAVIOR", SCORED, score=0.5, hostname="LABHOST", process_guid=G1, source_event_ids=[env["ids"]["p1"]],
              observed_at=T0, model_version="b1", explanation={"features": {}})
    ml.record("ML_STATIC", INSUFFICIENT, reason="DEPENDENCY_MISSING", hostname="LABHOST", process_guid=G1,
              source_event_ids=[], observed_at=T0, model_version="s1")
    r = svc(env, ml_enabled={"ML_STATIC": True, "ML_BEHAVIOR": True}).process("LABHOST", G1)
    ml_comp = [c for c in r["components"] if c["category"] == "ML_BEHAVIOR"]
    assert ml_comp and ml_comp[0]["points"] == 6.0 and ml_comp[0]["details"]["source_event_ids"] == [env["ids"]["p1"]]
    assert r["not_evaluated"] == [{"source": "ML_STATIC", "reason": "DEPENDENCY_MISSING",
                                   "signal_id": r["not_evaluated"][0]["signal_id"]}]
    assert r["score"] == 6.0 and r["level"] == "low"


def test_ml_enabled_but_not_yet_scored(env):
    r = svc(env, ml_enabled={"ML_STATIC": False, "ML_BEHAVIOR": True}).process("LABHOST", G1)
    reasons = {x["source"]: x["reason"] for x in r["not_evaluated"]}
    assert reasons["ML_BEHAVIOR"].startswith("NOT_SCORED")


def test_false_positive_alert_excluded_with_reason(env):
    alert(env["store"], "k1", "DACN-DET-001", "high", T0, status="FALSE_POSITIVE")
    r = svc(env).process("LABHOST", G1)
    assert r["score"] == 0 and r["components"][0]["included"] is False
    assert "FALSE_POSITIVE" in r["components"][0]["reason"]


def test_allowlisted_process_hash_reduces_score(env):
    (env["tmp"] / "ioc.yaml").write_text(f"version: 1\nallowlist_hashes: ['{SHA}']\n", encoding="utf-8")
    alert(env["store"], "k1", "DACN-DET-001", "high", T0)
    alert(env["store"], "k2", "DACN-DET-001", "high", T0, guid=G2)
    s = svc(env, ioc=IocStore(env["tmp"] / "ioc.yaml"))
    a, b = s.process("LABHOST", G1), s.process("LABHOST", G2)
    assert a["score"] == pytest.approx(13.5) and "allowlist" in a["components"][0]["reason"]
    assert b["score"] == 45


def test_static_alert_excluded_when_candidate_allowlisted(env):
    aid = alert(env["store"], "ks", "DACN-STATIC-001", "medium", T0, source="IOC")
    from static_analysis.review import CandidateStore
    cs = CandidateStore(env["st"].con)
    env["st"].con.execute("insert into static_candidates (candidate_id,schema_version,state,revision,created_by,"
                          "analysis,verdict,detection,alert_ids) values ('c1','dacn-candidate/1.0','ALLOWLISTED',3,'a',"
                          "'{}','{}','{}',?)", [f'["{aid}"]'])
    assert cs.get("c1")["state"] == "ALLOWLISTED"
    r = svc(env).process("LABHOST", G1)
    c = r["components"][0]
    assert c["category"] == "STATIC" and c["included"] is False and "ALLOWLISTED" in c["reason"]


def test_coverage_gap_listed_not_scored(env):
    env["store"].add_gap(detection_dedup_key="g1", rule_id="DACN-DET-001", rule_version=1, hostname="LABHOST",
                         contributing_event_ids=[env["ids"]["p1"]], missing_fields=["command_line"],
                         coverage_status="PARTIAL")
    r = svc(env).process("LABHOST", G1)
    assert r["score"] == 0 and r["data_gaps"][0]["missing_fields"] == ["command_line"]
    assert r["completeness"] == "PARTIAL"
    assert svc(env).process("LABHOST", G2)["data_gaps"] == []


def test_host_window_uses_data_time(env):
    alert(env["store"], "old", "DACN-DET-001", "high", T0 - timedelta(hours=5))
    alert(env["store"], "new1", "DACN-DET-001", "medium", T0)
    alert(env["store"], "new2", "DACN-DET-003", "medium", T0, guid=None)
    r = svc(env).host("LABHOST")
    assert r["subject"]["window_end"] == T0.isoformat() and r["subject"]["window_seconds"] == 3600
    assert sorted(c["ref_id"] for c in r["components"]) == sorted(
        x[0] for x in env["st"].con.execute("select alert_id from alerts where detection_dedup_key in ('new1','new2')").fetchall())
    older = svc(env).host("LABHOST", until=T0 - timedelta(hours=4, minutes=30))
    assert len(older["components"]) == 1 and older["score"] == 45


def test_subjects_sorted_and_filtered(env):
    alert(env["store"], "k1", "DACN-DET-001", "low", T0)
    alert(env["store"], "k2", "DACN-DET-001", "high", T0, guid=G2)
    items = svc(env).subjects("process")
    assert [i["subject"]["process_guid"] for i in items] == [G2, G1]
    assert [i["subject"]["process_guid"] for i in svc(env).subjects("process", min_level="medium")] == [G2]
    hosts = svc(env).subjects("host")
    assert len(hosts) == 1 and hosts[0]["subject"]["hostname"] == "LABHOST"


def test_for_alert_uses_process_or_host_subject(env):
    a1 = alert(env["store"], "k1", "DACN-DET-001", "medium", T0)
    a2 = alert(env["store"], "k2", "DACN-DET-003", "medium", T0, guid=None)
    s = svc(env)
    assert s.for_alert(a1)["subject"]["kind"] == "process"
    assert s.for_alert(a2)["subject"]["kind"] == "host"
    assert s.for_alert("khong-co") is None


def _imports(path):
    tree = ast.parse(path.read_text(encoding="utf-8"))
    out = set()
    for n in ast.walk(tree):
        if isinstance(n, ast.Import):
            out |= {a.name.split(".")[0] for a in n.names}
        elif isinstance(n, ast.ImportFrom) and n.module:
            out.add(n.module.split(".")[0])
    return out


def test_risk_and_ml_never_reach_response():
    """Điểm rủi ro / điểm ML không bao giờ kích hoạt response: không có đường import giữa hai phía."""
    for p in list((ROOT / "src/risk").rglob("*.py")) + list((ROOT / "src/detection/ml").rglob("*.py")):
        assert "response" not in _imports(p), p
    for p in list((ROOT / "src/response").rglob("*.py")) + list((ROOT / "experimental").rglob("*.py")):
        text = p.read_text(encoding="utf-8")
        assert "risk" not in _imports(p) and "_ml_signals" not in text and "risk_score" not in text, p
