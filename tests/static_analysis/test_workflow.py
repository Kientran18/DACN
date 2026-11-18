import hashlib
import json

import jsonschema
import pytest
from fastapi.testclient import TestClient

from alerts.store import AlertStore
from api.app import create_app
from api.auth import TokenStore, hash_token
from common.config import Config
from detection.loader import load_rules
from pipeline.silver_store import SilverStore
from response.policy import Policy
from static_analysis.contracts import CANDIDATE_SCHEMA
from static_analysis.review import ReviewError
from static_analysis.service import StaticWorkflow


@pytest.fixture
def env(tmp_path, bundle):
    root = tmp_path / "lab"; root.mkdir()
    p = root / "harmless.txt"; p.write_bytes(b"DACN-LAB-MARKER")
    sha = hashlib.sha256(p.read_bytes()).hexdigest()
    bundle["indicators"] = [{"id": "lab-hash", "source": "synthetic", "sha256": sha,
                              "expires_at": "2099-01-01T00:00:00Z"}]
    st = SilverStore(tmp_path / "s.duckdb")
    wf = StaticWorkflow(st.con, [root], tmp_path / "static-knowledge")
    wf.knowledge.activate(bundle, expected_revision=None, actor="approver", reason="lab only")
    yield st, wf, p, bundle
    st.close()


def test_standalone_hash_hit_creates_candidate_no_fabricated_event_alert_or_response(env):
    st, wf, p, _ = env
    row = wf.analyze(p, actor="analyst")
    jsonschema.validate(row, CANDIDATE_SCHEMA, format_checker=jsonschema.FormatChecker())
    assert row["detection"]["outcome"] == "MATCH" and row["alert_ids"] == []
    assert st.con.execute("select count(*) from alerts").fetchone()[0] == 0
    assert st.con.execute("select count(*) from response_actions").fetchone()[0] == 0
    assert row["analysis"]["source_event_ids"] == []


def test_source_hash_alert_trace_and_replay_no_duplicate_alert(env):
    st, wf, p, _ = env
    eid = "11111111-2222-3333-4444-555555555555"
    st.con.execute("insert into silver_process_events (event_id,timestamp,event_type,sysmon_event_id,channel,record_id,"
                   "hostname,process_guid,raw_data,pid,image_path,file_sha256) values (?,current_timestamp,'PROCESS_START',"
                   "1,'lab',1,'LABHOST',?,'{}',42,?,?)", [eid, eid, str(p), hashlib.sha256(p.read_bytes()).hexdigest()])
    row = wf.analyze(p, source_event_ids=[eid], actor="analyst")
    assert len(row["alert_ids"]) == 1 and row["analysis"]["historical_identity"] == "HASH_VERIFIED"
    wf.analyze(p, source_event_ids=[eid], actor="analyst")
    assert st.con.execute("select count(*) from alerts").fetchone()[0] == 1
    p.write_bytes(b"changed after event")
    changed = wf.analyze(p, source_event_ids=[eid], actor="analyst")
    assert changed["analysis"]["error_code"] == "HASH_MISMATCH"
    assert changed["detection"]["outcome"] == "INSUFFICIENT_TELEMETRY"


def test_fake_or_mismatched_source_is_rejected(env):
    _, wf, p, _ = env
    with pytest.raises(KeyError): wf.analyze(p, source_event_ids=["fake"], actor="analyst")


def test_review_revision_permissions_audit_and_ioc_conflict(env):
    st, wf, p, _ = env
    row = wf.analyze(p, actor="analyst"); cid = row["candidate_id"]
    triage = wf.candidates.transition(cid, "TRIAGED", expected_revision=1, actor="a", role="analyst", reason="looked")
    assert triage["revision"] == 2
    with pytest.raises(PermissionError): wf.candidates.transition(cid, "SUSPICIOUS", expected_revision=2, actor="a", role="analyst", reason="x")
    with pytest.raises(ReviewError, match="REVISION_CONFLICT"): wf.candidates.transition(cid, "SUSPICIOUS", expected_revision=1, actor="r", role="approver", reason="x")
    with pytest.raises(ReviewError): wf.candidates.transition(cid, "ALLOWLISTED", expected_revision=2, actor="r", role="approver", reason="x")
    done = wf.candidates.transition(cid, "SUSPICIOUS", expected_revision=2, actor="r", role="approver", reason="needs investigation")
    assert done["state"] == "SUSPICIOUS"
    assert len(wf.candidates.history(cid)) == 3 and AlertStore(st.con).verify_audit() == []
    with pytest.raises(ReviewError): wf.candidates.transition(cid, "REJECTED", expected_revision=3, actor="r", role="approver", reason="x")


def test_review_failure_rolls_back_state_and_no_global_allowlist_side_effect(env, monkeypatch):
    _, wf, p, bundle = env
    bundle["version"] = 2; bundle["indicators"] = []
    wf.knowledge.activate(bundle, expected_revision=wf.knowledge.snapshot()[0], actor="r", reason="benign")
    row = wf.analyze(p, actor="a"); cid = row["candidate_id"]
    wf.candidates.transition(cid, "TRIAGED", expected_revision=1, actor="a", role="analyst", reason="triage")
    def fail(*a): raise RuntimeError("audit failure")
    monkeypatch.setattr(wf.candidates.audit, "record", fail)
    with pytest.raises(RuntimeError): wf.candidates.transition(cid, "ALLOWLISTED", expected_revision=2, actor="r", role="approver", reason="benign")
    assert wf.candidates.get(cid)["revision"] == 2
    assert wf.knowledge.snapshot()[1]["allowlist"] == []


def test_static_allowlist_does_not_remove_ioc_evidence_or_behavioral_results(env):
    st, wf, p, bundle = env
    bundle["version"] = 2; bundle["allowlist"] = [{**bundle["indicators"][0], "id": "known-good"}]
    wf.knowledge.activate(bundle, expected_revision=wf.knowledge.snapshot()[0], actor="r", reason="review")
    row = wf.analyze(p, actor="a")
    assert row["detection"]["outcome"] == "NO_MATCH"
    assert row["verdict"]["signature_hit"]["suppressed"]
    assert row["verdict"]["signature_hit"]["ioc_ids"] == ["lab-hash"]


def test_pattern_store_integration_and_expiry_without_hash_indicator(env):
    _, wf, p, bundle = env
    bundle.update(version=2, indicators=[], patterns=[{"id": "lab-marker", "hex": b"LAB-MARKER".hex(),
                  "source": "synthetic", "expires_at": "2099-01-01T00:00:00Z"}])
    wf.knowledge.activate(bundle, expected_revision=wf.knowledge.snapshot()[0], actor="r", reason="literal lab marker")
    row = wf.analyze(p, actor="a")
    assert row["verdict"]["signature_hit"]["pattern_ids"] == ["lab-marker"]
    assert row["detection"]["outcome"] == "MATCH"
    bundle["version"] = 3; bundle["patterns"][0]["expires_at"] = "2020-01-01T00:00:00Z"
    wf.knowledge.activate(bundle, expected_revision=wf.knowledge.snapshot()[0], actor="r", reason="expired marker")
    assert wf.analyze(p, actor="a")["detection"]["outcome"] == "NO_MATCH"


def test_api_analysis_candidate_authorization_cas_history_and_knowledge_rollback(env, tmp_path):
    st, _, p, bundle = env
    roles = ("viewer", "analyst", "approver", "responder")
    tokens = TokenStore({hash_token("test-" + r): {"role": r, "actor": r} for r in roles})
    policy = Policy(mode="dry_run", execute_unlocked=False, allowed_actions=set(), protected_process_names=set(),
                    protected_dirs=[], lab_dirs=[tmp_path / "lab"], quarantine_dir=tmp_path / "lab" / "q")
    app = create_app(Config(home=tmp_path), tokens, store=st, rules=load_rules(), policy=policy, bronze_dir=tmp_path / "bronze")
    client = TestClient(app)
    headers = lambda role: {"Authorization": "Bearer test-" + role}
    assert client.post("/static/analyses", json={"path": str(p)}).status_code == 401
    assert client.post("/static/analyses", json={"path": str(p)}, headers=headers("viewer")).status_code == 403
    row = client.post("/static/analyses", json={"path": str(p)}, headers=headers("analyst")).json()
    cid = row["candidate_id"]
    assert client.get("/static/candidates", headers=headers("responder")).status_code == 403
    path = f"/static/candidates/{cid}/transition"
    body = {"to_state": "TRIAGED", "expected_revision": 1, "reason": "triage"}
    assert client.post(path, json=body, headers=headers("analyst")).status_code == 200
    assert client.post(path, json=body, headers=headers("analyst")).status_code == 409
    body.update(to_state="SUSPICIOUS", expected_revision=2)
    assert client.post(path, json=body, headers=headers("analyst")).status_code == 403
    assert client.post(path, json=body, headers=headers("approver")).status_code == 200
    assert len(client.get(f"/static/candidates/{cid}/history", headers=headers("viewer")).json()["items"]) == 3
    update = {"bundle": {**bundle, "version": 2}, "reason": "upgrade", "expected_revision": row["verdict"]["knowledge_revision"]}
    assert client.post("/static/knowledge/activate", json=update, headers=headers("analyst")).status_code == 403
    response = client.post("/static/knowledge/activate", json=update, headers=headers("approver"))
    assert response.status_code == 200
    rollback = {"expected_revision": response.json()["revision"], "revision": update["expected_revision"], "reason": "revert"}
    assert client.post("/static/knowledge/rollback", json=rollback, headers=headers("approver")).status_code == 200
