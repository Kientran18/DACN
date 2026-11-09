import json
import sys
from datetime import datetime, timezone
from pathlib import Path

import pytest
from fastapi.testclient import TestClient

HERE = Path(__file__).resolve().parent
sys.path.insert(0, str(HERE.parent / "detection"))
import harness  # noqa: E402

import bronze_contract as bc  # noqa: E402
from agent.bronze_writer import BronzeWriter  # noqa: E402
from alerts.builder import build_from_results  # noqa: E402
from alerts.store import AlertStore  # noqa: E402
from api.app import create_app  # noqa: E402
from api.auth import TokenStore, create_token, hash_token  # noqa: E402
from common.config import Config  # noqa: E402
from detection.engine import DetectionEngine  # noqa: E402
from detection.loader import load_rules  # noqa: E402
from pipeline.silver_store import SilverStore  # noqa: E402
from response.policy import Policy  # noqa: E402

SYN = Path(__file__).resolve().parents[2] / "poc/sysmon-collector/configs/synthetic_events.xml"
TOK = {r: f"tok-{r}-0123456789" for r in ("viewer", "analyst", "approver", "responder")}


@pytest.fixture
def ctx(tmp_path):
    bdir = tmp_path / "bronze"
    w = BronzeWriter(bdir)
    for i, x in enumerate(bc.iter_raw_xml_from_file(SYN)):
        w.append(bc.build_bronze_record(x, mode="file", seq=i))
    w.seal()
    st = SilverStore(tmp_path / "s.duckdb")
    st.ingest_dir(bdir, "t")
    for t, _, row in harness.build_rows({"name": "api", "rows": [
            {"id": "p", "table": "process", "image_path": "C:\\a\\powershell.exe", "command_line": "powershell.exe -enc AAAAAAAA",
             "timestamp": "2026-01-01T10:00:00+00:00", "record_id": 900}]}):
        st._insert(t, row)
    rules = load_rules()
    results = DetectionEngine(st.con, rules=rules).run()
    store = AlertStore(st.con)
    out = build_from_results(store, rules, results, st.con)
    cfg = Config(home=tmp_path)
    tokens = TokenStore({hash_token(t): {"role": r, "actor": f"user-{r}"} for r, t in TOK.items()})
    policy = Policy(mode="dry_run", execute_unlocked=False, allowed_actions={"TERMINATE_PROCESS", "QUARANTINE_FILE", "RESTORE_FILE"},
                    protected_process_names=set(), protected_dirs=[], lab_dirs=[tmp_path / "lab"],
                    quarantine_dir=tmp_path / "lab" / "q")
    app = create_app(cfg, tokens, store=st, rules=rules, policy=policy, bronze_dir=bdir)
    return {"app": app, "alert_id": out["alerts"][0], "st": st, "tmp": tmp_path}


def cl(ctx, role=None):
    c = TestClient(ctx["app"])
    if role:
        c.headers["Authorization"] = f"Bearer {TOK[role]}"
    return c


# ---- xác thực / phân quyền ----------------------------------------------------------
@pytest.mark.parametrize("path", ["/health", "/endpoint", "/events", "/alerts", "/rules", "/detections", "/response/actions"])
def test_endpoints_require_token(ctx, path):
    r = cl(ctx).get(path)
    assert r.status_code == 401 and r.json()["error"]["code"] == "E-UNAUTHENTICATED"


def test_wrong_token_rejected_and_livez_is_public_and_minimal(ctx):
    c = TestClient(ctx["app"]); c.headers["Authorization"] = "Bearer nope"
    assert c.get("/alerts").status_code == 401
    r = TestClient(ctx["app"]).get("/livez")
    assert r.status_code == 200 and r.json() == {"status": "ok"}


def test_viewer_cannot_write(ctx):
    a = ctx["alert_id"]
    r = cl(ctx, "viewer").post(f"/alerts/{a}/transition", json={"to_status": "TRIAGED", "note": "x"})
    assert r.status_code == 403 and r.json()["error"]["code"] == "E-FORBIDDEN"
    assert cl(ctx, "viewer").post("/response/actions", json={"action_type": "QUARANTINE_FILE", "target": {}, "requested_mode": "dry_run"}).status_code == 403


def test_responder_cannot_read_data(ctx):
    assert cl(ctx, "responder").get("/alerts").status_code == 403


# ---- health / endpoint ------------------------------------------------------------------
def test_health_reports_measured_state_only(ctx):
    h = cl(ctx, "viewer").get("/health").json()
    assert h["pipeline"]["segments_ingested"] == 1 and h["engine"]["rules_loaded"] >= 4
    assert h["agent"]["status"] == "UNKNOWN"          # không có health.json: không bịa
    assert h["response"]["mode"] == "dry_run" and h["audit_chain_ok"] is True


def test_endpoint_info(ctx):
    e = cl(ctx, "viewer").get("/endpoint").json()
    assert e["hosts"] and e["event_counts"]["silver_process_events"] >= 1


# ---- events ----------------------------------------------------------------------------------
def test_events_pagination_filter_and_no_raw_data(ctx):
    c = cl(ctx, "viewer")
    r = c.get("/events", params={"kind": "process", "limit": 1}).json()
    assert len(r["items"]) == 1 and "raw_data" not in r["items"][0]
    r2 = c.get("/events", params={"kind": "process", "image_path": "C:\\a\\powershell.exe"}).json()
    assert len(r2["items"]) == 1


def test_events_sqli_string_is_inert_and_bad_params_rejected(ctx):
    c = cl(ctx, "viewer")
    assert c.get("/events", params={"kind": "process", "image_path": "x'; drop table silver_process_events;--"}).json()["items"] == []
    assert c.get("/events", params={"kind": "users"}).status_code == 422
    assert c.get("/events", params={"kind": "process", "limit": 100000}).status_code == 422
    assert c.get("/events", params={"kind": "process", "since": "không phải ngày"}).status_code == 422
    assert c.get("/events", params={"kind": "process"}).status_code == 200
    assert ctx["st"].con.execute("select count(*) from silver_process_events").fetchone()[0] >= 1


# ---- alerts ---------------------------------------------------------------------------------------
def test_alert_list_detail_and_validation(ctx):
    c, a = cl(ctx, "viewer"), ctx["alert_id"]
    lst = c.get("/alerts").json()["items"]
    assert lst and lst[0]["mitre_technique_ids"] == ["T1059.001"]
    assert c.get(f"/alerts/{a}").json()["rule_id"] == "DACN-DET-001"
    assert c.get("/alerts/not-a-real-id").status_code == 404
    assert c.get("/alerts", params={"status": "BOGUS"}).status_code == 422


def test_alert_transition_flow_and_invalid(ctx):
    c, a = cl(ctx, "analyst"), ctx["alert_id"]
    bad = c.post(f"/alerts/{a}/transition", json={"to_status": "CONFIRMED", "note": "nhảy cóc"})
    assert bad.status_code == 409 and bad.json()["error"]["code"] == "E-INVALID_TRANSITION"
    ok = c.post(f"/alerts/{a}/transition", json={"to_status": "TRIAGED", "note": "đã xem"})
    assert ok.status_code == 200 and ok.json()["status"] == "TRIAGED"
    h = c.get(f"/alerts/{a}/history").json()["items"]
    assert h[-1]["actor"] == "user-analyst"       # actor lấy từ token, không từ body
    assert c.post(f"/alerts/{a}/transition", json={"to_status": "TRIAGED", "note": ""}).status_code == 422


def test_detections_and_coverage_gaps(ctx):
    c = cl(ctx, "viewer")
    d = c.get("/detections", params={"rule_id": "DACN-DET-001"}).json()["items"]
    assert d and d[0]["outcome"] == "MATCH"
    assert c.get("/coverage-gaps").status_code == 200


# ---- incident -------------------------------------------------------------------------------------------
def test_incident_flow(ctx):
    c, a = cl(ctx, "analyst"), ctx["alert_id"]
    iid = c.post("/incidents", json={"title": "Sự cố thử"}).json()["incident_id"]
    assert c.post(f"/incidents/{iid}/alerts", json={"alert_id": a}).status_code == 200
    assert c.post(f"/incidents/{iid}/notes", json={"note": "ghi chú"}).status_code == 200
    assert c.post(f"/incidents/{iid}/alerts", json={"alert_id": "none"}).status_code == 404
    assert c.post("/incidents", json={"title": ""}).status_code == 422


# ---- evidence -------------------------------------------------------------------------------------------
def test_evidence_raw_only_for_allowed_roles_and_audited(ctx):
    st = ctx["st"]
    eid = st.con.execute("select event_id from silver_process_events where record_id <> 900 limit 1").fetchone()[0]
    from datetime import datetime, timezone
    t = datetime(2026, 1, 1, tzinfo=timezone.utc)
    aid = AlertStore(st.con).insert_alert(detection_dedup_key="k-ev", group_key="g", first_seen_utc=t, last_seen_utc=t,
                                          detection_source="RULE", rule_id="DACN-DET-001", rule_version=1, rule_name="n",
                                          severity="low", severity_reason="thử", hostname="H", contributing_event_ids=[eid])
    v = cl(ctx, "viewer").get(f"/alerts/{aid}/evidence").json()
    assert v["events"][0]["raw_xml"] is None and v["events"][0]["silver"]["event_id"] == eid
    assert cl(ctx, "viewer").get(f"/alerts/{aid}/evidence", params={"include_raw": "true"}).status_code == 403
    a = cl(ctx, "analyst").get(f"/alerts/{aid}/evidence", params={"include_raw": "true"}).json()
    assert a["events"][0]["raw_xml"].startswith("<Event")
    acts = [r[0] for r in st.con.execute("select action from audit_log").fetchall()]
    assert "EVIDENCE_RAW_VIEW" in acts


def test_timeline_and_process_tree_404_without_process(ctx):
    c, a = cl(ctx, "viewer"), ctx["alert_id"]
    assert "events" in c.get(f"/alerts/{a}/timeline").json()
    assert "coverage_status" in c.get(f"/alerts/{a}/process-tree").json()
    assert c.get("/alerts/zzz/timeline").status_code == 404


# ---- rules -------------------------------------------------------------------------------------------------------
def test_rules_read_only(ctx):
    c = cl(ctx, "viewer")
    rs = c.get("/rules").json()["items"]
    assert any(r["rule_id"] == "DACN-DET-001" and r["rule_version"] == 1 and r["validation_status"] == "synthetic_only" for r in rs)
    assert c.get("/rules/DACN-DET-001").status_code == 200 and c.get("/rules/nope").status_code == 404
    assert c.put("/rules/DACN-DET-001", json={}).status_code in (404, 405)


# ---- response ---------------------------------------------------------------------------------------------------------
def test_response_request_approve_and_role_separation(ctx):
    body = {"action_type": "QUARANTINE_FILE", "target": {"path": str(ctx["tmp"] / "lab" / "a.bin")}, "requested_mode": "dry_run"}
    aid = cl(ctx, "analyst").post("/response/actions", json=body).json()["action_id"]
    assert cl(ctx, "analyst").post(f"/response/actions/{aid}/approve", json={"reason": "tự duyệt"}).status_code == 403
    r = cl(ctx, "approver").post(f"/response/actions/{aid}/approve", json={"reason": "đã xem bằng chứng"})
    assert r.status_code == 200 and r.json()["status"] == "APPROVED" and r.json()["approved_by"] == "user-approver"
    assert cl(ctx, "approver").post(f"/response/actions/{aid}/approve", json={"reason": "lần hai"}).status_code == 409
    assert cl(ctx, "analyst").post("/response/actions", json={**body, "action_type": "FORMAT_DISK"}).status_code == 422
    assert cl(ctx, "approver").post("/response/actions", json={**body, "requested_mode": "yolo"}).status_code == 422


def test_reject_needs_reason(ctx):
    aid = cl(ctx, "analyst").post("/response/actions", json={"action_type": "QUARANTINE_FILE", "target": {"path": str(ctx["tmp"] / "lab" / "x")}, "requested_mode": "dry_run"}).json()["action_id"]
    assert cl(ctx, "approver").post(f"/response/actions/{aid}/reject", json={"reason": ""}).status_code == 422
    assert cl(ctx, "approver").post(f"/response/actions/{aid}/reject", json={"reason": "thiếu bằng chứng"}).json()["status"] == "REJECTED"


def test_responder_claim_result_flow_with_remote_executor(ctx):
    from response.backends.dryrun import DryRunBackend
    from response.backends.local import LocalBackend, FakeProcessApi
    from response.executor import Executor
    from response.remote import RemoteActions
    from response.responder import Responder
    from response.policy import Policy
    tmp = ctx["tmp"]; (tmp / "lab").mkdir(exist_ok=True)
    aid = cl(ctx, "analyst").post("/response/actions", json={"action_type": "QUARANTINE_FILE",
                                  "target": {"path": str(tmp / "lab" / "a.bin")}, "requested_mode": "dry_run"}).json()["action_id"]
    cl(ctx, "approver").post(f"/response/actions/{aid}/approve", json={"reason": "ok"})
    http = cl(ctx, "responder")
    remote = RemoteActions(http)
    pol = Policy(mode="dry_run", execute_unlocked=False, allowed_actions={"QUARANTINE_FILE"}, protected_process_names=set(),
                 protected_dirs=[], lab_dirs=[tmp / "lab"], quarantine_dir=tmp / "lab" / "q")
    ex = Executor(pol, remote, LocalBackend(FakeProcessApi({}), [tmp / "lab"]), DryRunBackend(), own_pid=1)
    done = []
    n = Responder(remote.list_approved, ex, lambda a, r: done.append(r["status"])).run_once()
    assert n == 1 and done == ["DONE"]
    assert cl(ctx, "viewer").get(f"/response/actions/{aid}").json()["status"] == "DONE"
    acts = [r[0] for r in ctx["st"].con.execute("select action from audit_log order by seq").fetchall()]
    assert acts.index("RESPONSE_EXEC_BEGIN") < acts.index("RESPONSE_EXEC_END")


def test_responder_cannot_claim_unapproved_or_forge_audit(ctx):
    aid = cl(ctx, "analyst").post("/response/actions", json={"action_type": "QUARANTINE_FILE", "target": {"path": str(ctx["tmp"] / "lab" / "x")}, "requested_mode": "dry_run"}).json()["action_id"]
    r = cl(ctx, "responder")
    assert r.post(f"/response/actions/{aid}/claim").status_code == 409
    assert r.post("/response/audit", json={"action": "RESPONSE_APPROVE", "target_id": aid, "reason": "giả mạo"}).status_code == 422
    assert cl(ctx, "approver").post(f"/response/actions/{aid}/claim").status_code == 403


# ---- lỗi thống nhất / giới hạn --------------------------------------------------------------------------------------------
def test_oversized_body_rejected_and_errors_do_not_leak(ctx):
    r = cl(ctx, "analyst").post("/incidents", content=b"x" * 200_000, headers={"Content-Type": "application/json"})
    assert r.status_code == 413 and r.json()["error"]["code"] == "E-TOO_LARGE"
    r = cl(ctx, "viewer").get("/alerts/%27%3B--")
    assert r.status_code == 404 and "Traceback" not in r.text and str(ctx["tmp"]) not in r.text


def test_tokens_stored_hashed_and_cli_helper(tmp_path):
    p = tmp_path / "t.json"
    token = create_token(p, "analyst", "kien")
    assert token not in p.read_text() and TokenStore.load(p).lookup(token)["role"] == "analyst"
    assert TokenStore.load(p).lookup("sai") is None
    with pytest.raises(ValueError):
        create_token(p, "root", "x")


def test_openapi_export(tmp_path, ctx):
    from api.export_openapi import export
    out = tmp_path / "openapi.json"
    export(ctx["app"], out)
    spec = json.loads(out.read_text())
    assert "/alerts/{alert_id}/evidence" in spec["paths"] and spec["info"]["title"]


def test_me_stats_and_data_label(ctx):
    me = cl(ctx, "approver").get("/me").json()
    assert me["role"] == "approver" and "approve" in me["permissions"]
    st = cl(ctx, "viewer").get("/stats").json()
    assert st["alerts_by_severity"].get("medium", 0) >= 1 and st["coverage_gaps"] == 0
    assert cl(ctx, "viewer").get("/health").json()["data_label"] == "UNSPECIFIED"
    assert cl(ctx).get("/me").status_code == 401


def test_ui_is_served_with_strict_csp_and_no_cache(ctx):
    r = TestClient(ctx["app"]).get("/ui/")
    if r.status_code == 404:
        pytest.skip("chưa có static")
    assert r.status_code == 200 and "script-src 'self'" in r.headers["content-security-policy"]
    assert r.headers["x-content-type-options"] == "nosniff" and r.headers["cache-control"] == "no-store"
    assert "<script src=\"app.js\"" in r.text and "http://" not in r.text and "https://" not in r.text


def _write_agent_health(ctx, age_s, state="running"):
    from datetime import datetime, timedelta, timezone
    p = ctx["tmp"] / "agent" / "health.json"
    p.parent.mkdir(parents=True, exist_ok=True)
    hb = (datetime.now(timezone.utc) - timedelta(seconds=age_s)).isoformat()
    p.write_text(json.dumps({"state": state, "heartbeat": hb}))


def test_health_flags_dead_agent_as_stale(ctx):
    _write_agent_health(ctx, 1)
    assert cl(ctx, "viewer").get("/health").json()["agent"]["status"] == "REPORTED"
    _write_agent_health(ctx, 600)           # agent bị kill: health.json vẫn ghi "running"
    a = cl(ctx, "viewer").get("/health").json()["agent"]
    assert a["status"] == "STALE" and a["heartbeat_age_s"] >= 600
    _write_agent_health(ctx, 600, state="stopped")     # dừng sạch thì không phải STALE
    assert cl(ctx, "viewer").get("/health").json()["agent"]["status"] == "REPORTED"


def test_responder_does_not_leave_action_stuck_when_finish_fails(ctx):
    import httpx
    from response.backends.dryrun import DryRunBackend
    from response.backends.local import LocalBackend, FakeProcessApi
    from response.executor import Executor
    from response.remote import RemoteActions

    class Flaky:                       # API "rơi" đúng lúc báo kết quả
        def __init__(self, inner): self.inner, self.fail = inner, True
        def get(self, *a, **k): return self.inner.get(*a, **k)
        def post(self, url, **k):
            if self.fail and url.endswith("/result"):
                raise httpx.ConnectError("api down")
            return self.inner.post(url, **k)

    tmp = ctx["tmp"]; (tmp / "lab").mkdir(exist_ok=True)
    def approved():
        aid = cl(ctx, "analyst").post("/response/actions", json={"action_type": "QUARANTINE_FILE",
                                      "target": {"path": str(tmp / "lab" / "a.bin")}, "requested_mode": "dry_run"}).json()["action_id"]
        cl(ctx, "approver").post(f"/response/actions/{aid}/approve", json={"reason": "ok"})
        return aid
    status = lambda aid: cl(ctx, "viewer").get(f"/response/actions/{aid}").json()["status"]

    # (1) finish thất bại: kết quả thật được giữ ở spool rồi gửi lại, hành động không kẹt EXECUTING
    aid, http = approved(), Flaky(cl(ctx, "responder"))
    remote = RemoteActions(http, spool_dir=tmp / "spool", retries=2, backoff=0)
    pol = Policy(mode="dry_run", execute_unlocked=False, allowed_actions={"QUARANTINE_FILE"}, protected_process_names=set(),
                 protected_dirs=[], lab_dirs=[tmp / "lab"], quarantine_dir=tmp / "lab" / "q")
    ex = Executor(pol, remote, LocalBackend(FakeProcessApi({}), [tmp / "lab"]), DryRunBackend(), own_pid=1)
    with pytest.raises(httpx.HTTPError):
        ex.run(aid)
    assert status(aid) == "EXECUTING" and json.loads((tmp / "spool" / f"{aid}.json").read_text())["status"] == "DONE"
    http.fail = False
    assert remote.flush_spool() == 1 and status(aid) == "DONE" and not list((tmp / "spool").glob("*.json"))

    # (2) responder chết sau khi claim (không có spool): khởi động lại thì đánh dấu FAILED để kiểm tra thủ công
    orphan = approved()
    assert cl(ctx, "responder").post(f"/response/actions/{orphan}/claim").status_code == 200
    assert remote.recover_executing() == [orphan]
    a = cl(ctx, "viewer").get(f"/response/actions/{orphan}").json()
    assert a["status"] == "FAILED" and a["result"]["code"] == "X-UNKNOWN_OUTCOME"


def test_request_is_checked_against_policy_before_approval(ctx):
    bad = {"action_type": "QUARANTINE_FILE", "target": {"path": str(ctx["tmp"] / "outside.bin")}, "requested_mode": "dry_run"}
    r = cl(ctx, "analyst").post("/response/actions", json=bad)
    assert r.status_code == 422 and r.json()["error"]["code"] == "E-POLICY" and "P-NOT_LAB_TARGET" in r.json()["error"]["message"]
    assert cl(ctx, "viewer").get("/response/actions").json()["items"] == []        # không vào hàng đợi


def test_body_without_content_length_is_rejected(ctx):
    def chunks():
        yield b'{"title": "x"}'
    r = cl(ctx, "analyst").post("/incidents", content=chunks())                  # Transfer-Encoding: chunked
    assert r.status_code == 411 and r.json()["error"]["code"] == "E-LENGTH_REQUIRED"


def test_token_file_changes_apply_without_restart(tmp_path):
    from api.auth import TokenStore, create_token
    f = tmp_path / "t.json"
    create_token(f, "analyst", "a")
    ts = TokenStore.load(f)
    t2 = create_token(f, "viewer", "v")                    # token mới sau khi core đã chạy
    assert ts.lookup(t2)["actor"] == "v"
    f.write_text(json.dumps({h: e for h, e in json.loads(f.read_text()).items() if e["actor"] != "v"}))
    assert ts.lookup(t2) is None                           # thu hồi bằng cách xóa dòng
    f.write_text("{bad")                                   # tệp ghi dở: giữ danh sách cũ, không sập
    assert ts.lookup(t2) is None and any(e["actor"] == "a" for e in ts.entries.values())
