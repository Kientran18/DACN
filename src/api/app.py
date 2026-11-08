"""API cục bộ FastAPI (PH8). Bind loopback (cấu hình ép), Bearer token, vai trò, lỗi thống nhất, không lộ stack/đường dẫn.
Một khóa toàn cục bảo vệ kết nối DuckDB (MVP một người dùng; hiệu năng chưa đo)."""
from __future__ import annotations

import json
import threading
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, List, Literal, Optional

from fastapi import Depends, FastAPI, Header, HTTPException, Query as Q, Request
from fastapi.exceptions import RequestValidationError
from fastapi.responses import JSONResponse
from pydantic import BaseModel, Field

from alerts.evidence import resolve_evidence
from alerts.store import AlertStore, InvalidTransition
from alerts.timeline import process_tree, timeline
from pipeline.query import Query
from response.actions import ActionError, ActionStore
from response.policy import ACTION_TYPES

from .auth import ROLES, TokenStore

MAX_BODY = 64 * 1024
KINDS = {"process": "silver_process_events", "file": "silver_file_events",
         "registry": "silver_registry_events", "network": "silver_network_events"}
STATUSES = Literal["NEW", "TRIAGED", "INVESTIGATING", "CONFIRMED", "FALSE_POSITIVE", "CLOSED"]


class ApiError(Exception):
    def __init__(self, status: int, code: str, message: str):
        self.status, self.code, self.message = status, code, message


class Transition(BaseModel):
    to_status: STATUSES
    note: str = Field(min_length=1, max_length=1000)


class IncidentIn(BaseModel):
    title: str = Field(min_length=1, max_length=200)


class LinkIn(BaseModel):
    alert_id: str = Field(min_length=1, max_length=64)


class NoteIn(BaseModel):
    note: str = Field(min_length=1, max_length=2000)


class ActionIn(BaseModel):
    action_type: Literal["TERMINATE_PROCESS", "QUARANTINE_FILE", "RESTORE_FILE"]
    target: Dict[str, Any]
    requested_mode: Literal["dry_run", "execute"]
    alert_id: Optional[str] = Field(default=None, max_length=64)


class ReasonIn(BaseModel):
    reason: str = Field(min_length=1, max_length=1000)


class ResultIn(BaseModel):
    status: Literal["DONE", "FAILED"]
    result: Dict[str, Any]
    rollback: Dict[str, Any]


class AuditIn(BaseModel):
    action: Literal["RESPONSE_EXEC_BEGIN", "RESPONSE_EXEC_END"]
    target_id: str = Field(min_length=1, max_length=64)
    reason: str = Field(min_length=1, max_length=2000)


def _err(status, code, message):
    return JSONResponse(status_code=status, content={"error": {"code": code, "message": message}})


def _alert_out(a: dict) -> dict:
    a = dict(a)
    for k in ("mitre_technique_ids", "matched_fields", "missing_fields"):
        if isinstance(a.get(k), str):
            a[k] = json.loads(a[k])
    return a


def create_app(cfg, tokens: TokenStore, *, store, rules: Dict[str, dict], policy, bronze_dir: Path,
               health_path: Optional[Path] = None) -> FastAPI:
    app = FastAPI(title="DACN EDR Local API", version="0.1.0-mvp",
                  description="API cục bộ (loopback). Dữ liệu mẫu/synthetic nếu có sẽ được gắn nhãn ở nguồn.")
    lock = threading.RLock()
    con = store.con
    alerts, actions = AlertStore(con), ActionStore(con, AlertStore(con))
    actions.require_distinct = policy.require_distinct_approver
    q = Query(con)
    health_path = Path(health_path) if health_path else cfg.home / "agent" / "health.json"

    # -- lỗi thống nhất ---------------------------------------------------------------
    @app.exception_handler(ApiError)
    async def _api(_, e: ApiError):
        return _err(e.status, e.code, e.message)

    @app.exception_handler(RequestValidationError)
    async def _val(_, e: RequestValidationError):
        fields = sorted({".".join(str(x) for x in err["loc"][1:]) or str(err["loc"][0]) for err in e.errors()})
        return _err(422, "E-VALIDATION", "tham số không hợp lệ: " + ", ".join(fields))

    @app.exception_handler(HTTPException)
    async def _http(_, e: HTTPException):
        code = {401: "E-UNAUTHENTICATED", 403: "E-FORBIDDEN", 404: "E-NOT_FOUND"}.get(e.status_code, "E-HTTP")
        return _err(e.status_code, code, str(e.detail) if e.status_code < 500 else "lỗi")

    @app.exception_handler(Exception)
    async def _any(_, e: Exception):
        return _err(500, "E-INTERNAL", "lỗi nội bộ")      # không lộ stack/đường dẫn

    @app.middleware("http")
    async def _limit(request: Request, call_next):
        cl_ = request.headers.get("content-length")
        if cl_ and cl_.isdigit() and int(cl_) > MAX_BODY:
            return _err(413, "E-TOO_LARGE", "nội dung yêu cầu quá lớn")
        return await call_next(request)

    # -- xác thực ---------------------------------------------------------------------------
    def need(*perms: str):
        def dep(authorization: Optional[str] = Header(default=None)) -> dict:
            token = authorization[7:] if authorization and authorization.lower().startswith("bearer ") else None
            who = tokens.lookup(token)
            if who is None:
                raise HTTPException(401, "thiếu hoặc sai token")
            if not (set(perms) & ROLES[who["role"]]):
                raise HTTPException(403, "vai trò không đủ quyền")
            return who
        return dep

    def get_alert(aid: str) -> dict:
        a = alerts.get(aid)
        if a is None:
            raise HTTPException(404, "không tìm thấy alert")
        return a

    def page(items: list, limit: int, offset: int) -> dict:
        return {"items": items, "limit": limit, "offset": offset}

    # -- health -----------------------------------------------------------------------------
    @app.get("/livez", tags=["health"])
    def livez():
        return {"status": "ok"}

    @app.get("/health", tags=["health"])
    def health(_: dict = Depends(need("read"))):
        with lock:
            led = con.execute("select count(*) filter (where status='INGESTED'), coalesce(sum(quarantined),0),"
                              " coalesce(sum(records_read),0), max(ingested_at_utc) from _ingest_ledger").fetchone()
            dlq = con.execute("select count(*) from silver_quarantine_dlq").fetchone()[0]
            chain = alerts.verify_audit()
        agent: Dict[str, Any] = {"status": "UNKNOWN", "note": "không có health.json của agent"}
        try:
            agent = {"status": "REPORTED", **json.loads(health_path.read_text(encoding="utf-8"))}
        except (OSError, ValueError):
            pass
        lag = (datetime.now(timezone.utc) - led[3]).total_seconds() if led[3] else None
        return {"agent": agent,
                "pipeline": {"segments_ingested": led[0], "records_read": int(led[2]), "records_quarantined": int(led[1]),
                             "dlq_rows": dlq, "last_ingest_utc": led[3], "seconds_since_last_ingest": lag},
                "engine": {"rules_loaded": len(rules), "rules_enabled": sum(r["status"] == "enabled" for r in rules.values()),
                           "rule_versions": {k: r["rule_version"] for k, r in rules.items()}},
                "response": {"mode": policy.mode, "execute_unlocked": policy.execute_unlocked},
                "audit_chain_ok": chain == [], "audit_issues": chain[:5]}

    @app.get("/endpoint", tags=["health"])
    def endpoint(_: dict = Depends(need("read"))):
        with lock:
            counts, hosts, lo, hi = {}, set(), None, None
            for t in KINDS.values():
                n, a, b = con.execute(f"select count(*), min(timestamp), max(timestamp) from {t}").fetchone()
                counts[t] = n
                hosts |= {r[0] for r in con.execute(f"select distinct hostname from {t}").fetchall()}
                lo = a if lo is None or (a and a < lo) else lo
                hi = b if hi is None or (b and b > hi) else hi
        return {"hosts": sorted(hosts), "event_counts": counts, "first_event_utc": lo, "last_event_utc": hi}

    # -- events -------------------------------------------------------------------------------
    @app.get("/events", tags=["events"])
    def events(kind: Literal["process", "file", "registry", "network"], since: Optional[datetime] = None,
               until: Optional[datetime] = None, hostname: Optional[str] = Q(None, max_length=64),
               process_guid: Optional[str] = Q(None, max_length=36), sysmon_event_id: Optional[int] = Q(None, ge=1, le=300),
               sha256: Optional[str] = Q(None, max_length=64), image_path: Optional[str] = Q(None, max_length=1024),
               file_path: Optional[str] = Q(None, max_length=1024), limit: int = Q(50, ge=1, le=200),
               offset: int = Q(0, ge=0, le=1_000_000), _: dict = Depends(need("read"))):
        f = {k: v for k, v in dict(hostname=hostname, process_guid=process_guid, sysmon_event_id=sysmon_event_id,
                                   image_path=image_path).items() if v is not None}
        if sha256 is not None:
            f["file_sha256"] = sha256
        if file_path is not None:
            f["file_path"] = file_path
        try:
            with lock:
                rows = q.events(KINDS[kind], since=since, until=until, limit=limit, offset=offset, **f)
        except ValueError as exc:
            raise ApiError(422, "E-VALIDATION", "bộ lọc không áp dụng cho loại sự kiện này") from exc
        for r in rows:
            r.pop("raw_data", None)      # EventData thô chỉ qua endpoint evidence
        return page(rows, limit, offset)

    @app.get("/detections", tags=["alerts"])
    def detections(rule_id: Optional[str] = Q(None, max_length=32), outcome: Optional[str] = Q(None, max_length=32),
                   limit: int = Q(50, ge=1, le=200), offset: int = Q(0, ge=0), _: dict = Depends(need("read"))):
        sql, p = "select result from _detection_results", []
        cond = []
        if rule_id: cond.append("rule_id=?"); p.append(rule_id)
        if outcome: cond.append("outcome=?"); p.append(outcome)
        if cond: sql += " where " + " and ".join(cond)
        with lock:
            rows = [json.loads(r[0]) for r in con.execute(sql + " order by first_seen_utc desc, dedup_key limit ? offset ?", p + [limit, offset]).fetchall()]
        return page(rows, limit, offset)

    # -- alerts -----------------------------------------------------------------------------------
    @app.get("/alerts", tags=["alerts"])
    def list_alerts(status: Optional[STATUSES] = None, limit: int = Q(50, ge=1, le=200), offset: int = Q(0, ge=0),
                    _: dict = Depends(need("read"))):
        with lock:
            return page([_alert_out(a) for a in alerts.list(status, limit, offset)], limit, offset)

    @app.get("/alerts/{alert_id}", tags=["alerts"])
    def alert(alert_id: str, _: dict = Depends(need("read"))):
        with lock:
            return _alert_out(get_alert(alert_id))

    @app.get("/alerts/{alert_id}/history", tags=["alerts"])
    def history(alert_id: str, _: dict = Depends(need("read"))):
        with lock:
            get_alert(alert_id)
            return {"items": alerts.history(alert_id)}

    @app.post("/alerts/{alert_id}/transition", tags=["alerts"])
    def transition(alert_id: str, body: Transition, who: dict = Depends(need("alert_write"))):
        with lock:
            get_alert(alert_id)
            try:
                alerts.transition(alert_id, body.to_status, actor=who["actor"], note=body.note)
            except InvalidTransition as exc:
                raise ApiError(409, "E-INVALID_TRANSITION", str(exc)) from exc
            return _alert_out(alerts.get(alert_id))

    @app.get("/coverage-gaps", tags=["alerts"])
    def gaps(limit: int = Q(50, ge=1, le=200), offset: int = Q(0, ge=0), _: dict = Depends(need("read"))):
        with lock:
            cur = con.execute("select * from coverage_gaps order by created_at_utc desc limit ? offset ?", [limit, offset])
            cols = [c[0] for c in cur.description]
            rows = [dict(zip(cols, r)) for r in cur.fetchall()]
        for r in rows:
            r["missing_fields"] = json.loads(r["missing_fields"])
        return page(rows, limit, offset)

    @app.get("/alerts/{alert_id}/evidence", tags=["evidence"])
    def evidence(alert_id: str, include_raw: bool = False, who: dict = Depends(need("read"))):
        if include_raw and "raw" not in ROLES[who["role"]]:
            raise HTTPException(403, "vai trò không được xem raw_xml")
        with lock:
            get_alert(alert_id)
            ev = resolve_evidence(con, alert_id, bronze_dir)
            if include_raw:
                alerts.record(who["actor"], "EVIDENCE_RAW_VIEW", "alert", alert_id, "xem raw_xml")
        for e in ev["events"]:
            if not include_raw:
                e["raw_xml"] = None
            if e.get("silver"):
                e["silver"].pop("raw_data", None)
        return ev

    def _guid(alert_id: str) -> str:
        a = get_alert(alert_id)
        if not a.get("process_guid"):
            raise HTTPException(404, "alert không gắn process_guid")
        return a["process_guid"]

    @app.get("/alerts/{alert_id}/timeline", tags=["evidence"])
    def alert_timeline(alert_id: str, _: dict = Depends(need("read"))):
        with lock:
            return {"events": timeline(con, _guid(alert_id))}

    @app.get("/alerts/{alert_id}/process-tree", tags=["evidence"])
    def alert_tree(alert_id: str, _: dict = Depends(need("read"))):
        with lock:
            return process_tree(con, _guid(alert_id))

    # -- incident -----------------------------------------------------------------------------------
    @app.post("/incidents", tags=["incidents"])
    def new_incident(body: IncidentIn, who: dict = Depends(need("alert_write"))):
        with lock:
            return {"incident_id": alerts.create_incident(body.title, actor=who["actor"])}

    @app.post("/incidents/{incident_id}/alerts", tags=["incidents"])
    def link(incident_id: str, body: LinkIn, who: dict = Depends(need("alert_write"))):
        with lock:
            if not con.execute("select 1 from incidents where incident_id=?", [incident_id]).fetchone():
                raise HTTPException(404, "không tìm thấy incident")
            try:
                alerts.link_alert(incident_id, body.alert_id, actor=who["actor"])
            except KeyError:
                raise HTTPException(404, "không tìm thấy alert")
        return {"ok": True}

    @app.post("/incidents/{incident_id}/notes", tags=["incidents"])
    def note(incident_id: str, body: NoteIn, who: dict = Depends(need("alert_write"))):
        with lock:
            if not con.execute("select 1 from incidents where incident_id=?", [incident_id]).fetchone():
                raise HTTPException(404, "không tìm thấy incident")
            return {"note_id": alerts.add_note(incident_id, body.note, actor=who["actor"])}

    # -- rules (chỉ đọc) -------------------------------------------------------------------------------
    @app.get("/rules", tags=["rules"])
    def list_rules(_: dict = Depends(need("read"))):
        keys = ("rule_id", "legacy_id", "rule_version", "name", "type", "status", "severity", "validation_status",
                "response_policy", "mitre_technique_ids", "limitations")
        return {"items": [{k: r.get(k) for k in keys} for r in rules.values()]}

    @app.get("/rules/{rule_id}", tags=["rules"])
    def rule(rule_id: str, _: dict = Depends(need("read"))):
        if rule_id not in rules:
            raise HTTPException(404, "không tìm thấy rule")
        return rules[rule_id]

    # -- response ----------------------------------------------------------------------------------------
    @app.post("/response/actions", tags=["response"])
    def request_action(body: ActionIn, who: dict = Depends(need("request_action"))):
        with lock:
            aid = actions.request(body.action_type, body.target, requested_by=who["actor"],
                                  requested_mode=body.requested_mode, alert_id=body.alert_id)
        return {"action_id": aid, "status": "REQUESTED"}

    @app.get("/response/actions", tags=["response"])
    def list_actions(status: Optional[Literal["REQUESTED", "APPROVED", "REJECTED", "EXECUTING", "DONE", "FAILED"]] = None,
                     limit: int = Q(50, ge=1, le=200), _: dict = Depends(need("read", "responder"))):
        with lock:
            ids = [r[0] for r in con.execute(
                "select action_id from response_actions" + (" where status=?" if status else "") +
                " order by requested_at_utc desc limit ?", ([status] if status else []) + [limit]).fetchall()]
            return {"items": [actions.get(i) for i in ids]}

    @app.get("/response/actions/{action_id}", tags=["response"])
    def get_action(action_id: str, _: dict = Depends(need("read", "responder"))):
        with lock:
            a = actions.get(action_id)
        if a is None:
            raise HTTPException(404, "không tìm thấy hành động")
        return a

    def _decide(fn, action_id: str, body: ReasonIn, who: dict):
        with lock:
            if actions.get(action_id) is None:
                raise HTTPException(404, "không tìm thấy hành động")
            try:
                fn(action_id, approver=who["actor"], reason=body.reason)
            except ActionError as exc:
                raise ApiError(409, "E-INVALID_STATE", str(exc)) from exc
            return actions.get(action_id)

    @app.post("/response/actions/{action_id}/approve", tags=["response"])
    def approve(action_id: str, body: ReasonIn, who: dict = Depends(need("approve"))):
        return _decide(actions.approve, action_id, body, who)

    @app.post("/response/actions/{action_id}/reject", tags=["response"])
    def reject(action_id: str, body: ReasonIn, who: dict = Depends(need("approve"))):
        return _decide(actions.reject, action_id, body, who)

    @app.post("/response/actions/{action_id}/claim", tags=["responder"])
    def claim(action_id: str, _: dict = Depends(need("responder"))):
        with lock:
            if actions.get(action_id) is None:
                raise HTTPException(404, "không tìm thấy hành động")
            try:
                return actions.mark_executing(action_id)
            except ActionError as exc:
                raise ApiError(409, "E-INVALID_STATE", str(exc)) from exc

    @app.post("/response/actions/{action_id}/result", tags=["responder"])
    def result(action_id: str, body: ResultIn, _: dict = Depends(need("responder"))):
        with lock:
            a = actions.get(action_id)
            if a is None:
                raise HTTPException(404, "không tìm thấy hành động")
            if a["status"] != "EXECUTING":
                raise ApiError(409, "E-INVALID_STATE", f"trạng thái {a['status']}, cần EXECUTING")
            actions.finish(action_id, body.status, body.result, body.rollback)
        return {"ok": True}

    @app.post("/response/audit", tags=["responder"])
    def responder_audit(body: AuditIn, who: dict = Depends(need("responder"))):
        with lock:
            alerts.record(f"executor({who['actor']})", body.action, "response_action", body.target_id, body.reason)
        return {"ok": True}

    return app


def serve(cfg, app) -> None:     # pragma: no cover - chạy thật cần uvicorn
    import uvicorn
    uvicorn.run(app, host=cfg.api_host, port=cfg.api_port, log_level="info")
