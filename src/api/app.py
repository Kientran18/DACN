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
from fastapi.responses import JSONResponse, RedirectResponse
from fastapi.staticfiles import StaticFiles
from pydantic import BaseModel, Field

from alerts.evidence import resolve_evidence
from alerts.process_link import links_for_alert
from alerts.scriptblock_view import script_for_alert
from common.redact import redact
from alerts.process_view import CATEGORIES as PROC_EVENT_KINDS, process_events, process_tree_view, search_processes
from alerts.store import TRANSITIONS, AlertStore, InvalidTransition
from alerts.timeline import process_tree, timeline
from pipeline.query import Query
from response.actions import ActionError, ActionStore
from response.executor import precheck
from response.policy import ACTION_TYPES
from detection.ioc import IocStore
from risk.config import load_risk_config
from risk.service import RiskService
from static_analysis.service import StaticWorkflow
from static_analysis.knowledge import KnowledgeError
from static_analysis.review import ReviewError

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
    action_type: Literal["TERMINATE_PROCESS", "QUARANTINE_FILE", "RESTORE_FILE", "ADD_WHITELIST", "REMOVE_WHITELIST"]
    target: Dict[str, Any]
    requested_mode: Literal["dry_run", "execute"]
    alert_id: Optional[str] = Field(default=None, max_length=64)


if set(ActionIn.model_fields["action_type"].annotation.__args__) != ACTION_TYPES:   # giữ API khớp policy
    raise RuntimeError("ActionIn.action_type lệch response.policy.ACTION_TYPES")


class ReasonIn(BaseModel):
    reason: str = Field(min_length=1, max_length=1000)


class StaticIn(BaseModel):
    path: str = Field(min_length=1, max_length=1024)
    source_event_ids: List[str] = Field(default_factory=list, max_length=100)


class CandidateTransitionIn(ReasonIn):
    to_state: Literal["TRIAGED", "ALLOWLISTED", "SUSPICIOUS", "REJECTED"]
    expected_revision: int = Field(ge=1)


class KnowledgeIn(ReasonIn):
    expected_revision: Optional[str] = Field(default=None, pattern=r"^[a-f0-9]{64}$")
    bundle: Dict[str, Any]


class KnowledgeRollbackIn(ReasonIn):
    revision: str = Field(pattern=r"^[a-f0-9]{64}$")
    expected_revision: str = Field(pattern=r"^[a-f0-9]{64}$")


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


SOURCE_LABELS = {"EXTERNAL_DEFENDER": "Defender"}     # detection_source -> nhãn hiển thị; còn lại là phát hiện của DACN


def _alert_out(a: dict) -> dict:
    a = dict(a)
    for k in ("mitre_technique_ids", "matched_fields", "missing_fields"):
        if isinstance(a.get(k), str):
            a[k] = json.loads(a[k])
    # Trường suy ra cho giao diện (không lưu DB): ai phát hiện. "Defender" = DACN chỉ phản ánh, không xác minh lại.
    a["source_label"] = SOURCE_LABELS.get(a.get("detection_source"), "DACN")
    return a


STATIC_DIR = Path(__file__).resolve().parents[1] / "dashboard" / "static"
CSP = ("default-src 'none'; script-src 'self'; style-src 'self'; connect-src 'self'; img-src 'self' data:; "
       "base-uri 'none'; form-action 'none'; frame-ancestors 'none'")


def create_app(cfg, tokens: TokenStore, *, store, rules: Dict[str, dict], policy, bronze_dir: Path,
               health_path: Optional[Path] = None, data_label: str = "UNSPECIFIED",
               lock: Optional[threading.RLock] = None, core_status=None, agent_poll_s: float = 2.0,
               risk_config=None, ml_enabled: Optional[Dict[str, bool]] = None) -> FastAPI:
    """data_label: 'SAMPLE' = dữ liệu mẫu/synthetic (UI hiện biểu ngữ nổi bật); 'UNSPECIFIED' = chưa xác nhận nguồn."""
    if data_label not in ("SAMPLE", "UNSPECIFIED"):
        raise ValueError("data_label không hợp lệ")
    app = FastAPI(title="DACN EDR Local API", version="0.1.0-mvp",
                  description="API cục bộ (loopback). Dữ liệu mẫu/synthetic nếu có sẽ được gắn nhãn ở nguồn.")
    lock = lock or threading.RLock()     # dùng chung với worker ghi để một kết nối DuckDB không bị truy cập song song
    con = store.con
    alerts, actions = AlertStore(con), ActionStore(con, AlertStore(con))
    actions.require_distinct = policy.require_distinct_approver
    q = Query(con)
    static = StaticWorkflow(con, [cfg.home / "lab"], cfg.home / "static-knowledge", lock=lock)
    health_path = Path(health_path) if health_path else cfg.home / "agent" / "health.json"
    risk_cfg = risk_config or load_risk_config()
    ml_on = {k: bool((ml_enabled or {}).get(k, False)) for k in ("ML_STATIC", "ML_BEHAVIOR")}

    def risk() -> RiskService:
        # Nạp allowlist mỗi lần: ioc.yaml có thể đổi (ADD_WHITELIST) mà không cần khởi động lại API.
        ioc_path = cfg.home / "ioc" / "ioc.yaml"
        return RiskService(con, rules, risk_cfg, ioc=IocStore(ioc_path), ml_enabled=ml_on)

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
        if request.method in ("POST", "PUT", "PATCH") and not (cl_ and cl_.isdigit()):
            return _err(411, "E-LENGTH_REQUIRED", "cần Content-Length (không nhận chunked không giới hạn)")
        resp = await call_next(request)
        resp.headers["X-Content-Type-Options"] = "nosniff"
        resp.headers["Cache-Control"] = "no-store"
        if request.url.path.startswith("/ui"):
            resp.headers["Content-Security-Policy"] = CSP
        return resp

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

    @app.get("/me", tags=["health"])
    def me(who: dict = Depends(need("read", "responder"))):
        return {"actor": who["actor"], "role": who["role"], "permissions": sorted(ROLES[who["role"]])}

    @app.get("/stats", tags=["health"])
    def stats(_: dict = Depends(need("read"))):
        with lock:
            by = lambda sql: {r[0]: r[1] for r in con.execute(sql).fetchall()}
            return {"alerts_by_severity": by("select severity, count(*) from alerts group by 1"),
                    "alerts_by_status": by("select status, count(*) from alerts group by 1"),
                    "coverage_gaps": con.execute("select count(*) from coverage_gaps").fetchone()[0],
                    "actions_by_status": by("select status, count(*) from response_actions group by 1")}

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
            # agent chết thì health.json giữ nguyên "running": chỉ tuổi heartbeat mới lộ ra
            age = (datetime.now(timezone.utc) - datetime.fromisoformat(agent["heartbeat"])).total_seconds()
            agent["heartbeat_age_s"] = age
            if agent.get("state") == "error":
                agent["status"] = "ERROR"        # agent dừng vì lỗi ghi (C-004); không che bằng STALE
            elif agent.get("state") != "stopped" and age > 3 * agent_poll_s:
                agent["status"] = "STALE"
            elif agent.get("state") == "degraded":
                agent["status"] = "DEGRADED"     # agent đa kênh: một phần kênh lỗi (xem agent.channels), kênh khác vẫn chạy
        except (OSError, ValueError, KeyError, TypeError):
            pass
        lag = (datetime.now(timezone.utc) - led[3]).total_seconds() if led[3] else None
        return {"data_label": data_label, "agent": agent, "core": core_status() if core_status else None,
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
    def list_alerts(status: Optional[STATUSES] = None, source: Optional[Literal["DACN", "DEFENDER"]] = None,
                    limit: int = Q(50, ge=1, le=200), offset: int = Q(0, ge=0), _: dict = Depends(need("read"))):
        ext = None if source is None else source == "DEFENDER"
        with lock:
            return page([_alert_out(a) for a in alerts.list(status, limit, offset, external=ext)], limit, offset)

    @app.get("/alerts/{alert_id}", tags=["alerts"])
    def alert(alert_id: str, _: dict = Depends(need("read"))):
        with lock:
            out = _alert_out(get_alert(alert_id))
        out["allowed_transitions"] = sorted(TRANSITIONS.get(out["status"], set()))
        return out

    # -- rủi ro tổng hợp: CHỈ ĐỌC, heuristic chưa hiệu chỉnh, không bao giờ kích hoạt response ----------------
    @app.get("/alerts/{alert_id}/risk", tags=["risk"])
    def alert_risk(alert_id: str, _: dict = Depends(need("read"))):
        with lock:
            out = risk().for_alert(alert_id)
        if out is None:
            raise HTTPException(404, "không tìm thấy alert")
        return out

    @app.get("/risk/config", tags=["risk"])
    def risk_config_get(_: dict = Depends(need("read"))):
        return {**risk_cfg.summary(), "values": risk_cfg.data, "ml_enabled": ml_on}

    @app.get("/risk/subjects", tags=["risk"])
    def risk_subjects(kind: Literal["process", "host"] = "process",
                      min_level: Optional[Literal["low", "medium", "high", "critical"]] = None,
                      limit: int = Q(50, ge=1, le=500), offset: int = Q(0, ge=0), _: dict = Depends(need("read"))):
        with lock:
            return page(risk().subjects(kind, min_level=min_level, limit=limit, offset=offset), limit, offset)

    @app.get("/risk/process", tags=["risk"])
    def risk_process(hostname: str = Q(..., min_length=1, max_length=255), process_guid: str = Q(..., min_length=1, max_length=64),
                     _: dict = Depends(need("read"))):
        with lock:
            return risk().process(hostname, process_guid)

    @app.get("/risk/host", tags=["risk"])
    def risk_host(hostname: str = Q(..., min_length=1, max_length=255), until: Optional[datetime] = None,
                  _: dict = Depends(need("read"))):
        if until is not None and until.tzinfo is None:
            raise ApiError(422, "E-VALIDATION", "until phải có múi giờ (UTC)")
        with lock:
            return risk().host(hostname, until=until)

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
                # PowerShell 4104: văn bản script có thể chứa bí mật (w8 mục 2.7) -> che nếu không xem raw (quyền `raw` + audit ở trên)
                if not include_raw and e["silver"].get("script_block_text") is not None:
                    e["silver"]["script_block_text"], hits = redact(e["silver"]["script_block_text"])
                    e["silver"]["script_redacted"] = True
                    e["silver"]["redaction_rules"] = sorted(set(hits))
        return ev

    @app.get("/alerts/{alert_id}/process-links", tags=["evidence"])
    def alert_process_links(alert_id: str, _: dict = Depends(need("read"))):
        """SUY LUẬN: tiến trình Sysmon ứng viên cho sự kiện Defender/PowerShell của alert (không ghi DB, không gán vào alert).
        Nhãn UNIQUE / AMBIGUOUS / NONE / NOT_APPLICABLE; mọi ứng viên được liệt kê. Không trả văn bản script."""
        with lock:
            a = get_alert(alert_id)
            return {"alert_id": alert_id, **links_for_alert(con, a["contributing_event_ids"])}

    @app.get("/alerts/{alert_id}/script", tags=["evidence"])
    def alert_script(alert_id: str, reveal: bool = False, who: dict = Depends(need("read"))):
        """Văn bản script block đã ghép của alert PowerShell (DACN-DET-203/204). Mặc định ĐÃ CHE chuỗi giống bí mật
        (heuristic, không bảo đảm che hết). reveal=true cần quyền `raw` và ghi audit SCRIPT_RAW_VIEW."""
        if reveal and "raw" not in ROLES[who["role"]]:
            raise HTTPException(403, "vai trò không được xem script gốc")
        with lock:
            a = get_alert(alert_id)
            sb = script_for_alert(con, a["contributing_event_ids"])
            if sb is None:
                raise HTTPException(404, "alert không có script block PowerShell")
            if reveal:
                alerts.record(who["actor"], "SCRIPT_RAW_VIEW", "alert", alert_id,
                              f"xem script gốc script_block_id={sb['script_block_id']}")
        if reveal:
            sb.update(redacted=False, redaction_rules=[])
        else:
            sb["text"], hits = redact(sb["text"])
            sb.update(redacted=True, redaction_rules=sorted(set(hits)), redaction_count=len(hits),
                      note="đã che chuỗi giống bí mật bằng heuristic; không bảo đảm che hết")
        return sb

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

    # -- điều tra: cây tiến trình theo (hostname, process_guid). CHỈ ĐỌC, không raw_data, không response --------------
    def _tz(*vals):
        for v in vals:
            if v is not None and v.tzinfo is None:
                raise ApiError(422, "E-VALIDATION", "since/until phải có múi giờ (UTC)")

    @app.get("/investigation/process-tree", tags=["investigation"])
    def inv_tree(hostname: str = Q(..., min_length=1, max_length=255), process_guid: str = Q(..., min_length=1, max_length=64),
                 max_depth: int = Q(8, ge=1, le=20), max_nodes: int = Q(200, ge=1, le=500),
                 since: Optional[datetime] = None, until: Optional[datetime] = None, _: dict = Depends(need("read"))):
        _tz(since, until)
        with lock:
            return process_tree_view(con, hostname, process_guid, max_depth=max_depth, max_nodes=max_nodes,
                                     since=since, until=until)

    @app.get("/investigation/process-events", tags=["investigation"])
    def inv_events(hostname: str = Q(..., min_length=1, max_length=255), process_guid: str = Q(..., min_length=1, max_length=64),
                   kinds: Optional[str] = Q(None, max_length=64, description="danh sách phân tách bằng dấu phẩy: "
                                            + ",".join(PROC_EVENT_KINDS)),
                   since: Optional[datetime] = None, until: Optional[datetime] = None,
                   limit: int = Q(50, ge=1, le=200), offset: int = Q(0, ge=0, le=1_000_000), _: dict = Depends(need("read"))):
        _tz(since, until)
        ks = [k.strip() for k in kinds.split(",") if k.strip()] if kinds else None
        try:
            with lock:
                return process_events(con, hostname, process_guid, kinds=ks, since=since, until=until,
                                      limit=limit, offset=offset)
        except ValueError as exc:
            raise ApiError(422, "E-VALIDATION", "kinds không hợp lệ") from exc

    @app.get("/investigation/process-search", tags=["investigation"])
    def inv_search(hostname: Optional[str] = Q(None, min_length=1, max_length=255),
                   image: Optional[str] = Q(None, min_length=2, max_length=260),
                   sha256: Optional[str] = Q(None, pattern=r"^[A-Fa-f0-9]{64}$"),
                   limit: int = Q(50, ge=1, le=200), _: dict = Depends(need("read"))):
        if not image and not sha256:
            raise ApiError(422, "E-VALIDATION", "cần image hoặc sha256")
        with lock:
            return {"items": search_processes(con, hostname=hostname, image=image, sha256=sha256, limit=limit), "limit": limit}

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
        ok, code = precheck(policy, body.action_type, body.target)
        if not ok:
            raise ApiError(422, "E-POLICY", f"mục tiêu bị policy từ chối: {code}")
        with lock:
            aid = actions.request(body.action_type, body.target, requested_by=who["actor"],
                                  requested_mode=body.requested_mode, alert_id=body.alert_id)
        return {"action_id": aid, "status": "REQUESTED"}

    @app.get("/response/actions", tags=["response"])
    def list_actions(status: Optional[Literal["REQUESTED", "APPROVED", "REJECTED", "EXECUTING", "DONE", "FAILED"]] = None,
                     alert_id: Optional[str] = Q(None, max_length=64), limit: int = Q(50, ge=1, le=200),
                     _: dict = Depends(need("read", "responder"))):
        conds, params = [], []
        if status:
            conds.append("status=?"); params.append(status)
        if alert_id:
            conds.append("alert_id=?"); params.append(alert_id)
        with lock:
            ids = [r[0] for r in con.execute(
                "select action_id from response_actions" + (" where " + " and ".join(conds) if conds else "") +
                " order by requested_at_utc desc limit ?", params + [limit]).fetchall()]
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

    # W07: chỉ đọc bytes trong <EDR_HOME>/lab; không nhận root từ HTTP.
    @app.post("/static/analyses", tags=["static"])
    def static_analyze(body: StaticIn, who: dict = Depends(need("alert_write"))):
        try:
            return static.analyze(body.path, source_event_ids=body.source_event_ids, actor=who["actor"])
        except KeyError as exc:
            raise ApiError(404, "E-SOURCE_NOT_FOUND", "không tìm thấy source event") from exc
        except (ValueError, OSError) as exc:
            raise ApiError(409, "E-STATIC_INPUT", "source/package không hợp lệ hoặc không truy cập được") from exc

    @app.get("/static/candidates", tags=["static"])
    def candidates(limit: int = Q(100, ge=1, le=500), offset: int = Q(0, ge=0),
                   _: dict = Depends(need("read"))):
        with lock:
            return page(static.candidates.list(limit, offset), limit, offset)

    @app.get("/static/candidates/{candidate_id}", tags=["static"])
    def candidate(candidate_id: str, _: dict = Depends(need("read"))):
        with lock:
            row = static.candidates.get(candidate_id)
        if row is None:
            raise HTTPException(404, "không tìm thấy candidate")
        return row

    @app.post("/static/candidates/{candidate_id}/transition", tags=["static"])
    def candidate_transition(candidate_id: str, body: CandidateTransitionIn,
                             who: dict = Depends(need("alert_write"))):
        try:
            with lock:
                return static.candidates.transition(candidate_id, body.to_state, expected_revision=body.expected_revision,
                                                    actor=who["actor"], role=who["role"], reason=body.reason)
        except KeyError as exc:
            raise HTTPException(404, "không tìm thấy candidate") from exc
        except PermissionError as exc:
            raise HTTPException(403, "cần người có quyền duyệt") from exc
        except ReviewError as exc:
            raise ApiError(409, "E-CANDIDATE_STATE", str(exc)) from exc

    @app.get("/static/candidates/{candidate_id}/history", tags=["static"])
    def candidate_history(candidate_id: str, _: dict = Depends(need("read"))):
        with lock:
            try:
                return {"items": static.candidates.history(candidate_id)}
            except KeyError as exc:
                raise HTTPException(404, "không tìm thấy candidate") from exc

    @app.get("/static/knowledge", tags=["static"])
    def knowledge(_: dict = Depends(need("read"))):
        with lock:
            rev, bundle = static.knowledge.snapshot()
        return {"revision": rev, "bundle": bundle}

    @app.post("/static/knowledge/activate", tags=["static"])
    def knowledge_activate(body: KnowledgeIn, who: dict = Depends(need("approve"))):
        try:
            with lock:
                rev = static.knowledge.activate(body.bundle, expected_revision=body.expected_revision,
                                                actor=who["actor"], reason=body.reason)
            return {"revision": rev}
        except (KnowledgeError, OSError, ValueError) as exc:
            raise ApiError(409, "E-KNOWLEDGE_UPDATE", "package không hợp lệ hoặc revision xung đột") from exc

    @app.post("/static/knowledge/rollback", tags=["static"])
    def knowledge_rollback(body: KnowledgeRollbackIn, who: dict = Depends(need("approve"))):
        try:
            with lock:
                rev = static.knowledge.rollback(body.revision, expected_revision=body.expected_revision,
                                                actor=who["actor"], reason=body.reason)
            return {"revision": rev}
        except (KnowledgeError, OSError, ValueError) as exc:
            raise ApiError(409, "E-KNOWLEDGE_UPDATE", "không thể rollback revision này") from exc

    @app.get("/", include_in_schema=False)
    def root():
        return RedirectResponse("/ui/")

    if STATIC_DIR.is_dir():
        app.mount("/ui", StaticFiles(directory=str(STATIC_DIR), html=True), name="ui")
    return app


def serve(cfg, app) -> None:     # pragma: no cover - chạy thật cần uvicorn
    import uvicorn
    uvicorn.run(app, host=cfg.api_host, port=cfg.api_port, log_level="info")
