"""Candidate Review local, CAS revision + audit cùng transaction; không tự sửa global allowlist."""
from __future__ import annotations

import json
import uuid

from alerts.store import AlertStore

DDL = """
CREATE TABLE IF NOT EXISTS static_candidates (
    candidate_id VARCHAR PRIMARY KEY, schema_version VARCHAR, state VARCHAR, revision INTEGER,
    created_by VARCHAR, analysis JSON, verdict JSON, detection JSON, alert_ids JSON,
    created_at TIMESTAMPTZ DEFAULT CURRENT_TIMESTAMP
)
"""
TRANSITIONS = {"NEW": {"TRIAGED"}, "TRIAGED": {"ALLOWLISTED", "SUSPICIOUS", "REJECTED"},
               "ALLOWLISTED": set(), "SUSPICIOUS": set(), "REJECTED": set()}


class ReviewError(ValueError):
    pass


class CandidateStore:
    def __init__(self, con):
        self.con, self.audit = con, AlertStore(con)
        con.execute(DDL)  # bảng mở rộng W07, không đổi Silver/Bronze v1.x

    def create(self, analysis, verdict, detection, alert_ids, *, actor):
        if not actor.strip():
            raise ReviewError("actor bắt buộc")
        cid = str(uuid.uuid5(uuid.NAMESPACE_URL, "dacn-candidate|" + analysis["analysis_id"]))
        with self.audit.tx():
            if self.get(cid) is not None:
                return self.get(cid)
            self.con.execute("insert into static_candidates (candidate_id,schema_version,state,revision,created_by,"
                             "analysis,verdict,detection,alert_ids) values (?,?,'NEW',1,?,?,?,?,?)",
                             [cid, "dacn-candidate/1.0", actor, json.dumps(analysis), json.dumps(verdict),
                              json.dumps(detection), json.dumps(alert_ids)])
            self.audit.record(actor, "CANDIDATE_CREATE", "static_candidate", cid, "static observation; alert-only")
        return self.get(cid)

    def get(self, cid):
        cur = self.con.execute("select * from static_candidates where candidate_id=?", [cid])
        names, row = [x[0] for x in cur.description], cur.fetchone()
        if row is None:
            return None
        data = dict(zip(names, row))
        for k in ("analysis", "verdict", "detection", "alert_ids"):
            data[k] = json.loads(data[k])
        data["created_at"] = data["created_at"].isoformat()
        return data

    def list(self, limit=100, offset=0):
        ids = self.con.execute("select candidate_id from static_candidates order by created_at,candidate_id limit ? offset ?",
                               [min(max(limit, 1), 500), max(0, offset)]).fetchall()
        return [self.get(x[0]) for x in ids]

    def history(self, cid):
        if self.get(cid) is None:
            raise KeyError(cid)
        rows = self.con.execute("select seq,at_utc,actor,action,reason,row_hash from audit_log "
                                "where target_type='static_candidate' and target_id=? order by seq", [cid]).fetchall()
        return [{"seq": r[0], "at": r[1].isoformat(), "actor": r[2], "action": r[3],
                 "reason": r[4], "row_hash": r[5]} for r in rows]

    def transition(self, cid, to_state, *, expected_revision, actor, role, reason):
        if role not in ("analyst", "approver") or (to_state != "TRIAGED" and role != "approver"):
            raise PermissionError("review cần đúng vai trò")
        if not actor.strip() or not reason.strip():
            raise ReviewError("actor/reason bắt buộc")
        with self.audit.tx():
            old = self.get(cid)
            if old is None:
                raise KeyError(cid)
            if old["revision"] != expected_revision:
                raise ReviewError("REVISION_CONFLICT")
            if to_state not in TRANSITIONS[old["state"]]:
                raise ReviewError("INVALID_TRANSITION")
            if to_state == "ALLOWLISTED" and (old["analysis"]["status"] != "OK" or
                                               old["verdict"]["signature_hit"]["ioc_ids"]):
                raise ReviewError("không allowlist quan sát lỗi hoặc IOC conflict chưa giải quyết")
            self.con.execute("update static_candidates set state=?,revision=revision+1 where candidate_id=?",
                             [to_state, cid])
            self.audit.record(actor, "CANDIDATE_" + to_state, "static_candidate", cid, reason)
        return self.get(cid)
