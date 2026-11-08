"""Mô hình hành động và hàng đợi (PH7-T02): REQUESTED -> APPROVED/REJECTED -> EXECUTING -> DONE/FAILED."""
from __future__ import annotations

import json
import uuid
from datetime import datetime, timezone
from typing import Dict, List, Optional

from .policy import ACTION_TYPES


class ActionError(ValueError):
    pass


def _now():
    return datetime.now(timezone.utc)


def _need(**kw):
    for k, v in kw.items():
        if not (v and str(v).strip()):
            raise ValueError(f"thiếu {k}")


class ActionStore:
    def __init__(self, con, audit, require_distinct: bool = False):
        self.con, self.audit, self.require_distinct = con, audit, require_distinct

    def get(self, aid: str) -> Optional[Dict]:
        cur = self.con.execute("select * from response_actions where action_id=?", [aid])
        cols = [c[0] for c in cur.description]
        r = cur.fetchone()
        if not r:
            return None
        d = dict(zip(cols, r))
        for k in ("target", "result", "rollback"):
            d[k] = json.loads(d[k]) if d.get(k) else None
        return d

    def list_by_status(self, status: str) -> List[Dict]:
        ids = [r[0] for r in self.con.execute("select action_id from response_actions where status=? order by requested_at_utc", [status]).fetchall()]
        return [self.get(i) for i in ids]

    def request(self, action_type: str, target: dict, *, requested_by: str, requested_mode: str, alert_id: str = None) -> str:
        if action_type not in ACTION_TYPES:
            raise ActionError(f"loại hành động không hỗ trợ: {action_type}")
        if requested_mode not in ("dry_run", "execute"):
            raise ActionError("requested_mode phải là dry_run hoặc execute")
        _need(requested_by=requested_by)
        aid, now = str(uuid.uuid4()), _now()
        self.con.execute("insert into response_actions (action_id, alert_id, action_type, target, requested_mode, status,"
                         " requested_by, requested_at_utc, updated_at_utc) values (?,?,?,?,?,'REQUESTED',?,?,?)",
                         [aid, alert_id, action_type, json.dumps(target), requested_mode, requested_by, now, now])
        self.audit.record(requested_by, "RESPONSE_REQUEST", "response_action", aid, f"{action_type} ({requested_mode})")
        return aid

    def _must(self, aid: str, expected: str) -> Dict:
        a = self.get(aid)
        if a is None:
            raise KeyError(aid)
        if a["status"] != expected:
            raise ActionError(f"trạng thái {a['status']}, cần {expected}")
        return a

    def approve(self, aid: str, *, approver: str, reason: str) -> None:
        _need(approver=approver, reason=reason)
        a = self._must(aid, "REQUESTED")
        if self.require_distinct and approver == a["requested_by"]:
            raise ActionError("người duyệt phải khác người yêu cầu")
        self.con.execute("update response_actions set status='APPROVED', approved_by=?, approved_at_utc=?, decision_reason=?,"
                         " updated_at_utc=? where action_id=?", [approver, _now(), reason, _now(), aid])
        self.audit.record(approver, "RESPONSE_APPROVE", "response_action", aid, reason)

    def reject(self, aid: str, *, approver: str, reason: str) -> None:
        _need(approver=approver, reason=reason)
        self._must(aid, "REQUESTED")
        self.con.execute("update response_actions set status='REJECTED', approved_by=?, approved_at_utc=?, decision_reason=?,"
                         " updated_at_utc=? where action_id=?", [approver, _now(), reason, _now(), aid])
        self.audit.record(approver, "RESPONSE_REJECT", "response_action", aid, reason)

    def mark_executing(self, aid: str) -> Dict:
        a = self._must(aid, "APPROVED")
        self.con.execute("update response_actions set status='EXECUTING', updated_at_utc=? where action_id=?", [_now(), aid])
        return a

    def finish(self, aid: str, status: str, result: dict, rollback: dict) -> None:
        assert status in ("DONE", "FAILED")
        self.con.execute("update response_actions set status=?, result=?, rollback=?, updated_at_utc=? where action_id=?",
                         [status, json.dumps(result, default=str), json.dumps(rollback, default=str), _now(), aid])
