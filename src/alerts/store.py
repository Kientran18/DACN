"""Alert store, dedup, máy trạng thái, incident, audit (PH6-T03/T06). Dùng chung kết nối DuckDB (một writer)."""
from __future__ import annotations

import functools
import hashlib
import json
import uuid
from contextlib import contextmanager
from datetime import datetime, timezone
from typing import Dict, List, Optional

TRANSITIONS = {
    "NEW": {"TRIAGED"},
    "TRIAGED": {"INVESTIGATING", "FALSE_POSITIVE", "CLOSED"},
    "INVESTIGATING": {"FALSE_POSITIVE", "CONFIRMED", "CLOSED"},
    "CONFIRMED": {"CLOSED"},
    "FALSE_POSITIVE": set(),
    "CLOSED": set(),
}
_ZERO = "0" * 64


class InvalidTransition(ValueError):
    pass


def _now():
    return datetime.now(timezone.utc)


def _iso(dt) -> str:
    return dt.astimezone(timezone.utc).isoformat(timespec="microseconds")


def _need(**kw):
    for k, v in kw.items():
        if not (v and str(v).strip()):
            raise ValueError(f"thiếu {k}")


def _atomic(fn):
    """Thay đổi dữ liệu + dòng audit tương ứng phải cùng một transaction: crash giữa chừng không để lệch."""
    @functools.wraps(fn)
    def wrapper(self, *a, **k):
        with self.tx():
            return fn(self, *a, **k)
    return wrapper


class AlertStore:
    def __init__(self, con):
        self.con = con
        self._in_tx = False

    @contextmanager
    def tx(self):
        """begin/commit, rollback khi lỗi; lồng nhau thì dùng transaction ngoài cùng (DuckDB không có nested).
        Người gọi phải giữ khóa dùng chung kết nối (như API/core đang làm)."""
        if self._in_tx:
            yield
            return
        self.con.execute("begin")
        self._in_tx = True
        try:
            yield
            self.con.execute("commit")
        except BaseException:
            self.con.execute("rollback")
            raise
        finally:
            self._in_tx = False

    # -- audit (append-only, chuỗi băm) ---------------------------------------
    def _audit(self, actor, action, target_type, target_id, reason) -> None:
        row = self.con.execute("select seq, row_hash from audit_log order by seq desc limit 1").fetchone()
        seq, prev = (row[0] + 1, row[1]) if row else (1, _ZERO)
        at = _now()
        h = hashlib.sha256("|".join([str(seq), _iso(at), actor, action, target_type, target_id,
                                     reason, prev]).encode()).hexdigest()
        self.con.execute("insert into audit_log values (?,?,?,?,?,?,?,?,?)",
                         [seq, at, actor, action, target_type, target_id, reason, prev, h])

    def record(self, actor, action, target_type, target_id, reason) -> None:
        """Ghi audit từ module khác (response). Append-only."""
        self._audit(actor, action, target_type, target_id, reason)

    def verify_audit(self) -> List[str]:
        """Danh sách vấn đề (rỗng = chuỗi nguyên vẹn). Phát hiện sửa/xóa/chèn."""
        issues, prev, expect = [], _ZERO, 1
        for seq, at, actor, action, tt, tid, reason, ph, rh in self.con.execute(
                "select seq, at_utc, actor, action, target_type, target_id, reason, prev_hash, row_hash "
                "from audit_log order by seq").fetchall():
            if seq != expect:
                issues.append(f"seq {expect} bị thiếu")
                expect = seq
            if ph != prev:
                issues.append(f"seq {seq}: prev_hash sai")
            if hashlib.sha256("|".join([str(seq), _iso(at), actor, action, tt, tid, reason, ph]).encode()).hexdigest() != rh:
                issues.append(f"seq {seq}: nội dung không khớp row_hash")
            prev, expect = rh, seq + 1
        return issues

    # -- alert -----------------------------------------------------------------
    @_atomic
    def insert_alert(self, **f) -> str:
        aid = str(uuid.uuid5(uuid.NAMESPACE_URL, "dacn-alert|" + f["detection_dedup_key"]))
        now = _now()
        self.con.execute(
            "insert into alerts (alert_id, detection_dedup_key, group_key, created_at_utc, first_seen_utc, last_seen_utc,"
            " occurrence_count, detection_source, rule_id, rule_version, rule_name, severity, severity_reason, status,"
            " mitre_technique_ids, hostname, process_guid, image_path, command_line, user_name, contributing_event_ids,"
            " matched_fields, missing_fields, coverage_status) values (?,?,?,?,?,?,1,?,?,?,?,?,?,'NEW',?,?,?,?,?,?,?,?,?,?)",
            [aid, f["detection_dedup_key"], f["group_key"], now, f["first_seen_utc"], f["last_seen_utc"],
             f["detection_source"], f["rule_id"], f["rule_version"], f["rule_name"], f["severity"], f["severity_reason"],
             json.dumps(f.get("mitre_technique_ids")) if f.get("mitre_technique_ids") else None,
             f["hostname"], f.get("process_guid"), f.get("image_path"), f.get("command_line"), f.get("user_name"),
             list(f["contributing_event_ids"]), json.dumps(f.get("matched_fields") or {}, default=str),
             json.dumps(f.get("missing_fields") or []), f.get("coverage_status", "FULL")])
        self.con.execute("insert into alert_status_history values (?,?,?,?,?,?,?)",
                         [str(uuid.uuid4()), aid, None, "NEW", "system", "alert được tạo từ DetectionResult", now])
        self._audit("system", "ALERT_CREATE", "alert", aid, f["rule_id"])
        return aid

    def find_group(self, group_key: str) -> Optional[str]:
        r = self.con.execute("select alert_id from alerts where group_key=? order by created_at_utc limit 1", [group_key]).fetchone()
        return r[0] if r else None

    def exists_dedup(self, key: str) -> bool:
        return bool(self.con.execute("select 1 from alerts where detection_dedup_key=?", [key]).fetchone())

    @_atomic
    def bump(self, alert_id: str, last_seen, event_ids) -> None:
        self.con.execute(
            "update alerts set occurrence_count = occurrence_count + 1, last_seen_utc = greatest(last_seen_utc, ?),"
            " contributing_event_ids = list_distinct(list_concat(contributing_event_ids, ?)) where alert_id=?",
            [last_seen, list(event_ids), alert_id])
        self._audit("system", "ALERT_SUPPRESS_DUPLICATE", "alert", alert_id, "trùng nhóm dedup")

    def get(self, alert_id: str) -> Optional[Dict]:
        cur = self.con.execute("select * from alerts where alert_id=?", [alert_id])
        cols = [c[0] for c in cur.description]
        r = cur.fetchone()
        return dict(zip(cols, r)) if r else None

    def list(self, status: Optional[str] = None, limit: int = 100, offset: int = 0) -> List[Dict]:
        sql, params = "select * from alerts", []
        if status:
            sql += " where status=?"; params.append(status)
        cur = self.con.execute(sql + " order by first_seen_utc desc, alert_id limit ? offset ?",
                               params + [min(max(limit, 1), 500), max(offset, 0)])
        cols = [c[0] for c in cur.description]
        return [dict(zip(cols, r)) for r in cur.fetchall()]

    @_atomic
    def transition(self, alert_id: str, to_status: str, *, actor: str, note: str) -> None:
        _need(actor=actor, note=note)
        a = self.get(alert_id)
        if a is None:
            raise KeyError(alert_id)
        if to_status not in TRANSITIONS.get(a["status"], set()):
            raise InvalidTransition(f"{a['status']} -> {to_status} không hợp lệ")
        self.con.execute("update alerts set status=? where alert_id=?", [to_status, alert_id])
        self.con.execute("insert into alert_status_history values (?,?,?,?,?,?,?)",
                         [str(uuid.uuid4()), alert_id, a["status"], to_status, actor, note, _now()])
        self._audit(actor, "ALERT_" + to_status, "alert", alert_id, note)

    def history(self, alert_id: str) -> List[Dict]:
        cur = self.con.execute("select * from alert_status_history where alert_id=? order by at_utc, to_status", [alert_id])
        cols = [c[0] for c in cur.description]
        rows = [dict(zip(cols, r)) for r in cur.fetchall()]
        order = ["NEW", "TRIAGED", "INVESTIGATING", "CONFIRMED", "FALSE_POSITIVE", "CLOSED"]
        return sorted(rows, key=lambda r: (r["at_utc"], order.index(r["to_status"])))

    # -- coverage gap ------------------------------------------------------------
    @_atomic
    def add_gap(self, **f) -> str:
        gid = str(uuid.uuid5(uuid.NAMESPACE_URL, "dacn-gap|" + f["detection_dedup_key"]))
        self.con.execute("insert into coverage_gaps values (?,?,?,?,?,?,?,?,?) on conflict do nothing",
                         [gid, f["detection_dedup_key"], f["rule_id"], f["rule_version"], f.get("hostname"),
                          list(f["contributing_event_ids"]), json.dumps(f["missing_fields"]), f["coverage_status"], _now()])
        return gid

    # -- incident ----------------------------------------------------------------
    @_atomic
    def create_incident(self, title: str, *, actor: str) -> str:
        _need(title=title, actor=actor)
        iid = str(uuid.uuid4())
        self.con.execute("insert into incidents values (?,?,'OPEN',?,?)", [iid, title, _now(), actor])
        self._audit(actor, "INCIDENT_CREATE", "incident", iid, title)
        return iid

    @_atomic
    def link_alert(self, incident_id: str, alert_id: str, *, actor: str) -> None:
        _need(actor=actor)
        if self.get(alert_id) is None:
            raise KeyError(alert_id)
        self.con.execute("insert into incident_alerts values (?,?,?,?) on conflict do nothing",
                         [incident_id, alert_id, _now(), actor])
        self._audit(actor, "INCIDENT_LINK_ALERT", "incident", incident_id, alert_id)

    @_atomic
    def add_note(self, incident_id: str, note: str, *, actor: str) -> str:
        _need(note=note, actor=actor)
        nid = str(uuid.uuid4())
        self.con.execute("insert into incident_notes values (?,?,?,?,?)", [nid, incident_id, actor, note, _now()])
        self._audit(actor, "INCIDENT_NOTE", "incident", incident_id, note)
        return nid
