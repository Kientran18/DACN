"""Bộ chuyển đổi cho responder chạy tách tiến trình: cùng giao diện ActionStore nhưng đi qua API cục bộ (PH7-T07)."""
from __future__ import annotations

from typing import List


class _Audit:
    def __init__(self, http):
        self.http = http

    def record(self, actor, action, target_type, target_id, reason) -> None:
        r = self.http.post("/response/audit", json={"action": action, "target_id": target_id, "reason": str(reason)[:2000]})
        r.raise_for_status()


class RemoteActions:
    def __init__(self, http):
        self.http = http
        self.audit = _Audit(http)

    def list_approved(self) -> List[dict]:
        r = self.http.get("/response/actions", params={"status": "APPROVED"})
        r.raise_for_status()
        return r.json()["items"]

    def get(self, aid: str):
        r = self.http.get(f"/response/actions/{aid}")
        return r.json() if r.status_code == 200 else None

    def mark_executing(self, aid: str) -> dict:
        from .actions import ActionError
        r = self.http.post(f"/response/actions/{aid}/claim")
        if r.status_code == 409:
            raise ActionError(r.json()["error"]["message"])
        r.raise_for_status()
        return r.json()

    def finish(self, aid: str, status: str, result: dict, rollback: dict) -> None:
        self.http.post(f"/response/actions/{aid}/result", json={"status": status, "result": result, "rollback": rollback}).raise_for_status()
