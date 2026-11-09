"""Bộ chuyển đổi cho responder chạy tách tiến trình: cùng giao diện ActionStore nhưng đi qua API cục bộ (PH7-T07)."""
from __future__ import annotations

import json
import os
import time
from pathlib import Path
from typing import List, Optional

import httpx


class _Audit:
    def __init__(self, http):
        self.http = http

    def record(self, actor, action, target_type, target_id, reason) -> None:
        r = self.http.post("/response/audit", json={"action": action, "target_id": target_id, "reason": str(reason)[:2000]})
        r.raise_for_status()


class RemoteActions:
    """spool_dir: kết quả chưa gửi được lưu ở đây (kể cả quarantined_to để rollback) tới khi API nhận."""

    def __init__(self, http, spool_dir: Optional[Path] = None, retries: int = 3, backoff: float = 0.2):
        self.http = http
        self.audit = _Audit(http)
        self.spool = Path(spool_dir) if spool_dir else None
        self.retries, self.backoff = retries, backoff

    def list_approved(self) -> List[dict]:
        return self._list("APPROVED")

    def _list(self, status: str) -> List[dict]:
        r = self.http.get("/response/actions", params={"status": status})
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

    def _post_result(self, aid: str, body: dict) -> None:
        for i in range(self.retries):
            try:
                r = self.http.post(f"/response/actions/{aid}/result", json=body)
                if r.status_code == 409:      # đã được chốt (ví dụ đã đánh dấu FAILED): không gửi lại
                    return
                r.raise_for_status()
                return
            except httpx.HTTPError:
                if i == self.retries - 1:
                    raise
                time.sleep(self.backoff * 2 ** i)

    def finish(self, aid: str, status: str, result: dict, rollback: dict) -> None:
        body = {"status": status, "result": result, "rollback": rollback}
        try:
            self._post_result(aid, body)
        except httpx.HTTPError:
            if self.spool:      # giữ kết quả thật để flush_spool gửi lại; không mất dữ liệu rollback
                self.spool.mkdir(parents=True, exist_ok=True)
                tmp = self.spool / (aid + ".tmp")
                tmp.write_text(json.dumps({"aid": aid, **body}, default=str), encoding="utf-8")
                os.replace(tmp, self.spool / (aid + ".json"))
            raise

    def flush_spool(self) -> int:
        """Gửi lại các kết quả đã lưu. Trả số kết quả đã gửi xong."""
        n = 0
        for f in sorted(self.spool.glob("*.json")) if self.spool and self.spool.is_dir() else []:
            d = json.loads(f.read_text(encoding="utf-8"))
            self._post_result(d["aid"], {k: d[k] for k in ("status", "result", "rollback")})
            f.unlink()
            n += 1
        return n

    def recover_executing(self) -> List[str]:
        """Gọi khi khởi động SAU flush_spool: hành động còn EXECUTING nghĩa là tiến trình trước chết giữa chừng.
        Không biết thay đổi đã xảy ra chưa, nên đánh dấu FAILED để người dùng kiểm tra thủ công."""
        ids = []
        for a in self._list("EXECUTING"):
            aid = a["action_id"]
            msg = "không rõ kết quả, kiểm tra thủ công"
            self._post_result(aid, {"status": "FAILED", "result": {"mode": "unknown", "code": "X-UNKNOWN_OUTCOME", "message": msg},
                                    "rollback": {"possible": False, "note": msg}})
            self.audit.record("executor", "RESPONSE_EXEC_END", "response_action", aid, "FAILED X-UNKNOWN_OUTCOME " + msg)
            ids.append(aid)
        return ids
