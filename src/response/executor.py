"""Executor lõi (PH7-T03/T06). Thứ tự: phê duyệt -> policy -> audit BEGIN -> backend -> audit END.
Chế độ execute chỉ khi policy mở CẢ HAI khóa VÀ hành động yêu cầu execute; ngược lại luôn dry-run."""
from __future__ import annotations

import os
from typing import Optional

from .policy import Policy, check_file_target, check_process_target, check_restore_target

_CHECK = {"QUARANTINE_FILE": lambda p, t, own: check_file_target(p, t),
          "RESTORE_FILE": lambda p, t, own: check_restore_target(p, t),
          "TERMINATE_PROCESS": check_process_target}


def precheck(policy: Policy, action_type: str, target: dict):
    """(ok, mã lý do) dùng khi nhận yêu cầu, để người duyệt không duyệt hành động chắc chắn bị chặn.
    Executor vẫn kiểm lại lúc chạy (policy/đích có thể đổi). own_pid=-1: API không biết PID của responder."""
    if action_type not in policy.allowed_actions:
        return False, "P-ACTION_NOT_ALLOWED"
    return _CHECK[action_type](policy, target, -1)


class Executor:
    def __init__(self, policy: Policy, actions, real_backend, dryrun_backend, own_pid: Optional[int] = None):
        self.policy, self.actions = policy, actions
        self.real, self.dry = real_backend, dryrun_backend
        self.own_pid = os.getpid() if own_pid is None else own_pid

    def run(self, action_id: str) -> dict:
        a = self.actions.mark_executing(action_id)          # ném ActionError nếu chưa APPROVED
        t, typ = a["target"], a["action_type"]
        mode = "execute" if (self.policy.execute_allowed() and a["requested_mode"] == "execute") else "dry_run"
        audit = self.actions.audit

        def fail(code, msg=""):
            res = {"mode": mode, "code": code, "message": msg}
            self.actions.finish(action_id, "FAILED", res, {"possible": False, "note": "không có thay đổi"})
            audit.record("executor", "RESPONSE_EXEC_END", "response_action", action_id, f"FAILED {code}")
            return {"action_id": action_id, "status": "FAILED", "result": res, "rollback": {"possible": False}}

        if typ not in self.policy.allowed_actions:
            return fail("P-ACTION_NOT_ALLOWED")
        ok, code = _CHECK[typ](self.policy, t, self.own_pid)
        if not ok:
            return fail(code)
        audit.record("executor", "RESPONSE_EXEC_BEGIN", "response_action", action_id, f"{typ} mode={mode} target={t}")
        backend = self.real if mode == "execute" else self.dry
        try:
            out = backend.execute(typ, t, {"quarantine_dir": str(self.policy.quarantine_dir), "action_id": action_id})
        except Exception as exc:     # lỗi backend: trạng thái rõ ràng, không lặp vô hạn
            return fail("X-BACKEND_ERROR", type(exc).__name__)
        if not out.get("ok"):
            return fail(out.get("code", "X-FAILED"), out.get("message", ""))
        result = {"mode": mode, **{k: v for k, v in out.items() if k != "ok"}}
        rollback = {"possible": False, "note": "không thể hoàn tác"}
        if mode == "dry_run":
            rollback = {"possible": False, "note": "dry_run: không có thay đổi"}
        elif typ == "QUARANTINE_FILE":
            rollback = {"possible": True, "action": "RESTORE_FILE",
                        "target": {"quarantined_to": out["quarantined_to"], "original_path": out["original_path"],
                                   "expected_sha256": out["sha256"]}}
        elif typ == "TERMINATE_PROCESS":
            rollback = {"possible": False, "note": "tiến trình đã bị kết thúc không khôi phục được"}
        self.actions.finish(action_id, "DONE", result, rollback)
        audit.record("executor", "RESPONSE_EXEC_END", "response_action", action_id, f"DONE mode={mode} rollback={rollback.get('possible')}")
        return {"action_id": action_id, "status": "DONE", "result": result, "rollback": rollback}
