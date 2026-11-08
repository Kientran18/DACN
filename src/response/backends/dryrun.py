"""Backend dry-run: KHÔNG chạm hệ thống, chỉ mô tả điều sẽ làm."""
from __future__ import annotations


class DryRunBackend:
    def execute(self, action_type: str, target: dict, ctx: dict) -> dict:
        return {"ok": True, "planned": f"{action_type} trên {target}", "identity_verified": False,
                "note": "dry_run: không có thay đổi nào được thực hiện"}
