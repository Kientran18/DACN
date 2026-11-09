"""THỬ NGHIỆM, CHƯA NỐI VÀO HỆ THỐNG (chỉ tests/ gọi; nằm ngoài src/ có chủ ý). Auto-response có cổng (PH7-T08). MẶC ĐỊNH TẮT.
Tự yêu cầu và tự duyệt nên vô hiệu khi require_distinct_approver=true (mặc định). Cần: enabled, mode execute + unlocked, rule và action được liệt kê,
bằng chứng đầy đủ (coverage FULL), và không bắt buộc người duyệt khác người yêu cầu."""
from __future__ import annotations

from typing import Optional

from response.policy import Policy

AUTO = "policy:auto"


class AutoResponder:
    def __init__(self, policy: Policy, actions):
        self.policy, self.actions = policy, actions

    def propose(self, alert: dict, action_type: str, target: dict) -> Optional[str]:
        ar = self.policy.auto_response or {}
        if not ar.get("enabled") or not self.policy.execute_allowed() or self.policy.require_distinct_approver:
            return None
        if alert.get("rule_id") not in ar.get("rules", []) or action_type not in ar.get("allowed_actions", []):
            return None
        if action_type not in self.policy.allowed_actions or alert.get("coverage_status") != "FULL":
            return None
        aid = self.actions.request(action_type, target, requested_by=AUTO, requested_mode="execute", alert_id=alert.get("alert_id"))
        self.actions.approve(aid, approver=AUTO, reason=f"auto-response theo policy cho {alert['rule_id']}")
        return aid
