"""Tiến trình responder (PH7-T07): kéo hành động APPROVED, thực thi qua Executor, báo kết quả.
fetch/report là hàm trừu tượng; bộ chuyển đổi API cục bộ (token) được thêm ở PH8-T06. Core không giữ quyền response."""
from __future__ import annotations

from typing import Callable, List


class Responder:
    def __init__(self, fetch_approved: Callable[[], List[dict]], executor, report: Callable[[str, dict], None]):
        self.fetch, self.executor, self.report = fetch_approved, executor, report

    def run_once(self) -> int:
        n = 0
        for a in self.fetch():
            res = self.executor.run(a["action_id"])
            self.report(a["action_id"], res)
            n += 1
        return n
