"""Nguồn giả có kịch bản (PH2-T01) — dùng cho test; không phải dữ liệu thật."""
from __future__ import annotations

from typing import Iterator, List, Optional

from .base import RawItem, SourceError


class FakeEventSource:
    def __init__(self, xmls: List[str], *, stop_after: Optional[int] = None,
                 fail_after: Optional[int] = None, fail_code: str = "C-006"):
        self.xmls = list(xmls)
        self.stop_after = stop_after    # kết thúc êm sau N sự kiện (mô phỏng dừng giữa chừng)
        self.fail_after = fail_after    # ném SourceError sau N sự kiện
        self.fail_code = fail_code

    def iter_events(self, from_bookmark: Optional[str]) -> Iterator[RawItem]:
        start = int(from_bookmark) + 1 if from_bookmark is not None else 0
        emitted = 0
        for i in range(start, len(self.xmls)):
            if self.stop_after is not None and emitted >= self.stop_after:
                return
            if self.fail_after is not None and emitted >= self.fail_after:
                raise SourceError(self.fail_code, "fake failure")
            yield RawItem(self.xmls[i], str(i))
            emitted += 1
