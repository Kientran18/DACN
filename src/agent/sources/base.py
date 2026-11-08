"""Giao diện nguồn sự kiện (PH2-T01). Nguồn phát XML thô kèm bookmark."""
from __future__ import annotations

from dataclasses import dataclass
from typing import Iterator, Optional, Protocol


@dataclass(frozen=True)
class RawItem:
    xml: str
    bookmark: str  # chuỗi bất kỳ do nguồn định nghĩa; đưa lại vào iter_events để tiếp tục


class SourceError(RuntimeError):
    """Lỗi nguồn; `code` là mã lý do (ví dụ C-006 lỗi quyền)."""

    def __init__(self, code: str, message: str = ""):
        super().__init__(f"{code} {message}".strip())
        self.code = code


class EventSource(Protocol):
    def iter_events(self, from_bookmark: Optional[str]) -> Iterator[RawItem]:
        """Phát các sự kiện SAU bookmark (None = từ đầu)."""
        ...
