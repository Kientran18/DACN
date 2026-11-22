"""Nguồn đọc từ tệp XML export (wevtutil/Get-WinEvent). Bookmark = chỉ số sự kiện."""
from __future__ import annotations

from pathlib import Path
from typing import Iterator, Optional

import bronze_contract as bc

from .base import RawItem, SourceError


class FileEventSource:
    def __init__(self, path: Path):
        self.path = Path(path)

    def iter_events(self, from_bookmark: Optional[str]) -> Iterator[RawItem]:
        start = int(from_bookmark) + 1 if from_bookmark is not None else 0
        try:
            for i, xml in enumerate(bc.iter_raw_xml_from_file(self.path)):
                if i >= start:
                    yield RawItem(xml, str(i))
        except UnicodeError as exc:       # hợp đồng W5: lỗi giải mã văn bản/BOM = C-003, không làm chết agent
            raise SourceError("C-003", "không giải mã được tệp XML") from exc
