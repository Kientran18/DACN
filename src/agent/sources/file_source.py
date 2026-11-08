"""Nguồn đọc từ tệp XML export (wevtutil/Get-WinEvent). Bookmark = chỉ số sự kiện."""
from __future__ import annotations

from pathlib import Path
from typing import Iterator, Optional

import bronze_contract as bc

from .base import RawItem


class FileEventSource:
    def __init__(self, path: Path):
        self.path = Path(path)

    def iter_events(self, from_bookmark: Optional[str]) -> Iterator[RawItem]:
        start = int(from_bookmark) + 1 if from_bookmark is not None else 0
        for i, xml in enumerate(bc.iter_raw_xml_from_file(self.path)):
            if i >= start:
                yield RawItem(xml, str(i))
