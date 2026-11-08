"""Đọc segment Bronze đã seal có xác minh (PH3-T01). Chỉ đọc `.jsonl` có manifest."""
from __future__ import annotations

import json
from pathlib import Path
from typing import Iterator, List, Tuple

from agent.bronze_writer import verify_segment


class SegmentError(Exception):
    def __init__(self, code: str, detail: str = ""):
        super().__init__(f"{code} {detail}".strip())
        self.code = code


def list_sealed(directory: Path) -> List[Path]:
    """Chỉ các `.jsonl` (không phải `.part`), sắp theo tên (tên chứa thời gian)."""
    return sorted(p for p in Path(directory).glob("seg-*.jsonl"))


def read_segment(seg: Path) -> Iterator[Tuple[int, dict]]:
    """Phát (line_no, record). V-007 nếu manifest thiếu hoặc hash/số bản ghi sai."""
    errs = verify_segment(seg)
    if errs:
        raise SegmentError("V-007", ",".join(errs))
    with Path(seg).open("rb") as f:
        for n, line in enumerate(f, 1):
            yield n, json.loads(line)
