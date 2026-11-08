"""Checkpoint/bookmark (PH2-T03): ghi tạm → fsync → os.replace (có retry cho PermissionError)."""
from __future__ import annotations

import json
import os
import time
from pathlib import Path
from typing import Optional, Tuple


class Checkpoint:
    def __init__(self, path: Path, retries: int = 5, backoff: float = 0.05):
        self.path = Path(path)
        self.retries = retries
        self.backoff = backoff

    def load(self) -> Tuple[Optional[str], Optional[str]]:
        """Trả (bookmark, reason_code). Hỏng → (None, 'C-005')."""
        if not self.path.exists():
            return None, None
        try:
            data = json.loads(self.path.read_text(encoding="utf-8"))
            bm = data["bookmark"]
            if not isinstance(bm, str):
                raise TypeError
            return bm, None
        except (ValueError, KeyError, TypeError, OSError):
            return None, "C-005"

    def save(self, bookmark: str) -> None:
        self.path.parent.mkdir(parents=True, exist_ok=True)
        tmp = self.path.with_suffix(".tmp")
        with tmp.open("w", encoding="utf-8", newline="\n") as f:
            json.dump({"bookmark": bookmark}, f)
            f.flush()
            os.fsync(f.fileno())
        for attempt in range(self.retries):
            try:
                os.replace(tmp, self.path)
                return
            except PermissionError:
                if attempt == self.retries - 1:
                    raise
                time.sleep(self.backoff * (2 ** attempt))
