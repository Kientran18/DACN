"""Logging JSONL (PH1-T09): ts, level, component, run_id, event, reason_code.
Loại bỏ các trường nhạy cảm (command line, XML thô) trước khi ghi."""
from __future__ import annotations

import json
import sys
import uuid
from datetime import datetime, timezone
from pathlib import Path
from typing import Optional

_BLOCKED = {"commandline", "command_line", "raw_xml", "event_data", "parentcommandline", "username", "user"}


class JsonlLogger:
    def __init__(self, component: str, path: Optional[Path], run_id: Optional[str]):
        self.component = component
        self.path = Path(path) if path else None
        self.run_id = run_id or uuid.uuid4().hex[:12]
        if self.path:
            self.path.parent.mkdir(parents=True, exist_ok=True)

    def _emit(self, level: str, event: str, reason_code: Optional[str], fields: dict) -> None:
        row = {"ts": datetime.now(timezone.utc).isoformat(), "level": level,
               "component": self.component, "run_id": self.run_id,
               "event": event, "reason_code": reason_code}
        row.update({k: v for k, v in fields.items() if k.lower() not in _BLOCKED})
        line = json.dumps(row, ensure_ascii=False, default=str)
        if self.path:
            with self.path.open("a", encoding="utf-8", newline="\n") as fh:
                fh.write(line + "\n")
        else:
            sys.stderr.write(line + "\n")

    def info(self, event, reason_code=None, **f): self._emit("INFO", event, reason_code, f)
    def warning(self, event, reason_code=None, **f): self._emit("WARNING", event, reason_code, f)
    def error(self, event, reason_code=None, **f): self._emit("ERROR", event, reason_code, f)


def get_logger(component: str, path: Optional[Path] = None, run_id: Optional[str] = None) -> JsonlLogger:
    return JsonlLogger(component, path, run_id)
