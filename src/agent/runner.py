"""AgentRunner (PH2-T07): đọc lô → ghi Bronze → fsync → mới lưu bookmark (at-least-once)."""
from __future__ import annotations

import json
import os
from collections import Counter
from datetime import datetime, timezone
from pathlib import Path
from typing import Optional

import bronze_contract as bc

from .bronze_writer import BronzeWriter, recover_dir
from .checkpoint import Checkpoint
from .sources.base import SourceError


def _now() -> str:
    return datetime.now(timezone.utc).isoformat()


class AgentRunner:
    def __init__(self, source, writer: BronzeWriter, checkpoint: Checkpoint, health_path: Path,
                 *, batch_size: int = 100, mode: str = "file", stop_file: Optional[Path] = None):
        self.source, self.writer, self.cp = source, writer, checkpoint
        self.health_path = Path(health_path)
        self.batch_size, self.mode = batch_size, mode
        self.stop_file = Path(stop_file) if stop_file else None
        self.stop_requested = False
        self.errors = Counter()
        self.written = 0
        self.last_event_at = None

    def request_stop(self) -> None:
        self.stop_requested = True

    def _should_stop(self) -> bool:
        return self.stop_requested or bool(self.stop_file and self.stop_file.exists())

    def _health(self, state: str) -> None:
        h = {"state": state, "heartbeat": _now(), "last_event_at": self.last_event_at,
             "last_seal_at": _now() if self.writer.last_sealed else None,
             "events_written": self.written, "errors_by_code": dict(self.errors)}
        tmp = self.health_path.with_suffix(".tmp")
        tmp.parent.mkdir(parents=True, exist_ok=True)
        tmp.write_text(json.dumps(h), encoding="utf-8")
        os.replace(tmp, self.health_path)

    def _record_error(self, code: str, xml: Optional[str], msg: str) -> None:
        self.errors[code] += 1
        # giữ nguyên raw để không mất âm thầm (Zero Data Fabrication)
        err_dir = self.writer.dir / "errors"
        err_dir.mkdir(exist_ok=True)
        with (err_dir / "collector_errors.jsonl").open("a", encoding="utf-8", newline="\n") as f:
            f.write(json.dumps({"ts": _now(), "code": code, "message": msg, "raw_xml": xml},
                               ensure_ascii=False) + "\n")

    def run(self) -> None:
        for item in recover_dir(self.writer.dir):
            self.errors[item["reason"]] += 1
        bookmark, reason = self.cp.load()
        if reason:
            self.errors[reason] += 1
        self._health("running")
        pending_bm, in_batch, seq = None, 0, 0
        try:
            for item in self.source.iter_events(bookmark):
                if self._should_stop():
                    break
                try:
                    rec = bc.build_bronze_record(item.xml, mode=self.mode, seq=seq)
                    self.writer.append(rec)
                    self.written += 1
                    self.last_event_at = _now()
                except ValueError as exc:
                    self._record_error(str(exc).split(" ", 1)[0], item.xml, str(exc))
                seq += 1
                pending_bm, in_batch = item.bookmark, in_batch + 1
                if in_batch >= self.batch_size:
                    self._commit(pending_bm)
                    in_batch = 0
                    self._health("running")
        except SourceError as exc:
            self.errors[exc.code] += 1
        finally:
            if pending_bm is not None and in_batch:
                self._commit(pending_bm)
            self.writer.seal()
            self._health("stopped")

    def _commit(self, bookmark: str) -> None:
        self.writer.flush()      # bản ghi bền trước
        self.cp.save(bookmark)   # rồi mới tiến bookmark
