"""Ingest worker (PH3-T07): nạp segment sealed mới, ghi metrics.jsonl."""
from __future__ import annotations

import json
import time
import uuid
from datetime import datetime, timezone
from contextlib import nullcontext
from pathlib import Path
from typing import Optional


class IngestWorker:
    def __init__(self, bronze_dir: Path, store, metrics_path: Path, on_batch=None, lock=None):
        self.dir, self.store, self.metrics_path = Path(bronze_dir), store, Path(metrics_path)
        self.on_batch = on_batch  # hook cho bước phát hiện sau mỗi batch (PH4)
        self.lock = lock
        self.stop = False

    def run_once(self, max_seconds: Optional[float] = None) -> dict:
        """max_seconds: ngân sách nạp của một lần gọi (xem SilverStore.ingest_dir); None = nạp hết hàng đợi."""
        t0 = time.monotonic()
        results = [r for r in self.store.ingest_dir(self.dir, "worker-" + uuid.uuid4().hex[:8], self.lock,
                                                    max_seconds=max_seconds)
                   if not r["status"].startswith("SKIPPED_")]
        m = {"ts": datetime.now(timezone.utc).isoformat(),
             "segments_ingested": sum(r["status"] == "INGESTED" for r in results),
             "segments_quarantined": sum(r["status"] == "QUARANTINED_SEGMENT" for r in results),
             "records_read": sum(r["read"] for r in results),
             "records_inserted": sum(r["inserted"] for r in results),
             "duplicates_ignored": sum(r["duplicates"] for r in results),
             "records_quarantined": sum(r["quarantined"] for r in results),
             "elapsed_s": round(time.monotonic() - t0, 4)}
        if max_seconds is not None:
            # Hàng đợi còn lại sau lần gọi (đếm theo ledger, không băm lại); quan sát backlog trên VM qua metrics.jsonl.
            m["pending_segments"] = self.pending()
        self.metrics_path.parent.mkdir(parents=True, exist_ok=True)
        with self.metrics_path.open("a", encoding="utf-8", newline="\n") as f:
            f.write(json.dumps(m) + "\n")
        if self.on_batch and m["segments_ingested"]:
            self.on_batch(results)
        return m

    def pending(self) -> int:
        from .segment_reader import list_sealed
        with self.lock or nullcontext():
            done = {r[0] for r in self.store.con.execute(
                "select segment from _ingest_ledger where status='INGESTED'").fetchall()}
        return sum(1 for s in list_sealed(self.dir) if s.name not in done)

    def run_forever(self, interval_s: float = 2.0) -> None:
        while not self.stop:
            self.run_once()
            time.sleep(interval_s)
