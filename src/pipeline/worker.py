"""Ingest worker (PH3-T07): nạp segment sealed mới, ghi metrics.jsonl."""
from __future__ import annotations

import json
import time
import uuid
from datetime import datetime, timezone
from pathlib import Path


class IngestWorker:
    def __init__(self, bronze_dir: Path, store, metrics_path: Path, on_batch=None, lock=None):
        self.dir, self.store, self.metrics_path = Path(bronze_dir), store, Path(metrics_path)
        self.on_batch = on_batch  # hook cho bước phát hiện sau mỗi batch (PH4)
        self.lock = lock
        self.stop = False

    def run_once(self) -> dict:
        t0 = time.monotonic()
        results = [r for r in self.store.ingest_dir(self.dir, "worker-" + uuid.uuid4().hex[:8], self.lock)
                   if r["status"] != "SKIPPED_ALREADY_INGESTED"]
        m = {"ts": datetime.now(timezone.utc).isoformat(),
             "segments_ingested": sum(r["status"] == "INGESTED" for r in results),
             "segments_quarantined": sum(r["status"] == "QUARANTINED_SEGMENT" for r in results),
             "records_read": sum(r["read"] for r in results),
             "records_inserted": sum(r["inserted"] for r in results),
             "duplicates_ignored": sum(r["duplicates"] for r in results),
             "records_quarantined": sum(r["quarantined"] for r in results),
             "elapsed_s": round(time.monotonic() - t0, 4)}
        self.metrics_path.parent.mkdir(parents=True, exist_ok=True)
        with self.metrics_path.open("a", encoding="utf-8", newline="\n") as f:
            f.write(json.dumps(m) + "\n")
        if self.on_batch and m["segments_ingested"]:
            self.on_batch(results)
        return m

    def run_forever(self, interval_s: float = 2.0) -> None:
        while not self.stop:
            self.run_once()
            time.sleep(interval_s)
