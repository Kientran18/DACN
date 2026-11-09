"""Core: nạp Bronze -> Silver -> phát hiện -> alert (PH10). Một writer duy nhất vào DuckDB."""
from __future__ import annotations

import threading
from datetime import datetime, timezone
from pathlib import Path
from typing import Dict, Optional

from alerts.builder import build_from_results
from alerts.store import AlertStore
from common.log import get_logger
from detection.engine import DetectionEngine
from detection.ioc import IocStore
from detection.loader import load_rules
from pipeline.worker import IngestWorker


class CoreService:
    def __init__(self, store, bronze_dir: Path, metrics_path: Path, rules: Optional[Dict[str, dict]] = None,
                 ioc_path: Optional[Path] = None, lock: Optional[threading.RLock] = None):
        self.store, self.lock = store, lock or threading.RLock()
        self.rules = rules if rules is not None else load_rules()
        self.ioc_path = ioc_path
        self.worker = IngestWorker(bronze_dir, store, metrics_path, lock=self.lock)
        self.alerts = AlertStore(store.con)
        self.stop = threading.Event()
        self.log = get_logger("core")
        self.last_error = None          # {"at_utc", "type", "message"} của vòng lỗi gần nhất
        self.last_ok_utc = None

    def status(self) -> dict:
        return {"last_error": self.last_error, "last_cycle_ok_utc": self.last_ok_utc}

    def cycle(self) -> dict:
        """Một vòng: nạp segment mới, chạy rule, dựng alert. Khóa chỉ giữ theo từng pha (ingest khóa theo từng
        segment) để API không bị chặn cả vòng; con trỏ phát hiện nằm trong DB nên pha nào lỡ dở sẽ chạy lại."""
        m = self.worker.run_once()
        with self.lock:
            eng = DetectionEngine(self.store.con, rules=self.rules, ioc=IocStore(self.ioc_path) if self.ioc_path else IocStore())
            results = eng.run()
        with self.lock:
            built = build_from_results(self.alerts, self.rules, results, self.store.con)
        return {**m, "alerts_created": len(built["alerts"]), "coverage_gaps": len(built["gaps"]), "suppressed": built["suppressed"]}

    def run_forever(self, interval_s: float = 2.0, stop_file: Optional[Path] = None) -> None:
        while not self.stop.is_set() and not (stop_file and Path(stop_file).exists()):
            try:
                self.cycle()
                self.last_ok_utc = datetime.now(timezone.utc).isoformat()
            except Exception as exc:     # một vòng lỗi không được làm chết cả phát hiện; lỗi hiện ở /health
                self.last_error = {"at_utc": datetime.now(timezone.utc).isoformat(), "type": type(exc).__name__,
                                   "message": str(exc)[:300]}
                self.log.error("cycle_failed", "CORE-001", error_type=type(exc).__name__)
            self.stop.wait(interval_s)
