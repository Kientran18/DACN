"""Core: nạp Bronze -> Silver -> phát hiện -> alert (PH10). Một writer duy nhất vào DuckDB."""
from __future__ import annotations

import threading
from pathlib import Path
from typing import Dict, Optional

from alerts.builder import build_from_results
from alerts.store import AlertStore
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
        self.worker = IngestWorker(bronze_dir, store, metrics_path)
        self.alerts = AlertStore(store.con)
        self.stop = threading.Event()

    def cycle(self) -> dict:
        """Một vòng: nạp segment mới, chạy rule, dựng alert. Giữ khóa suốt vòng để API không đọc giữa chừng."""
        with self.lock:
            m = self.worker.run_once()
            eng = DetectionEngine(self.store.con, rules=self.rules, ioc=IocStore(self.ioc_path) if self.ioc_path else IocStore())
            results = eng.run()
            built = build_from_results(self.alerts, self.rules, results, self.store.con)
        return {**m, "alerts_created": len(built["alerts"]), "coverage_gaps": len(built["gaps"]), "suppressed": built["suppressed"]}

    def run_forever(self, interval_s: float = 2.0, stop_file: Optional[Path] = None) -> None:
        while not self.stop.is_set() and not (stop_file and Path(stop_file).exists()):
            self.cycle()
            self.stop.wait(interval_s)
