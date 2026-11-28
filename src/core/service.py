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


# Ngân sách nạp mỗi vòng (giây): hết ngân sách thì chạy Detection rồi nạp tiếp ở vòng sau. Giá trị chọn tay, chưa đo;
# lý do: trên Windows 10 VM (2026-11-28) một vòng nạp hết hàng đợi mất 1.962 s, alert mới chờ suốt thời gian đó.
DEFAULT_INGEST_BUDGET_S = 20.0


class CoreService:
    def __init__(self, store, bronze_dir: Path, metrics_path: Path, rules: Optional[Dict[str, dict]] = None,
                 ioc_path: Optional[Path] = None, lock: Optional[threading.RLock] = None, ml_runner=None,
                 ingest_budget_s: Optional[float] = DEFAULT_INGEST_BUDGET_S):
        self.store, self.lock = store, lock or threading.RLock()
        self.ingest_budget_s = ingest_budget_s
        self.rules = rules if rules is not None else load_rules()
        self.ioc_path = ioc_path
        self.worker = IngestWorker(bronze_dir, store, metrics_path, lock=self.lock)
        self.alerts = AlertStore(store.con)
        self.stop = threading.Event()
        self.log = get_logger("core")
        self.last_error = None          # {"at_utc", "type", "message"} của vòng lỗi gần nhất
        self.last_ok_utc = None
        self.last_ingest = None         # số liệu nạp của vòng gần nhất (segment, hàng đợi còn lại, thời gian)
        # Tín hiệu ML (tắt mặc định): chỉ góp vào điểm rủi ro, không tạo alert, không gọi response.
        self.ml_runner = ml_runner
        self.ml_last_error = None
        self.ml_last_run = None

    def status(self) -> dict:
        enabled = self.ml_runner.enabled() if self.ml_runner else {"ML_STATIC": False, "ML_BEHAVIOR": False}
        return {"last_error": self.last_error, "last_cycle_ok_utc": self.last_ok_utc, "last_ingest": self.last_ingest,
                "ml": {"enabled": enabled, "last_run": self.ml_last_run, "last_error": self.ml_last_error}}

    def cycle(self) -> dict:
        """Một vòng: nạp segment mới, chạy rule, dựng alert. Khóa chỉ giữ theo từng pha (ingest khóa theo từng
        segment) để API không bị chặn cả vòng; con trỏ phát hiện nằm trong DB nên pha nào lỡ dở sẽ chạy lại."""
        m = self.worker.run_once(max_seconds=self.ingest_budget_s)
        self.last_ingest = {k: m.get(k) for k in ("ts", "segments_ingested", "records_read", "elapsed_s", "pending_segments")}
        with self.lock:
            eng = DetectionEngine(self.store.con, rules=self.rules, ioc=IocStore(self.ioc_path) if self.ioc_path else IocStore())
            eng.run()
        with self.lock:
            # Outbox: alert commit và ack cùng transaction; restart không mất delivery.
            with self.alerts.tx():
                results = eng.pending_delivery()
                built = {"alerts": [], "gaps": [], "suppressed": 0, "skipped": 0}
                for result in results:
                    one = build_from_results(self.alerts, {result.rule_id: eng.delivery_rule(result)},
                                             [result], self.store.con)
                    for key in built:
                        built[key] += one[key]
                eng.acknowledge(results)
        out = {**m, "alerts_created": len(built["alerts"]), "coverage_gaps": len(built["gaps"]), "suppressed": built["suppressed"]}
        if self.ml_runner is not None:
            out["ml"] = self._run_ml()
        return out

    def _run_ml(self):
        """Sau khi alert đã commit: lỗi ML không ảnh hưởng phát hiện/alert, chỉ hiện ở /health."""
        try:
            with self.lock:
                res = self.ml_runner.run(self.store.con)
            self.ml_last_run = {"at_utc": datetime.now(timezone.utc).isoformat(), "result": res}
            return res
        except Exception as exc:     # noqa: BLE001
            self.ml_last_error = {"at_utc": datetime.now(timezone.utc).isoformat(), "type": type(exc).__name__}
            self.log.error("ml_failed", "CORE-002", error_type=type(exc).__name__)
            return f"ERROR: {type(exc).__name__}"

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
