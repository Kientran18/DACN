"""W07 -> DetectionResult/Alert/Candidate; không gọi Response Executor, không sửa telemetry."""
from __future__ import annotations

import hashlib
import json
import os
import threading
from pathlib import Path

from alerts.builder import build_from_results
from alerts.store import AlertStore
from detection.result import DetectionResult, make_dedup_key
from .extractor import StaticExtractor
from .knowledge import KnowledgeStore
from .review import CandidateStore

TABLES = ("silver_process_events", "silver_file_events", "silver_registry_events", "silver_network_events")
STATIC_RULE = {"rule_id": "DACN-STATIC-001", "rule_version": 1, "name": "Local static IOC/pattern candidate",
               "type": "ioc", "response_policy": "alert_only"}


class StaticWorkflow:
    def __init__(self, con, roots, knowledge_root, *, lock=None, extractor=None):
        self.con, self.lock = con, lock or threading.RLock()
        self.extractor = extractor or StaticExtractor(roots)
        self.knowledge = KnowledgeStore(knowledge_root)
        self.candidates = CandidateStore(con)
        self.alerts = AlertStore(con)

    def _sources(self, event_ids, path):
        """Không nhận ID giả hoặc liên kết file khác. Khóa do caller giữ."""
        hashes, hosts = set(), set()
        if len(event_ids) > 100 or len(set(event_ids)) != len(event_ids):
            raise ValueError("source_event_ids sai hoặc quá nhiều")
        for eid in event_ids:
            row = None
            for table in TABLES:
                cur = self.con.execute(f"select * from {table} where event_id=?", [eid])
                cols, values = [c[0] for c in cur.description], cur.fetchone()
                if values:
                    row = dict(zip(cols, values)); break
            if row is None:
                raise KeyError(eid)
            hosts.add(row["hostname"])
            target = row.get("file_path") if table == "silver_file_events" else row.get("image_path")
            if not target or os.path.normcase(os.path.abspath(target)) != os.path.normcase(os.path.abspath(path)):
                raise ValueError("SOURCE_PATH_MISMATCH")
            if row.get("file_sha256"):
                hashes.add(row["file_sha256"].lower())
        if len(hashes) > 1:
            raise ValueError("SOURCE_HASH_CONFLICT")
        if len(hosts) > 1:
            raise ValueError("SOURCE_HOST_CONFLICT")
        return next(iter(hashes), None)

    def analyze(self, path, *, source_event_ids=(), actor):
        with self.lock:
            expected = self._sources(source_event_ids, path)
            snapshot = self.knowledge.snapshot()
        # I/O bytes ngoài khóa DuckDB; đúng một snapshot kiến thức cho toàn analysis.
        analysis = self.extractor.extract(path, source_event_ids=source_event_ids,
                                          patterns=snapshot[1]["patterns"], expected_sha256=expected)
        verdict = self.knowledge.match(analysis, snapshot)
        subject = hashlib.sha256(json.dumps([str(Path(path)), analysis["sha256"], analysis["file_identity"],
                                             sorted(source_event_ids), snapshot[0], analysis["error_code"]],
                                            sort_keys=True).encode()).hexdigest()
        outcome = "MATCH" if verdict["verdict"] == "HIT" else (
            "INSUFFICIENT_TELEMETRY" if verdict["verdict"] == "UNAVAILABLE" else "NO_MATCH")
        detection = DetectionResult(rule_id=STATIC_RULE["rule_id"], rule_version=1, outcome=outcome,
                                    subject=subject, contributing_event_ids=list(source_event_ids),
                                    matched_fields={"analysis_id": analysis["analysis_id"], "sha256": analysis["sha256"],
                                                    "knowledge_revision": snapshot[0], "signature_hit": verdict["signature_hit"]},
                                    missing_fields=["file_bytes"] if outcome == "INSUFFICIENT_TELEMETRY" else [],
                                    coverage_status="FILE_UNAVAILABLE" if outcome == "INSUFFICIENT_TELEMETRY" else (
                                        "CURRENT_BYTES_ONLY" if not expected else "HASH_VERIFIED"),
                                    severity="medium" if outcome == "MATCH" else None,
                                    severity_reason="Chỉ báo static là candidate, không chứng minh malware; alert-only",
                                    dedup_key=make_dedup_key(STATIC_RULE["rule_id"], 1, subject),
                                    notes=["no_auto_response", "behavioral_results_unchanged"])
        with self.lock:
            # Alert và candidate/audit cùng transaction; lỗi giữa chừng rollback toàn bộ.
            with self.candidates.audit.tx():
                # Dùng cùng AlertStore cho transaction lồng nhau.
                built = build_from_results(self.candidates.audit, {STATIC_RULE["rule_id"]: STATIC_RULE},
                                           [detection], self.con) if source_event_ids else {"alerts": []}
                candidate = self.candidates.create(analysis, verdict, detection.to_dict(), built["alerts"], actor=actor)
        return candidate
