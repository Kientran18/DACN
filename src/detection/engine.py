"""Detection Engine (PH4-T03/T07/T08/T10). Đọc Silver qua lớp truy vấn; lưu kết quả có khử trùng."""
from __future__ import annotations

import json
from datetime import datetime, timezone
from typing import Dict, List, Optional

from pipeline.query import Query

from .correlator import evaluate_drop_execute_delete
from .evaluator import evaluate_single
from .ioc import IocStore
from .loader import load_rules
from .ml.interface import NullDetector
from .result import DetectionResult, make_dedup_key

_TABLE_FOR = {1: "silver_process_events", 11: "silver_file_events", 29: "silver_file_events",
              13: "silver_registry_events", 12: "silver_registry_events", 14: "silver_registry_events",
              3: "silver_network_events", 22: "silver_network_events"}

DDL = """
CREATE TABLE IF NOT EXISTS _detection_results (
    dedup_key VARCHAR PRIMARY KEY, rule_id VARCHAR, rule_version INTEGER, outcome VARCHAR,
    subject VARCHAR, severity VARCHAR, result JSON, first_seen_utc TIMESTAMPTZ, updated_utc TIMESTAMPTZ
)"""


class DetectionEngine:
    def __init__(self, con, rules: Optional[Dict[str, dict]] = None, ioc: Optional[IocStore] = None,
                 ml=None):
        self.con = con
        self.rules = rules if rules is not None else load_rules()
        self.ioc = ioc or IocStore()
        self.ml = ml or NullDetector()
        self.q = Query(con)
        con.execute(DDL)

    # -- lưu trữ, khử trùng, replay-safe --------------------------------------
    def _save(self, r: DetectionResult) -> str:
        """'new' | 'updated' | 'unchanged'. NO_MATCH không lưu."""
        if r.outcome == "NO_MATCH" and r.coverage_status != "PARTIAL_CHAIN":
            return "unchanged"
        row = self.con.execute("select outcome from _detection_results where dedup_key=?", [r.dedup_key]).fetchone()
        now = datetime.now(timezone.utc)
        payload = json.dumps(r.to_dict(), ensure_ascii=False, default=str)
        if row is None:
            self.con.execute("insert into _detection_results values (?,?,?,?,?,?,?,?,?)",
                             [r.dedup_key, r.rule_id, r.rule_version, r.outcome, r.subject, r.severity,
                              payload, now, now])
            return "new"
        if row[0] == "PENDING_LATE_EVENTS" and r.outcome != row[0]:
            self.con.execute("update _detection_results set outcome=?, severity=?, result=?, updated_utc=? "
                             "where dedup_key=?", [r.outcome, r.severity, payload, now, r.dedup_key])
            return "updated"
        return "unchanged"

    def _rows(self, table: str, ids: List[int]) -> List[dict]:
        ph = ",".join("?" * len(ids))
        cur = self.con.execute(f"select * from {table} where sysmon_event_id in ({ph}) order by timestamp, event_id", ids)
        cols = [c[0] for c in cur.description]
        return [dict(zip(cols, r)) for r in cur.fetchall()]

    def _watermark(self):
        ts = []
        for t in ("silver_process_events", "silver_file_events", "silver_registry_events", "silver_network_events"):
            v = self.con.execute(f"select max(timestamp) from {t}").fetchone()[0]
            if v is not None:
                ts.append(v)
        return max(ts) if ts else None

    # -- chạy ------------------------------------------------------------------
    def run(self) -> List[DetectionResult]:
        """Đánh giá mọi rule enabled; trả các kết quả MỚI hoặc được cập nhật."""
        emitted: List[DetectionResult] = []
        for rule in self.rules.values():
            if rule["status"] != "enabled":
                continue
            if rule["type"] == "single":
                for eid in rule["sysmon_event_ids"]:
                    for row in self._rows(_TABLE_FOR[eid], [eid]):
                        res = evaluate_single(rule, row)
                        if self._save(res) != "unchanged":
                            emitted.append(res)
            elif rule["type"] == "ioc":
                for eid in rule["sysmon_event_ids"]:
                    for row in self._rows(_TABLE_FOR[eid], [eid]):
                        res = self._ioc(rule, row)
                        if res and self._save(res) != "unchanged":
                            emitted.append(res)
            elif rule["type"] == "correlation":
                files = self._rows("silver_file_events", [11, 23, 26])
                procs = self._rows("silver_process_events", [1])
                for res in evaluate_drop_execute_delete(rule, files, procs, self._watermark()):
                    if self._save(res) != "unchanged":
                        emitted.append(res)
        return emitted

    def _ioc(self, rule: dict, row: dict) -> Optional[DetectionResult]:
        sha = row.get("file_sha256")
        if not sha:
            return None   # không có hash thì không có gì để so; không coi là INSUFFICIENT cho mọi hàng
        status, info = self.ioc.check(sha)
        if status != "IOC_MATCH":
            return None   # allowlist hoặc không khớp: không gắn cờ
        rid, ver = rule["rule_id"], rule["rule_version"]
        return DetectionResult(rule_id=rid, rule_version=ver, outcome="MATCH", subject=row["event_id"],
                               contributing_event_ids=[row["event_id"]],
                               matched_fields={"file_sha256": sha, "ioc_source": info["source"]},
                               severity=rule["severity"],
                               severity_reason="hash khớp IOC cục bộ; khớp hash không đủ chứng minh độc hại",
                               dedup_key=make_dedup_key(rid, ver, row["event_id"]))
