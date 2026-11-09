"""Detection Engine (PH4-T03/T07/T08/T10). Đọc Silver qua lớp truy vấn; lưu kết quả có khử trùng."""
from __future__ import annotations

import hashlib
import json
from datetime import datetime, timedelta, timezone
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
# Con trỏ đánh giá tăng dần: bền qua restart. sig đổi (rule/IOC đổi) -> quét lại toàn bộ một lần.
CURSOR_DDL = """
CREATE TABLE IF NOT EXISTS _detection_cursor (
    id INTEGER PRIMARY KEY, ingest_ts TIMESTAMPTZ, watermark TIMESTAMPTZ, sig VARCHAR
)"""
_TABLES = ("silver_process_events", "silver_file_events", "silver_registry_events", "silver_network_events")


class DetectionEngine:
    def __init__(self, con, rules: Optional[Dict[str, dict]] = None, ioc: Optional[IocStore] = None,
                 ml=None):
        self.con = con
        self.rules = rules if rules is not None else load_rules()
        self.ioc = ioc or IocStore()
        self.ml = ml or NullDetector()
        self.q = Query(con)
        con.execute(DDL)
        con.execute(CURSOR_DDL)

    # -- lưu trữ, khử trùng, replay-safe --------------------------------------
    def _save_all(self, results: List[DetectionResult]) -> List[DetectionResult]:
        """Lưu kết quả; trả các kết quả MỚI hoặc được cập nhật. NO_MATCH không lưu. Một truy vấn cho cả lô."""
        todo = [r for r in results if not (r.outcome == "NO_MATCH" and r.coverage_status != "PARTIAL_CHAIN")]
        keys = list({r.dedup_key for r in todo})
        have = dict(self.con.execute("select dedup_key, outcome from _detection_results where list_contains(?, dedup_key)",
                                     [keys]).fetchall()) if keys else {}
        now, emitted = datetime.now(timezone.utc), []
        for r in todo:
            old = have.get(r.dedup_key)
            payload = json.dumps(r.to_dict(), ensure_ascii=False, default=str)
            if old is None:
                self.con.execute("insert into _detection_results values (?,?,?,?,?,?,?,?,?)",
                                 [r.dedup_key, r.rule_id, r.rule_version, r.outcome, r.subject, r.severity,
                                  payload, now, now])
            elif old == "PENDING_LATE_EVENTS" and r.outcome != old:
                self.con.execute("update _detection_results set outcome=?, severity=?, result=?, updated_utc=? "
                                 "where dedup_key=?", [r.outcome, r.severity, payload, now, r.dedup_key])
            else:
                continue
            have[r.dedup_key] = r.outcome
            emitted.append(r)
        return emitted

    def _rows(self, table: str, ids: List[int], ingested_from=None, ts_from=None) -> List[dict]:
        ph = ",".join("?" * len(ids))
        sql, p = f"select * from {table} where sysmon_event_id in ({ph})", list(ids)
        if ingested_from is not None:
            sql += " and ingest_timestamp > ?"; p.append(ingested_from)
        if ts_from is not None:
            sql += " and timestamp >= ?"; p.append(ts_from)
        cur = self.con.execute(sql + " order by timestamp, event_id", p)
        cols = [c[0] for c in cur.description]
        return [dict(zip(cols, r)) for r in cur.fetchall()]

    def _max(self, col: str):
        ts = [v for v in (self.con.execute(f"select max({col}) from {t}").fetchone()[0] for t in _TABLES) if v is not None]
        return max(ts) if ts else None

    def _watermark(self):
        return self._max("timestamp")

    def _sig(self) -> str:
        """Dấu vân tay rule + IOC: đổi thì quét lại lịch sử một lần (retro-hunt)."""
        h = hashlib.sha256()
        for k in sorted(self.rules):
            h.update(f"{k}|{self.rules[k]['rule_version']}|{self.rules[k]['status']};".encode())
        for x in sorted(self.ioc.hashes) + ["|"] + sorted(self.ioc.allow):
            h.update(x.encode())
        return h.hexdigest()

    # -- chạy ------------------------------------------------------------------
    def run(self) -> List[DetectionResult]:
        """Đánh giá rule enabled trên sự kiện MỚI kể từ con trỏ (hoặc toàn bộ nếu lần đầu / rule / IOC đổi).
        Trả các kết quả mới hoặc được cập nhật.
        shortcut: con trỏ dùng ingest_timestamp (đồng hồ máy); đồng hồ lùi sẽ bỏ sót, nâng cấp bằng cột tuần tự."""
        sig, cur = self._sig(), self.con.execute("select ingest_ts, watermark, sig from _detection_cursor").fetchone()
        full = cur is None or cur[2] != sig or cur[0] is None     # DB rỗng ở lần trước: chưa có mốc
        since, prev_wm = (None, None) if full else (cur[0], cur[1])
        top = self._max("ingest_timestamp")
        if not full and (top is None or top <= since):
            return []                       # không có gì mới
        lo = None                           # timestamp sự kiện nhỏ nhất trong số mới
        if not full:
            lows = [self.con.execute(f"select min(timestamp) from {t} where ingest_timestamp > ?", [since]).fetchone()[0]
                    for t in _TABLES]
            lows = [v for v in lows if v is not None]
            lo = min(lows) if lows else None
        results: List[DetectionResult] = []
        for rule in self.rules.values():
            if rule["status"] != "enabled":
                continue
            if rule["type"] in ("single", "ioc"):
                for eid in rule["sysmon_event_ids"]:
                    for row in self._rows(_TABLE_FOR[eid], [eid], ingested_from=since):
                        res = evaluate_single(rule, row) if rule["type"] == "single" else self._ioc(rule, row)
                        if res:
                            results.append(res)
            elif rule["type"] == "correlation":
                # Chỉ nạp phần đuôi: cửa sổ của mọi create còn có thể đổi kết quả nằm sau mốc `from_ts`.
                from_ts = None if full else min(x for x in (prev_wm, lo) if x is not None) - timedelta(seconds=rule["time_window_seconds"])
                files = self._rows("silver_file_events", [11, 23, 26], ts_from=from_ts)
                procs = self._rows("silver_process_events", [1], ts_from=from_ts)
                results += evaluate_drop_execute_delete(rule, files, procs, self._watermark())
        emitted = self._save_all(results)
        self.con.execute("insert or replace into _detection_cursor values (1, ?, ?, ?)", [top, self._watermark(), sig])
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
