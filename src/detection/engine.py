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
from .scriptblock import GAP, assemble, evaluate_scriptblock
from .sigma.evaluate import defender_event, evaluate_event as evaluate_sigma, script_event, sysmon_event
from .schema import SILVER_TABLE_FOR_CHANNEL as _TABLE_FOR_CHANNEL
from .schema import SILVER_TABLE_FOR_EVENT as _TABLE_FOR


DDL = """
CREATE TABLE IF NOT EXISTS _detection_results (
    dedup_key VARCHAR PRIMARY KEY, rule_id VARCHAR, rule_version INTEGER, outcome VARCHAR,
    subject VARCHAR, severity VARCHAR, result JSON, first_seen_utc TIMESTAMPTZ, updated_utc TIMESTAMPTZ
)"""
# Con trỏ đánh giá tăng dần: bền qua restart. sig đổi (rule/IOC đổi) -> quét lại toàn bộ một lần.
CURSOR_DDL = """
CREATE TABLE IF NOT EXISTS _detection_cursor (
    id INTEGER PRIMARY KEY, ingest_ts TIMESTAMPTZ, watermark TIMESTAMPTZ, sig VARCHAR
);
CREATE TABLE IF NOT EXISTS _detection_outbox (dedup_key VARCHAR PRIMARY KEY, result JSON, rule JSON)
"""
_TABLES = ("silver_process_events", "silver_file_events", "silver_registry_events", "silver_network_events")
# Bảng v1.3 (đề xuất): chỉ dùng nếu tồn tại trong DB (SilverStore tạo; DB cũ/thiếu DDL v1.3 vẫn chạy như trước).
_CHANNEL_TABLES = tuple(_TABLE_FOR_CHANNEL.values())


class DetectionEngine:
    def __init__(self, con, rules: Optional[Dict[str, dict]] = None, ioc: Optional[IocStore] = None,
                 ml=None):
        self.con = con
        self.rules = rules if rules is not None else load_rules()
        self.ioc = ioc or IocStore()
        self.ml = ml or NullDetector()
        self.q = Query(con)
        have = {r[0] for r in con.execute("select table_name from information_schema.tables").fetchall()}
        self.tables = _TABLES + tuple(t for t in _CHANNEL_TABLES if t in have)
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
            elif (old == "PENDING_LATE_EVENTS" and r.outcome != old) or (
                    old in ("NO_MATCH", "INSUFFICIENT_TELEMETRY") and r.outcome == "MATCH"):
                self.con.execute("update _detection_results set outcome=?, severity=?, result=?, updated_utc=? "
                                 "where dedup_key=?", [r.outcome, r.severity, payload, now, r.dedup_key])
            else:
                continue
            have[r.dedup_key] = r.outcome
            self.con.execute("insert or replace into _detection_outbox values (?,?,?)",
                             [r.dedup_key, payload, json.dumps(self.rules[r.rule_id], ensure_ascii=False)])
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

    def _rows_channel(self, table: str, ids: List[int], ingested_from=None) -> List[dict]:
        """Như _rows cho bảng v1.3 (cột ID là windows_event_id)."""
        ph = ",".join("?" * len(ids))
        sql, p = f"select * from {table} where windows_event_id in ({ph})", list(ids)
        if ingested_from is not None:
            sql += " and ingest_timestamp > ?"; p.append(ingested_from)
        cur = self.con.execute(sql + " order by timestamp, event_id", p)
        cols = [c[0] for c in cur.description]
        return [dict(zip(cols, r)) for r in cur.fetchall()]

    def _max(self, col: str, tables=None):
        ts = [v for v in (self.con.execute(f"select max({col}) from {t}").fetchone()[0] for t in (tables or self.tables))
              if v is not None]
        return max(ts) if ts else None

    def _watermark(self):
        # Chỉ bảng Sysmon: watermark đóng cửa sổ correlation (DET-010 dùng Sysmon). Kênh khác đến theo segment riêng,
        # có thể sớm hơn Sysmon cùng khoảng thời gian -> không được đẩy watermark (tránh đóng cửa sổ sớm).
        return self._max("timestamp", _TABLES)

    def _host_watermarks(self):
        """Không dùng đồng hồ host khác để đóng correlation window."""
        rows = self.con.execute("select hostname,max(ts) from (" + " union all ".join(
            f"select hostname,max(timestamp) ts from {t} group by hostname" for t in _TABLES)
            + ") group by hostname").fetchall()
        return dict(rows)

    def _sig(self) -> str:
        """Dấu vân tay rule + IOC: đổi thì quét lại lịch sử một lần (retro-hunt)."""
        h = hashlib.sha256()
        for k in sorted(self.rules):
            h.update(json.dumps(self.rules[k], sort_keys=True, ensure_ascii=False).encode())
        for x in sorted(self.ioc.hashes) + ["|"] + sorted(self.ioc.allow):
            h.update(x.encode())
        return h.hexdigest()

    # -- chạy ------------------------------------------------------------------
    def run(self) -> List[DetectionResult]:
        """Evaluation, cursor và outbox cùng transaction; caller giữ khóa shared connection."""
        self.con.execute("begin")
        try:
            results = self._run()
            self.con.execute("commit")
            return results
        except BaseException:
            self.con.execute("rollback")
            raise

    def pending_delivery(self) -> List[DetectionResult]:
        return [DetectionResult(**json.loads(row[0])) for row in self.con.execute(
            "select result from _detection_outbox order by dedup_key").fetchall()]

    def acknowledge(self, results) -> None:
        """Gọi trong transaction chứa AlertBuilder; crash trước commit sẽ giữ outbox."""
        for r in results:
            self.con.execute("delete from _detection_outbox where dedup_key=?", [r.dedup_key])

    def delivery_rule(self, result):
        """Metadata đóng băng cùng evaluation, không dùng version mới sau restart."""
        row = self.con.execute("select rule from _detection_outbox where dedup_key=?", [result.dedup_key]).fetchone()
        if row is None:
            raise ValueError("delivery không tồn tại")
        return json.loads(row[0])

    def _run(self) -> List[DetectionResult]:
        """Đánh giá rule enabled trên sự kiện MỚI kể từ con trỏ (hoặc toàn bộ nếu lần đầu / rule / IOC đổi).
        Trả các kết quả mới hoặc được cập nhật.
        shortcut: con trỏ dùng ingest_timestamp (đồng hồ máy); đồng hồ lùi sẽ bỏ sót, nâng cấp bằng cột tuần tự."""
        sig, cur = self._sig(), self.con.execute("select ingest_ts, watermark, sig from _detection_cursor").fetchone()
        full = cur is None or cur[2] != sig or cur[0] is None     # DB rỗng ở lần trước: chưa có mốc
        since, prev_wm = (None, None) if full else (cur[0], cur[1])
        top = self._max("ingest_timestamp")
        if not full and (top is None or top <= since):
            return []                       # không có gì mới
        lo = None                           # timestamp sự kiện Sysmon nhỏ nhất trong số mới (chỉ dùng cho correlation)
        if not full:
            lows = [self.con.execute(f"select min(timestamp) from {t} where ingest_timestamp > ?", [since]).fetchone()[0]
                    for t in _TABLES]
            lows = [v for v in lows if v is not None]
            lo = min(lows) if lows else None
        results: List[DetectionResult] = []
        for rule in self.rules.values():
            if rule["status"] != "enabled":
                continue
            if rule["type"] == "single" and rule.get("source_events"):
                for se in rule["source_events"]:
                    table = _TABLE_FOR_CHANNEL[se["channel"]]
                    if table not in self.tables:
                        continue        # DB chưa có DDL v1.3: không có dữ liệu để đánh giá
                    for row in self._rows_channel(table, se["event_ids"], ingested_from=since):
                        results.append(evaluate_single(rule, row))
            elif rule["type"] == "scriptblock":
                table = _TABLE_FOR_CHANNEL[rule["source_events"][0]["channel"]]
                if table in self.tables:
                    results += self._scriptblocks(rule, table, since)
            elif rule["type"] == "sigma":
                results += self._sigma(rule, since)
            elif rule["type"] in ("single", "ioc"):
                for eid in rule["sysmon_event_ids"]:
                    for row in self._rows(_TABLE_FOR[eid], [eid], ingested_from=since):
                        res = evaluate_single(rule, row) if rule["type"] == "single" else self._ioc(rule, row)
                        if res:
                            results.append(res)
            elif rule["type"] == "correlation":
                # Chỉ nạp phần đuôi: cửa sổ của mọi create còn có thể đổi kết quả nằm sau mốc `from_ts`.
                # Không có mốc Sysmon nào (lượt trước chưa có Sysmon và không có Sysmon mới, chỉ có kênh v1.3) nghĩa là bảng
                # Sysmon rỗng: from_ts = None (nạp toàn bộ = không có gì), tránh min() trên tập rỗng.
                marks = [x for x in (prev_wm, lo) if x is not None]
                from_ts = None if full or not marks else min(marks) - timedelta(
                    seconds=rule["time_window_seconds"] + rule.get("allowed_lateness_seconds", 0))
                if from_ts is not None:
                    pending_at = self.con.execute("select min(f.timestamp) from silver_file_events f "
                        "join _detection_results d on f.event_id=d.subject "
                        "where d.rule_id=? and d.outcome='PENDING_LATE_EVENTS'", [rule["rule_id"]]).fetchone()[0]
                    if pending_at is not None:
                        from_ts = min(from_ts, pending_at)
                files = self._rows("silver_file_events", [11, 23, 26], ts_from=from_ts)
                procs = self._rows("silver_process_events", [1], ts_from=from_ts)
                results += evaluate_drop_execute_delete(rule, files, procs, self._host_watermarks())
        emitted = self._save_all(results)
        self.con.execute("insert or replace into _detection_cursor values (1, ?, ?, ?)", [top, self._watermark(), sig])
        return emitted

    def _script_groups(self, table: str, since) -> Dict[tuple, List[dict]]:
        """MỌI phần của các script block có phần mới kể từ con trỏ (phần đến muộn làm block đầy đủ hơn).
        Cùng message_number xuất hiện nhiều lần (chạy lại cùng ScriptBlockId, chưa xác minh) -> giữ dòng record_id nhỏ nhất."""
        cond, p = ("and ingest_timestamp > ?", [since]) if since is not None else ("", [])
        cur = self.con.execute(
            f"select x.* from {table} x join (select distinct hostname, script_block_id, message_total from {table} "
            f"where windows_event_id = 4104 {cond}) g using (hostname, script_block_id, message_total) "
            "where x.windows_event_id = 4104 order by x.hostname, x.script_block_id, x.message_total, x.message_number, x.record_id", p)
        cols = [c[0] for c in cur.description]
        groups: Dict[tuple, List[dict]] = {}
        for r in cur.fetchall():
            row = dict(zip(cols, r))
            parts = groups.setdefault((row["hostname"], row["script_block_id"], row["message_total"]), [])
            if not parts or parts[-1]["message_number"] != row["message_number"]:
                parts.append(row)
        return groups

    def _scriptblocks(self, rule: dict, table: str, since) -> List[DetectionResult]:
        out = []
        for (host, sbid, total), parts in self._script_groups(table, since).items():
            res = evaluate_scriptblock(rule, host, sbid, total, parts)
            if res:
                out.append(res)
        return out

    def _sigma(self, rule: dict, since) -> List[DetectionResult]:
        """Rule Sigma (detection.sigma): bảng/Event ID đã phân giải khi nạp (sigma.dacn_logsource)."""
        spec = rule["sigma"]["dacn_logsource"]
        out: List[DetectionResult] = []
        if spec["table"] not in self.tables:
            return out                      # DB chưa có DDL v1.3: không có dữ liệu để đánh giá
        if spec["kind"] == "sysmon":
            for eid in spec["event_ids"]:
                for row in self._rows(spec["table"], [eid], ingested_from=since):
                    out.append(evaluate_sigma(rule, sysmon_event(rule, row), row["event_id"], [row["event_id"]]))
        elif spec["kind"] == "defender":
            for row in self._rows_channel(spec["table"], spec["event_ids"], ingested_from=since):
                out.append(evaluate_sigma(rule, defender_event(row), row["event_id"], [row["event_id"]]))
        else:   # scriptblock: văn bản đã ghép như DACN-DET-203; không chép văn bản vào kết quả
            for (host, sbid, total), parts in self._script_groups(spec["table"], since).items():
                text, nums, ids = assemble(parts)
                missing = [f"MessageNumber:{n}" for n in range(1, total + 1) if n not in set(nums)]
                clean = text.replace(GAP, "")
                extra = {"script_block_id": sbid, "message_total": total, "parts_seen": len(nums),
                         "script_sha256": hashlib.sha256(clean.encode("utf-8")).hexdigest(), "script_length": len(clean)}
                res = evaluate_sigma(rule, script_event(text, parts, total), f"{host}|{sbid}|{total}", ids,
                                     extra=extra, missing_parts=missing)
                if res.outcome == "MATCH" or not missing:
                    out.append(res)         # block thiếu phần mà chưa khớp: chưa kết luận (như DET-203)
        return out

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
