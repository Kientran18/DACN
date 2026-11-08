"""Silver store bền vững trên DuckDB (PH3-T02/T03). Một writer; nạp theo segment, idempotent.

Giữ nguyên SilverValidatorEngine và DDL v1.1. Hostname: giữ hành vi hiện tại của validator
(PH1-T04 chưa được quyết định).
"""
from __future__ import annotations

import hashlib
import json
import uuid
from datetime import datetime, timezone
from pathlib import Path
from typing import Dict, List

import duckdb

import bronze_to_silver_adapter as adapter
from validator_poc import SilverValidatorEngine

from .segment_reader import SegmentError, read_segment
from agent.bronze_writer import _sha256

DDL = Path(__file__).parent / "sql" / "silver_gold_schema_and_views_v1_1.sql"
DDL_V12 = Path(__file__).parent / "sql" / "silver_gold_schema_and_views_v1_2_proposal.sql"  # ĐỀ XUẤT, chưa duyệt
MAPPER_VERSION = "bronze_to_silver_adapter+validator_poc/v1.1-poc"
TABLES = {"silver_process": "silver_process_events", "silver_file": "silver_file_events",
          "silver_registry": "silver_registry_events", "silver_network": "silver_network_events"}

LEDGER_DDL = """
CREATE TABLE IF NOT EXISTS _ingest_ledger (
    segment VARCHAR PRIMARY KEY, sha256 VARCHAR, status VARCHAR NOT NULL,
    records_read INTEGER, inserted INTEGER, duplicates INTEGER, quarantined INTEGER,
    run_id VARCHAR, ingested_at_utc TIMESTAMPTZ
)"""


class SilverStore:
    def __init__(self, path):
        self.path = path
        Path(path).parent.mkdir(parents=True, exist_ok=True)
        self.con = duckdb.connect(str(path))
        self.con.execute(DDL.read_text(encoding="utf-8"))
        self.con.execute(DDL_V12.read_text(encoding="utf-8"))
        self.con.execute(LEDGER_DDL)
        self._cols = {t: [r[0] for r in self.con.execute(
            "select column_name from information_schema.columns where table_name=? order by ordinal_position",
            [t]).fetchall()] for t in list(TABLES.values()) + ["silver_quarantine_dlq"]}

    def close(self):
        self.con.close()

    # -- ledger ---------------------------------------------------------------
    def _write_ledger(self, seg: str, sha: str, status: str, res: Dict, run_id: str) -> None:
        self.con.execute(
            "insert or replace into _ingest_ledger values (?,?,?,?,?,?,?,?,?)",
            [seg, sha, status, res["read"], res["inserted"], res["duplicates"], res["quarantined"],
             run_id, datetime.now(timezone.utc)])

    def _already(self, seg: str, sha: str) -> bool:
        r = self.con.execute("select status, sha256 from _ingest_ledger where segment=?", [seg]).fetchone()
        return bool(r and r[0] == "INGESTED" and r[1] == sha)

    def _insert(self, table: str, row: dict) -> int:
        unknown = set(row) - set(self._cols[table])
        if unknown:
            raise ValueError(f"cột không có trong DDL {table}: {sorted(unknown)}")
        cols = list(row)
        before = self.con.execute(f"select count(*) from {table}").fetchone()[0]
        self.con.execute(
            f"insert into {table} ({','.join(cols)}) values ({','.join('?' * len(cols))}) "
            f"on conflict do nothing",
            [json.dumps(v, ensure_ascii=False, default=str) if isinstance(v, (dict, list)) else v
             for v in row.values()])
        return self.con.execute(f"select count(*) from {table}").fetchone()[0] - before

    def _dlq(self, code: str, stage: str, reason: str, ref: str, payload) -> None:
        self.con.execute(
            "insert into silver_quarantine_dlq (quarantine_id, quarantined_at_utc, error_code, error_stage,"
            " error_reason, source_reference, raw_payload) values (?,?,?,?,?,?,?)",
            [str(uuid.uuid4()), datetime.now(timezone.utc), code, stage, reason, ref,
             json.dumps(payload, ensure_ascii=False, default=str)])

    # -- ingest ---------------------------------------------------------------
    def ingest_segment(self, seg: Path, run_id: str) -> Dict:
        seg = Path(seg)
        res = {"read": 0, "inserted": 0, "duplicates": 0, "quarantined": 0, "status": "INGESTED"}
        try:
            sha = _sha256(seg)
        except OSError:
            sha = ""
        if self._already(seg.name, sha):
            return {**res, "status": "SKIPPED_ALREADY_INGESTED"}
        try:
            records = list(read_segment(seg))
        except SegmentError as exc:
            res["status"] = "QUARANTINED_SEGMENT"
            self._write_ledger(seg.name, sha, res["status"], res, run_id)
            self._last_error = str(exc)
            return res

        self.con.execute("begin")
        try:
            for line_no, rec in records:
                res["read"] += 1
                ref = f"{seg.name}#{line_no}"
                try:
                    flat = adapter.to_silver_input(rec)
                except ValueError as exc:
                    code = str(exc).split(":", 1)[0]
                    self._dlq(code, "BRONZE_ADAPTER", str(exc), ref, rec)
                    res["quarantined"] += 1
                    continue
                eng = SilverValidatorEngine()
                if not eng.process_record(flat, ref):
                    for q in eng.quarantine_dlq:
                        self._dlq(q.error_code, q.error_stage, q.error_reason, ref, q.raw_payload)
                    res["quarantined"] += 1
                    continue
                n = 0
                for attr, table in TABLES.items():
                    for row in getattr(eng, attr):
                        n += self._insert(table, row)
                if n:
                    self.con.execute(
                        "insert into silver_event_lineage values (?,?,?,?,?,?) on conflict do nothing",
                        [rec["event_id"], seg.name, line_no,
                         hashlib.sha256(rec["raw_xml"].encode("utf-8")).hexdigest(), MAPPER_VERSION, run_id])
                res["inserted" if n else "duplicates"] += 1
            self._write_ledger(seg.name, sha, "INGESTED", res, run_id)
            self.con.execute("commit")
        except BaseException:
            self.con.execute("rollback")
            raise
        return res

    def ingest_dir(self, directory: Path, run_id: str) -> List[Dict]:
        from .segment_reader import list_sealed
        return [{"segment": s.name, **self.ingest_segment(s, run_id)} for s in list_sealed(directory)]
