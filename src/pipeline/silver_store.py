"""Silver store bền vững trên DuckDB (PH3-T02/T03). Một writer; nạp theo segment, idempotent.

Giữ nguyên SilverValidatorEngine và không sửa DDL v1.1; áp DDL v1.1 rồi DDL v1.2 (ĐỀ XUẤT, chưa duyệt:
lineage, alerts, response_actions...). Hostname: giữ hành vi hiện tại của validator (PH1-T04 chưa được quyết định).
"""
from __future__ import annotations

import hashlib
import json
import time
import uuid
from contextlib import nullcontext
from datetime import datetime, timezone
from pathlib import Path
from typing import Dict, List, Optional

import duckdb

import bronze_to_silver_adapter as adapter
import windows_channels as wc
from validator_poc import SilverValidatorEngine
from validator_windows_channels import WindowsChannelValidator

from .segment_reader import SegmentError, read_segment
from agent.bronze_writer import _sha256

DDL = Path(__file__).parent / "sql" / "silver_gold_schema_and_views_v1_1.sql"
DDL_V12 = Path(__file__).parent / "sql" / "silver_gold_schema_and_views_v1_2_proposal.sql"  # ĐỀ XUẤT, chưa duyệt
# ĐỀ XUẤT v1.3: Windows Defender + PowerShell 4104 (người dùng duyệt D3 thay cho Data/Cyber; chưa review độc lập)
DDL_V13 = Path(__file__).parent / "sql" / "silver_schema_v1_3_proposal_defender_powershell.sql"
MAPPER_VERSION = "bronze_to_silver_adapter+validator_poc/v1.1-poc"
TABLES = {"silver_process": "silver_process_events", "silver_file": "silver_file_events",
          "silver_registry": "silver_registry_events", "silver_network": "silver_network_events"}
WIN_TABLES = ("silver_defender_events", "silver_powershell_scriptblock_events")
# Nạp theo lô: một INSERT nhiều dòng cho mỗi (bảng, bộ cột) mỗi segment thay vì một lệnh mỗi dòng. Trên Windows 10 VM
# (2026-11-28) mỗi lệnh DuckDB tốn ~0,3 s nên nạp từng dòng chỉ đạt ~2-4 bản ghi/giây. Giới hạn số dòng mỗi lệnh để
# số tham số không quá lớn.
BATCH_ROWS = 200

LEDGER_DDL = """
CREATE TABLE IF NOT EXISTS _ingest_ledger (
    segment VARCHAR PRIMARY KEY, sha256 VARCHAR, status VARCHAR NOT NULL,
    records_read INTEGER, inserted INTEGER, duplicates INTEGER, quarantined INTEGER,
    run_id VARCHAR, ingested_at_utc TIMESTAMPTZ
)"""

# Cột hay lọc/tra cứu theo giá trị. `timestamp` không lập index: DuckDB đã có zonemap theo khối và dữ liệu vào gần như theo thời gian.
INDEXES = [f"CREATE INDEX IF NOT EXISTS ix_{t}_guid ON {t}(process_guid)" for t in TABLES.values()] + [
    "CREATE INDEX IF NOT EXISTS ix_lineage_hash ON silver_event_lineage(bronze_content_hash)",
    "CREATE INDEX IF NOT EXISTS ix_alerts_group ON alerts(group_key)"]


class SilverStore:
    def __init__(self, path):
        self.path = path
        Path(path).parent.mkdir(parents=True, exist_ok=True)
        self.con = duckdb.connect(str(path))
        self.con.execute(DDL.read_text(encoding="utf-8"))
        self.con.execute(DDL_V12.read_text(encoding="utf-8"))
        self.con.execute(DDL_V13.read_text(encoding="utf-8"))
        self.con.execute(LEDGER_DDL)
        for ix in INDEXES:
            self.con.execute(ix)
        self._cols = {t: [r[0] for r in self.con.execute(
            "select column_name from information_schema.columns where table_name=? order by ordinal_position",
            [t]).fetchall()] for t in list(TABLES.values()) + list(WIN_TABLES) + ["silver_quarantine_dlq"]}

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
        inserted = self.con.execute(
            f"insert into {table} ({','.join(cols)}) values ({','.join('?' * len(cols))}) "
            f"on conflict do nothing",
            [_param(v) for v in row.values()]).fetchone()[0]     # INSERT trả số hàng thật sự thêm (0 nếu trùng)
        return inserted

    def _insert_many(self, table: str, rows: List[dict]) -> None:
        """INSERT nhiều dòng (đã lọc trùng theo event_id trước). Giữ `on conflict do nothing` làm lưới an toàn."""
        groups: Dict[tuple, List[dict]] = {}
        for row in rows:
            unknown = set(row) - set(self._cols[table])
            if unknown:
                raise ValueError(f"cột không có trong DDL {table}: {sorted(unknown)}")
            groups.setdefault(tuple(row), []).append(row)
        for cols, grp in groups.items():
            ph = "(" + ",".join("?" * len(cols)) + ")"
            for i in range(0, len(grp), BATCH_ROWS):
                chunk = grp[i:i + BATCH_ROWS]
                self.con.execute(f"insert into {table} ({','.join(cols)}) values {','.join([ph] * len(chunk))} "
                                 "on conflict do nothing", [_param(r[c]) for r in chunk for c in cols])

    def _existing(self, table: str, ids: List[str], col: str = "event_id", value: str = "event_id") -> Dict[str, object]:
        """{id: value} của các id đã có trong bảng; một truy vấn cho cả lô."""
        if not ids:
            return {}
        return dict(self.con.execute(f"select {col}, {value} from {table} where list_contains(?, {col})",
                                     [list(set(ids))]).fetchall())

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
        except SegmentError:
            prev = self.con.execute("select status, sha256 from _ingest_ledger where segment=?", [seg.name]).fetchone()
            if prev and prev[0] == "QUARANTINED_SEGMENT" and prev[1] == sha:
                # vẫn hỏng như lần trước: không ghi/đếm lại; vòng sau vẫn thử (tự nạp khi tệp/manifest được sửa)
                return {**res, "status": "SKIPPED_STILL_QUARANTINED"}
            res["status"] = "QUARANTINED_SEGMENT"
            self._write_ledger(seg.name, sha, res["status"], res, run_id)
            return res

        self.con.execute("begin")
        try:
            # Pha 1 (Python thuần): adapter + validator từng bản ghi; DLQ ghi ngay (hiếm).
            staged = []      # (line_no, rec, flat, ref, [(table, row)])
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
                # Route theo kênh: Sysmon -> validator W05 (không đổi); Defender/PowerShell -> validator v1.3 riêng.
                if wc.is_sysmon(rec.get("channel")):
                    eng = SilverValidatorEngine()
                    ok = eng.process_record(flat, ref)
                    out_rows = [(t, row) for attr, t in TABLES.items() for row in getattr(eng, attr)] if ok else []
                else:
                    eng = WindowsChannelValidator()
                    ok = eng.process_record(flat, rec, ref)
                    out_rows = [(t, row) for t, rows in eng.rows.items() for row in rows] if ok else []
                if not ok:
                    for q in eng.quarantine_dlq:
                        self._dlq(q.error_code, q.error_stage, q.error_reason, ref, q.raw_payload)
                    res["quarantined"] += 1
                    continue
                staged.append((line_no, rec, flat, ref, out_rows))
            # Pha 2: tra trùng một lần cho mỗi bảng, rồi quyết định từng bản ghi THEO THỨ TỰ (giống nạp từng dòng:
            # bản đầu tiên của một event_id được ghi, bản sau là duplicate hoặc va chạm).
            ids_by_table: Dict[str, List[str]] = {}
            for _, _, _, _, out_rows in staged:
                for table, row in out_rows:
                    ids_by_table.setdefault(table, []).append(row["event_id"])
            taken = {t: set(self._existing(t, ids)) for t, ids in ids_by_table.items()}
            lineage_old = self._existing("silver_event_lineage", [r[1]["event_id"] for r in staged],
                                         value="bronze_content_hash")
            new_rows: Dict[str, List[dict]] = {}
            lineage_rows = []
            for line_no, rec, flat, ref, out_rows in staged:
                h = hashlib.sha256(rec["raw_xml"].encode("utf-8")).hexdigest()
                n = 0
                for table, row in out_rows:
                    if row["event_id"] not in taken[table]:
                        taken[table].add(row["event_id"])
                        new_rows.setdefault(table, []).append(row)
                        n += 1
                if n:
                    if rec["event_id"] not in lineage_old:          # như "on conflict do nothing" của lineage
                        lineage_old[rec["event_id"]] = h
                        lineage_rows.append([rec["event_id"], seg.name, line_no, h, MAPPER_VERSION, run_id])
                if not n and self._collision(rec, flat, ref, seg.name, run_id, old_hash=lineage_old.get(rec["event_id"]),
                                             new_hash=h):
                    res["quarantined"] += 1
                    continue
                res["inserted" if n else "duplicates"] += 1
            for table, rows in new_rows.items():
                self._insert_many(table, rows)
            for i in range(0, len(lineage_rows), BATCH_ROWS):
                chunk = lineage_rows[i:i + BATCH_ROWS]
                self.con.execute("insert into silver_event_lineage values " + ",".join(["(?,?,?,?,?,?)"] * len(chunk))
                                 + " on conflict do nothing", [v for r in chunk for v in r])
            self._write_ledger(seg.name, sha, "INGESTED", res, run_id)
            self.con.execute("commit")
        except BaseException:
            self.con.execute("rollback")
            raise
        return res

    def _collision(self, rec: dict, flat: dict, ref: str, seg_name: str, run_id: str, old_hash: Optional[str] = None,
                   new_hash: Optional[str] = None) -> bool:
        """Cùng event_id nhưng raw_xml khác bản đã nạp = va chạm định danh (ví dụ EventRecordID tái dùng sau khi xóa log),
        KHÔNG phải bản sao. Không đổi cách tính event_id: ghi DLQ + coverage gap để bằng chứng mới không mất âm thầm.
        Trả True nếu là va chạm MỚI. Phát lại cùng dữ liệu thì không tạo thêm dòng."""
        h = new_hash or hashlib.sha256(rec["raw_xml"].encode("utf-8")).hexdigest()
        # old_hash do pha tra trùng theo lô truyền vào (gồm cả bản ghi trước đó trong CÙNG segment); None = không có lineage
        if old_hash is None or old_hash == h:
            return False
        key = f"ingest-collision|{rec['event_id']}|{h}"
        new = self.con.execute(
            "insert into coverage_gaps values (?,?,?,?,?,?,?,?,?) on conflict do nothing",
            [str(uuid.uuid5(uuid.NAMESPACE_URL, key)), key, "INGEST-EVENT-ID", 0, flat.get("hostname"), [rec["event_id"]],
             json.dumps(["unique_event_id"]), "EVENT_ID_COLLISION", datetime.now(timezone.utc)]).fetchone()[0]
        if new:
            self._dlq("ERR_EVENT_ID_COLLISION", "INGEST_COLLISION",
                      "cùng event_id nhưng raw_xml khác bản đã nạp (nghi EventRecordID tái dùng sau khi xóa log)", ref, rec)
        return bool(new)

    def ingest_dir(self, directory: Path, run_id: str, lock=None, max_seconds: Optional[float] = None) -> List[Dict]:
        """lock (tùy chọn): giữ theo từng segment để tiến trình khác dùng chung kết nối xen vào được.
        Thứ tự: segment niêm phong SỚM NHẤT trước (mtime, rồi tên), không theo tên: tên Sysmon `seg-2026...` luôn đứng trước
        `seg-microsoft...` nên xếp theo tên làm kênh Defender/PowerShell chờ hết hàng đợi Sysmon.
        max_seconds (tùy chọn): không bắt đầu segment mới khi đã quá ngân sách (luôn nạp ít nhất một segment) để caller
        (core) chạy Detection xen kẽ khi hàng đợi dài; phần còn lại nạp ở lần gọi sau."""
        from .segment_reader import list_sealed
        out = []
        t0 = time.monotonic()
        # Segment đã niêm phong là bất biến: bỏ qua theo tên trong ledger, không băm lại cả lịch sử mỗi vòng.
        with lock or nullcontext():
            done = {r[0] for r in self.con.execute("select segment from _ingest_ledger where status='INGESTED'").fetchall()}
        todo = []
        for s in list_sealed(directory):
            if s.name in done:
                continue
            try:
                todo.append((s.stat().st_mtime, s.name, s))
            except OSError:
                continue          # bị xóa/đổi tên giữa chừng: lần sau
        for _, _, s in sorted(todo):
            if max_seconds is not None and out and time.monotonic() - t0 >= max_seconds:
                break
            with lock or nullcontext():
                out.append({"segment": s.name, **self.ingest_segment(s, run_id)})
        return out


def _param(v):
    return json.dumps(v, ensure_ascii=False, default=str) if isinstance(v, (dict, list)) else v

