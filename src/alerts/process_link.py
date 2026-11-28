"""Nối sự kiện Defender/PowerShell với tiến trình Sysmon (hạng mục 4, docs/architecture/w8 mục 4.6). SUY LUẬN, tính khi truy vấn.

- Không ghi DB, không gán process_guid vào alert hay Silver (alert giữ NULL như dữ liệu quan sát được).
- Kết quả liệt kê MỌI ứng viên, kèm nhãn: UNIQUE (một tiến trình), AMBIGUOUS (nhiều, không chọn đại), NONE (không có),
  NOT_APPLICABLE (thiếu dữ liệu để nối, ví dụ Process Name 'Unknown').
- "Còn sống tại thời điểm t": có Sysmon Event 1 trước t (trong cửa sổ nhìn lại) và không có Event 5 của cùng process_guid
  trước t. Thiếu Event 5 (agent không chạy lúc tiến trình kết thúc) làm tiến trình trông như còn sống -> có thể thừa ứng viên.
- 4104: PID của tiến trình ghi sự kiện (System/Execution@ProcessID, CHƯA đối chiếu trên VM là powershell.exe) + host + ảnh
  PowerShell + vòng đời. Khác nguyên tắc W06 "không PID-only" ở chỗ PID là khóa chính; vì vậy luôn là suy luận có nhãn.
- Cửa sổ nhìn lại mặc định 24 giờ: HEURISTIC chưa hiệu chỉnh.
"""
from __future__ import annotations

from datetime import datetime, timedelta, timezone
from typing import Dict, List, Optional

DEFAULT_LOOKBACK = timedelta(hours=24)
POWERSHELL_IMAGES = ("\\powershell.exe", "\\pwsh.exe", "\\powershell_ise.exe")
MAX_CANDIDATES = 20


def _confidence(cands: List[dict]) -> str:
    n = len({c["process_guid"] for c in cands})
    return "NONE" if n == 0 else ("UNIQUE" if n == 1 else "AMBIGUOUS")


def _parse_time(v) -> Optional[datetime]:
    if isinstance(v, datetime):
        return v
    try:
        t = datetime.fromisoformat(str(v).replace("Z", "+00:00"))
    except (TypeError, ValueError):
        return None
    return t if t.tzinfo else None            # không đoán múi giờ


def _alive(con, hostname: str, at: datetime, lookback: timedelta, extra_sql: str, params: list) -> List[dict]:
    """Tiến trình có Event 1 trong [at - lookback, at] và chưa có Event 5 trước `at`."""
    rows = con.execute(
        "select s.process_guid, s.pid, s.image_path, s.command_line, s.timestamp, s.event_id from silver_process_events s "
        "where s.hostname = ? and s.sysmon_event_id = 1 and s.timestamp <= ? and s.timestamp >= ? " + extra_sql +
        " and not exists (select 1 from silver_process_events e where e.hostname = s.hostname and e.sysmon_event_id = 5 "
        "and e.process_guid = s.process_guid and e.timestamp >= s.timestamp and e.timestamp < ?) "
        "order by s.timestamp desc limit ?", [hostname, at, at - lookback, *params, at, MAX_CANDIDATES]).fetchall()
    return [{"process_guid": g, "pid": pid, "image_path": img, "command_line": cmd, "start_utc": ts, "event_id": eid}
            for g, pid, img, cmd, ts, eid in rows]


def link_powershell(con, row: dict, lookback: timedelta = DEFAULT_LOOKBACK) -> dict:
    pid, at = row.get("writer_process_id"), _parse_time(row.get("timestamp"))
    base = {"method": "PID_IMAGE_LIFETIME", "basis": "writer_process_id + hostname + ảnh PowerShell + còn sống tại thời điểm 4104"}
    if pid is None or at is None:
        return {**base, "confidence": "NOT_APPLICABLE", "candidates": [], "note": "thiếu PID hoặc thời điểm"}
    cond = " and s.pid = ? and (" + " or ".join("lower(s.image_path) like ?" for _ in POWERSHELL_IMAGES) + ")"
    cands = _alive(con, row["hostname"], at, lookback, cond, [pid, *("%" + i for i in POWERSHELL_IMAGES)])
    return {**base, "confidence": _confidence(cands), "candidates": cands,
            "note": "PID có thể bị tái sử dụng; ứng viên là suy luận, không phải bằng chứng"}


def link_defender(con, row: dict, lookback: timedelta = DEFAULT_LOOKBACK) -> List[dict]:
    """Trả tối đa hai kết quả: theo Process Name và theo tệp bị phát hiện (Event 11)."""
    at = _parse_time(row.get("detection_time")) or _parse_time(row.get("timestamp"))
    out = []
    name = (row.get("process_name") or "").strip()
    by_name = {"method": "PROCESS_NAME_LIFETIME", "basis": "Process Name của Defender = image_path, còn sống tại Detection Time"}
    if not name or name.lower() == "unknown" or at is None:
        out.append({**by_name, "confidence": "NOT_APPLICABLE", "candidates": [],
                    "note": "Defender ghi Process Name 'Unknown' hoặc thiếu thời điểm" if at else "thiếu thời điểm"})
    else:
        cands = _alive(con, row["hostname"], at, lookback, " and lower(s.image_path) = lower(?)", [name])
        out.append({**by_name, "confidence": _confidence(cands), "candidates": cands,
                    "note": "nhiều tiến trình cùng ảnh -> AMBIGUOUS; không có PID để phân biệt"})
    if row.get("resource_type") == "file" and row.get("resource_value") and at is not None:
        rows = con.execute(
            "select f.process_guid, f.pid, f.image_path, f.timestamp, f.event_id from silver_file_events f "
            "where f.hostname = ? and f.sysmon_event_id = 11 and lower(f.file_path) = lower(?) and f.timestamp <= ? "
            "and f.timestamp >= ? order by f.timestamp desc limit ?",
            [row["hostname"], row["resource_value"], at, at - lookback, MAX_CANDIDATES]).fetchall()
        cands = [{"process_guid": g, "pid": pid, "image_path": img, "command_line": None, "start_utc": None,
                  "file_event_utc": ts, "event_id": eid} for g, pid, img, ts, eid in rows]
        out.append({"method": "FILE_CREATE", "basis": "Path của Defender = file_path của Sysmon Event 11 trước Detection Time",
                    "confidence": _confidence(cands), "candidates": cands,
                    "note": "chỉ có khi cấu hình Sysmon ghi Event 11 cho đường dẫn này"})
    return out


def links_for_event(con, table: str, row: dict, lookback: timedelta = DEFAULT_LOOKBACK) -> List[dict]:
    if table == "silver_powershell_scriptblock_events" or "script_block_id" in row:
        return [link_powershell(con, row, lookback)]
    if table == "silver_defender_events" or "threat_name" in row:
        return link_defender(con, row, lookback)
    return []


def links_for_alert(con, contributing_event_ids: List[str], lookback: timedelta = DEFAULT_LOOKBACK) -> Dict:
    """Kết quả nối cho từng sự kiện Defender/PowerShell của alert. Sự kiện Sysmon (đã có process_guid) bị bỏ qua."""
    have = {r[0] for r in con.execute("select table_name from information_schema.tables").fetchall()}
    events = []
    for table in ("silver_defender_events", "silver_powershell_scriptblock_events"):
        if table not in have or not contributing_event_ids:
            continue
        cur = con.execute(f"select * from {table} where list_contains(?, event_id) order by timestamp, event_id",
                          [list(contributing_event_ids)])
        cols = [c[0] for c in cur.description]
        seen_blocks = set()
        for r in cur.fetchall():
            row = dict(zip(cols, r))
            if table.startswith("silver_powershell"):
                key = (row["script_block_id"], row["writer_process_id"])
                if key in seen_blocks:
                    continue                  # các phần của cùng block cùng PID: nối một lần
                seen_blocks.add(key)
            events.append({"event_id": row["event_id"], "table": table, "hostname": row["hostname"],
                           "links": links_for_event(con, table, row, lookback)})
    return {"generated_at_utc": datetime.now(timezone.utc).isoformat(), "lookback_hours": lookback.total_seconds() / 3600,
            "kind": "INFERENCE", "events": events,
            "note": "Suy luận tính khi truy vấn; không ghi vào alert. AMBIGUOUS = nhiều ứng viên, DACN không chọn đại."}
