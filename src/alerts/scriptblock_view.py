"""Ghép văn bản script block cho một alert PowerShell (DACN-DET-203/204) để API hiển thị (hạng mục 8, docs/architecture/w8).

Trả văn bản NGUYÊN VĂN; lớp API quyết định che (common.redact) hay trả bản gốc (quyền `raw`, ghi audit). Không ghi DB.
Phần thiếu được đánh dấu rõ, không bịa nội dung.
"""
from __future__ import annotations

from typing import Dict, List, Optional

TABLE = "silver_powershell_scriptblock_events"


def gap_marker(n: int) -> str:
    return f"\n[... THIẾU PHẦN {n} (MessageNumber {n}) ...]\n"


def script_for_alert(con, contributing_event_ids: List[str]) -> Optional[Dict]:
    """None nếu bảng không tồn tại hoặc alert không có sự kiện 4104 nào."""
    if not con.execute("select 1 from information_schema.tables where table_name=?", [TABLE]).fetchone():
        return None
    rows = con.execute(f"select event_id, hostname, script_block_id, message_number, message_total, script_block_text, "
                       f"timestamp, writer_process_id, script_path from {TABLE} where list_contains(?, event_id) "
                       f"order by message_number, record_id", [list(contributing_event_ids or [])]).fetchall()
    if not rows:
        return None
    parts: Dict[int, tuple] = {}
    for r in rows:
        parts.setdefault(r[3], r)            # cùng message_number lặp lại: giữ record_id nhỏ nhất (như engine)
    total = rows[0][4]
    pieces, missing = [], []
    for n in range(1, total + 1):
        if n in parts:
            pieces.append(parts[n][5] or "")
        else:
            missing.append(n)
            pieces.append(gap_marker(n))
    first = parts[min(parts)]
    return {"hostname": first[1], "script_block_id": first[2], "message_total": total, "parts_seen": len(parts),
            "missing_message_numbers": missing, "first_timestamp": min(p[6] for p in parts.values()),
            "writer_process_id": first[7], "script_path": first[8], "event_ids": [parts[n][0] for n in sorted(parts)],
            "text": "".join(pieces)}
