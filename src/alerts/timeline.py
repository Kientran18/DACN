"""Timeline và cây tiến trình theo process_guid (PH6-T05). Không dùng PID để nối (ADR 0002)."""
from __future__ import annotations

from typing import Dict, List

_TABLES = ("silver_process_events", "silver_file_events", "silver_registry_events", "silver_network_events")
_ZERO_GUID = "00000000-0000-0000-0000-000000000000"


def timeline(con, process_guid: str, limit: int = 1000) -> List[Dict]:
    out = []
    for t in _TABLES:
        cur = con.execute(f"select event_id, timestamp, event_utc_time, record_id, sysmon_event_id, event_type, "
                          f"'{t}' as tbl from {t} where process_guid=?", [process_guid])
        cols = [c[0] for c in cur.description]
        for r in cur.fetchall():
            e = dict(zip(cols, r))
            e["skew_seconds"] = (round((e["timestamp"] - e["event_utc_time"]).total_seconds(), 3)
                                 if e["event_utc_time"] else None)
            out.append(e)
    out.sort(key=lambda e: (e["timestamp"], e["record_id"]))
    return out[:limit]


def _proc(con, guid: str):
    cur = con.execute("select event_id, process_guid, parent_guid, image_path, command_line, timestamp from "
                      "silver_process_events where process_guid=? and sysmon_event_id=1 order by timestamp limit 1", [guid])
    cols = [c[0] for c in cur.description]
    r = cur.fetchone()
    return dict(zip(cols, r)) if r else None


def process_tree(con, process_guid: str, max_depth: int = 12) -> Dict:
    """Tổ tiên (từ gần đến xa) và con cháu. PARTIAL_ANCESTRY nếu một tổ tiên không có Event 1 trong Silver."""
    node = _proc(con, process_guid)
    ancestors, status, seen = [], "FULL", {process_guid}
    cur_guid = node["parent_guid"] if node else None
    if node is None:
        status = "PARTIAL_ANCESTRY"
    while cur_guid and cur_guid != _ZERO_GUID and len(ancestors) < max_depth:
        if cur_guid in seen:
            status = "PARTIAL_ANCESTRY"; break
        seen.add(cur_guid)
        p = _proc(con, cur_guid)
        if p is None:
            status = "PARTIAL_ANCESTRY"; break
        ancestors.append(p)
        cur_guid = p["parent_guid"]
    descendants, frontier = [], [process_guid]
    for depth in range(1, max_depth + 1):
        nxt = []
        for g in frontier:
            cur = con.execute("select event_id, process_guid, parent_guid, image_path, command_line, timestamp from "
                              "silver_process_events where parent_guid=? and sysmon_event_id=1 order by timestamp", [g])
            cols = [c[0] for c in cur.description]
            for r in cur.fetchall():
                d = dict(zip(cols, r)); d["depth"] = depth
                if d["process_guid"] not in seen:
                    seen.add(d["process_guid"]); descendants.append(d); nxt.append(d["process_guid"])
        frontier = nxt
        if not frontier:
            break
    return {"process": node, "ancestors": ancestors, "descendants": descendants, "coverage_status": status}
