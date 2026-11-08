"""Evidence resolver: alert -> Silver -> Bronze -> raw_xml, và chiều ngược (PH6-T04). Luôn xác minh hash."""
from __future__ import annotations

import hashlib
from pathlib import Path
from typing import Dict, Optional

from pipeline.segment_reader import SegmentError, read_segment

_TABLES = ("silver_process_events", "silver_file_events", "silver_registry_events", "silver_network_events")


def _silver(con, event_id: str) -> Optional[Dict]:
    for t in _TABLES:
        cur = con.execute(f"select * from {t} where event_id=?", [event_id])
        cols = [c[0] for c in cur.description]
        r = cur.fetchone()
        if r:
            return dict(zip(cols, r))
    return None


def resolve_evidence(con, alert_id: str, bronze_dir: Path) -> Dict:
    """status: FULL | PARTIAL | RAW_EXPIRED | SEGMENT_INVALID | NO_LINEAGE — mức kém nhất trong các sự kiện."""
    row = con.execute("select contributing_event_ids from alerts where alert_id=?", [alert_id]).fetchone()
    if row is None:
        raise KeyError(alert_id)
    events, order = [], ["FULL", "PARTIAL", "RAW_EXPIRED", "NO_LINEAGE", "SEGMENT_INVALID"]
    worst = "FULL"
    for eid in row[0]:
        item = {"event_id": eid, "silver": _silver(con, eid), "raw_xml": None, "bronze": None, "status": "FULL"}
        lin = con.execute("select bronze_segment, bronze_line_no, bronze_content_hash from silver_event_lineage "
                          "where event_id=?", [eid]).fetchone()
        if item["silver"] is None:
            item["status"] = "PARTIAL"
        elif lin is None:
            item["status"] = "NO_LINEAGE"
        else:
            seg, line_no, h = lin
            item["bronze"] = {"segment": seg, "line_no": line_no}
            path = Path(bronze_dir) / seg
            if not path.exists():
                item["status"] = "RAW_EXPIRED"
            else:
                try:
                    rec = next(r for n, r in read_segment(path) if n == line_no)
                    if hashlib.sha256(rec["raw_xml"].encode("utf-8")).hexdigest() != h:
                        item["status"] = "SEGMENT_INVALID"
                    else:
                        item["raw_xml"] = rec["raw_xml"]
                except (SegmentError, StopIteration):
                    item["status"] = "SEGMENT_INVALID"
        events.append(item)
        if order.index(item["status"]) > order.index(worst):
            worst = item["status"]
    return {"alert_id": alert_id, "status": worst, "events": events}


def event_for_raw(con, raw_xml: str) -> Optional[str]:
    """Chiều ngược: raw_xml -> event_id Silver (qua hash nội dung trong lineage)."""
    h = hashlib.sha256(raw_xml.encode("utf-8")).hexdigest()
    r = con.execute("select event_id from silver_event_lineage where bronze_content_hash=?", [h]).fetchone()
    return r[0] if r else None
