"""Kho tín hiệu ML (bảng nội bộ `_ml_signals`, do module này sở hữu như `_detection_results` của engine;
KHÔNG thuộc DDL v1.1/v1.2). Tín hiệu ML chỉ góp vào điểm rủi ro, KHÔNG tạo alert, KHÔNG kích hoạt response.
Không chấm được -> status INSUFFICIENT_TELEMETRY kèm reason, score NULL (không điền điểm giả)."""
from __future__ import annotations

import json
import math
import uuid
from datetime import datetime, timezone
from typing import List, Optional

SCORED, INSUFFICIENT = "SCORED", "INSUFFICIENT_TELEMETRY"
DETECTORS = ("ML_STATIC", "ML_BEHAVIOR")
_NS = uuid.uuid5(uuid.NAMESPACE_URL, "dacn-ml-signal")
DDL = """
CREATE TABLE IF NOT EXISTS _ml_signals (
    signal_id VARCHAR PRIMARY KEY, detector VARCHAR NOT NULL, model_version VARCHAR, feature_schema_version VARCHAR,
    status VARCHAR NOT NULL, reason VARCHAR, score DOUBLE, hostname VARCHAR, process_guid VARCHAR,
    source_event_ids VARCHAR[], observed_at_utc TIMESTAMPTZ, explanation JSON, created_at_utc TIMESTAMPTZ
)"""


def signal_id(detector: str, model_version: Optional[str], hostname: Optional[str], process_guid: Optional[str]) -> str:
    return str(uuid.uuid5(_NS, "|".join([detector, model_version or "", hostname or "", process_guid or ""])))


class MLSignalStore:
    def __init__(self, con):
        self.con = con
        con.execute(DDL)

    def record(self, detector: str, status: str, *, hostname, process_guid, source_event_ids, observed_at,
               score: Optional[float] = None, reason: Optional[str] = None, model_version: Optional[str] = None,
               feature_schema_version: Optional[str] = None, explanation: Optional[dict] = None) -> str:
        if detector not in DETECTORS:
            raise ValueError(f"detector không hỗ trợ: {detector}")
        if status == SCORED:
            if score is None or isinstance(score, bool) or not isinstance(score, (int, float)) \
                    or math.isnan(score) or not 0.0 <= score <= 1.0:
                raise ValueError("SCORED cần score trong [0,1]")
        elif status == INSUFFICIENT:
            if not reason or score is not None:
                raise ValueError("INSUFFICIENT_TELEMETRY cần reason và không có score")
        else:
            raise ValueError(f"status không hỗ trợ: {status}")
        sid = signal_id(detector, model_version, hostname, process_guid)
        self.con.execute("insert into _ml_signals values (?,?,?,?,?,?,?,?,?,?,?,?,?) on conflict do nothing",
                         [sid, detector, model_version, feature_schema_version, status, reason,
                          None if score is None else float(score), hostname, process_guid, list(source_event_ids),
                          observed_at, json.dumps(explanation or {}, ensure_ascii=False, default=str),
                          datetime.now(timezone.utc)])
        return sid

    def has(self, detector: str, model_version: Optional[str], hostname, process_guid) -> bool:
        return bool(self.con.execute("select 1 from _ml_signals where signal_id=?",
                                     [signal_id(detector, model_version, hostname, process_guid)]).fetchone())

    def list(self, hostname: Optional[str] = None, process_guid: Optional[str] = None) -> List[dict]:
        sql, p, cond = "select * from _ml_signals", [], []
        if hostname is not None:
            cond.append("hostname=?"); p.append(hostname)
        if process_guid is not None:
            cond.append("process_guid=?"); p.append(process_guid)
        if cond:
            sql += " where " + " and ".join(cond)
        cur = self.con.execute(sql + " order by observed_at_utc, signal_id", p)
        cols = [c[0] for c in cur.description]
        out = []
        for r in cur.fetchall():
            row = dict(zip(cols, r))
            row["explanation"] = json.loads(row["explanation"]) if row["explanation"] else {}
            row["triggers_response"] = False
            out.append(row)
        return out
