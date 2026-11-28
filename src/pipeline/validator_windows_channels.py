"""Validator Silver cho kênh Windows Defender và PowerShell/Operational (DDL v1.3 đề xuất).

Thiết kế: docs/architecture/w8/telemetry-defender-powershell-proposal.md mục 4 (D3–D5, người dùng duyệt 2026-11-26).
Tách khỏi SilverValidatorEngine (bản sao thiết kế Data W05, khóa theo Sysmon ID): không đổi hành vi Sysmon.
Tên trường EventData đối chiếu với mẫu XML thật đã khử định danh (2026-11-28, một Windows 10 VM); 5001/5013 chưa có mẫu.

Thứ tự kiểm tra (theo tinh thần W05): khóa tự nhiên -> record_id -> (channel, event_id) được hỗ trợ -> thời gian ->
trường bắt buộc theo loại -> route. Bản ghi lỗi vào DLQ với mã ERR_* (không điền giá trị giả, không bỏ âm thầm).
Module trần (import bằng tên như validator_poc); dùng lại parse_iso_utc của validator_poc.
"""
from __future__ import annotations

import hashlib
import re
import uuid
from datetime import datetime, timedelta, timezone
from typing import Any, Dict, List, Optional

import windows_channels as wc
from validator_poc import QuarantineRecord, parse_iso_utc

TABLE_DEFENDER = "silver_defender_events"
TABLE_POWERSHELL = "silver_powershell_scriptblock_events"

# Cột Silver <- tên 'Data Name' gốc (đã thấy trên mẫu thật)
DEFENDER_FIELDS = {
    "detection_time": "Detection Time", "threat_id": "Threat ID", "threat_name": "Threat Name",
    "severity_id": "Severity ID", "severity_name": "Severity Name", "category_name": "Category Name",
    "source_name": "Source Name", "process_name": "Process Name", "detection_user": "Detection User",
    "path_raw": "Path", "origin_name": "Origin Name", "execution_name": "Execution Name", "type_name": "Type Name",
    "action_id": "Action ID", "action_name": "Action Name", "error_code": "Error Code",
    "remediation_user": "Remediation User", "signature_version": "Security intelligence Version",
    "engine_version": "Engine Version", "old_value": "Old Value", "new_value": "New Value",
}
DEFENDER_THREAT_EVENTS = (1116, 1117)
PS_REQUIRED = ("ScriptBlockId", "MessageNumber", "MessageTotal", "ScriptBlockText")
_RESOURCE_RE = re.compile(r"^([A-Za-z][A-Za-z0-9]{0,31}):_(.*)$", re.S)


def split_resource(path: Optional[str]):
    """'file:_C:\\x.txt' -> ('file', 'C:\\x.txt'); 'CmdLine:_cmd /c ...' -> ('CmdLine', ...). Không có tiền tố -> (None, None).
    Chỉ tách tiền tố đầu tiên; Path chứa nhiều tài nguyên (nếu có) giữ nguyên ở resource_value và path_raw."""
    m = _RESOURCE_RE.match(path or "")
    return (m.group(1), m.group(2)) if m else (None, None)


def _blank_to_none(v: Optional[str]) -> Optional[str]:
    return v if v not in (None, "") else None


class WindowsChannelValidator:
    """Một bản ghi phẳng (từ bronze_to_silver_adapter) + bản ghi Bronze gốc -> dòng Silver hoặc DLQ."""

    def __init__(self) -> None:
        self.rows: Dict[str, List[Dict[str, Any]]] = {TABLE_DEFENDER: [], TABLE_POWERSHELL: []}
        self.quarantine_dlq: List[QuarantineRecord] = []

    def _q(self, code: str, reason: str, ref: str, payload: Dict[str, Any], stage: str = "SCHEMA_VALIDATION") -> bool:
        self.quarantine_dlq.append(QuarantineRecord(str(uuid.uuid4()), datetime.now(timezone.utc).isoformat(),
                                                    code, stage, reason, ref, payload))
        return False

    def process_record(self, flat: Dict[str, Any], bronze: Dict[str, Any], ref: str = "memory") -> bool:
        hostname = str(flat.get("hostname") or "").strip()
        channel = str(flat.get("channel") or "").strip()
        event_id = str(flat.get("event_id") or "").strip()
        for name, val in (("hostname", hostname), ("channel", channel), ("event_id", event_id)):
            if not val:
                return self._q("ERR_MISSING_NATURAL_KEY", f"Missing mandatory field '{name}'", ref, flat)
        try:
            record_id = int(flat.get("record_id"))
            if record_id <= 0:
                raise ValueError
        except (TypeError, ValueError):
            return self._q("ERR_INVALID_RECORD_ID", f"Invalid or non-positive record_id: {flat.get('record_id')!r}",
                           ref, flat, stage="TYPE_COERCION")
        canon = wc.canonical_channel(channel)
        if canon not in wc.SUPPORTED_EVENT_IDS:
            return self._q("ERR_UNSUPPORTED_CHANNEL", f"Channel {channel!r} has no Silver validator", ref, flat, stage="ROUTE")
        try:
            win_id = int(flat.get("sysmon_event_id"))
        except (TypeError, ValueError):
            return self._q("ERR_UNSUPPORTED_EVENT_ID", f"Non-integer event id: {flat.get('sysmon_event_id')!r}", ref, flat)
        if win_id not in wc.SUPPORTED_EVENT_IDS[canon]:
            return self._q("ERR_UNSUPPORTED_EVENT_ID", f"Event ID {win_id} is not supported for {canon}", ref, flat)
        ts = parse_iso_utc(flat.get("timestamp"))
        if ts is None or ts < datetime(2020, 1, 1, tzinfo=timezone.utc) or ts > datetime.now(timezone.utc) + timedelta(days=365):
            return self._q("ERR_INVALID_TIMESTAMP", f"Timestamp {flat.get('timestamp')!r} is malformed or out of valid range",
                           ref, flat)
        data = flat.get("raw_data") or {}
        base = {"event_id": event_id, "timestamp": ts, "source": flat.get("source"),
                "event_type": wc.event_type_for(canon, win_id), "windows_event_id": win_id, "channel": channel,
                "record_id": record_id, "hostname": hostname, "level": bronze.get("level"), "raw_data": dict(data)}
        if canon == wc.DEFENDER_CHANNEL:
            return self._defender(base, data, ref, flat)
        return self._powershell(base, data, bronze, ref, flat)

    def _defender(self, base, data, ref, flat) -> bool:
        if base["windows_event_id"] in DEFENDER_THREAT_EVENTS:
            missing = [k for k in ("Threat Name", "Threat ID") if not (data.get(k) or "").strip()]
            if missing:
                return self._q("ERR_DEFENDER_MISSING_THREAT", f"Defender {base['windows_event_id']} missing {missing}", ref, flat)
        row = dict(base)
        for col, name in DEFENDER_FIELDS.items():
            row[col] = _blank_to_none(data.get(name))
        det = _blank_to_none(data.get("Detection ID"))
        row["detection_id"] = det.strip().strip("{}").lower() if det else None
        row["resource_type"], row["resource_value"] = split_resource(row["path_raw"])
        self.rows[TABLE_DEFENDER].append(row)
        return True

    def _powershell(self, base, data, bronze, ref, flat) -> bool:
        missing = [k for k in PS_REQUIRED if k not in data or (k != "ScriptBlockText" and not str(data[k]).strip())]
        if missing:
            return self._q("ERR_PS_MISSING_SCRIPTBLOCK_FIELD", f"4104 missing {missing}", ref, flat)
        try:
            num, total = int(data["MessageNumber"]), int(data["MessageTotal"])
            if num < 1 or total < 1 or num > total:
                raise ValueError
        except (TypeError, ValueError):
            return self._q("ERR_PS_INVALID_PART_NUMBER",
                           f"MessageNumber={data.get('MessageNumber')!r} MessageTotal={data.get('MessageTotal')!r}",
                           ref, flat, stage="TYPE_COERCION")
        text = data["ScriptBlockText"]
        row = dict(base)
        row.update({"writer_process_id": bronze.get("writer_process_id"), "user_sid": bronze.get("log_writer_sid"),
                    "script_block_id": data["ScriptBlockId"].strip().strip("{}").lower(),
                    "message_number": num, "message_total": total, "script_block_text": text,
                    "script_text_sha256": hashlib.sha256(text.encode("utf-8")).hexdigest(),
                    "script_path": _blank_to_none(data.get("Path"))})
        self.rows[TABLE_POWERSHELL].append(row)
        return True
