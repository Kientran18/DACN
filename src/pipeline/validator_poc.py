#!/usr/bin/env python3
"""
Local EDR W05 PoC: Bronze-to-Silver Validation, Deterministic Deduplication,
Quarantine DLQ, DuckDB Storage, and Feature/Lineage Verification.

Chạy kiểm chứng trực tiếp trên bộ mẫu thật W03 (process.json, file.json,
registry.json, network.json, poc_run_20261018_021142.json) và bộ mẫu lỗi có nhãn.
"""

from __future__ import annotations

import ipaddress
import json
import math
import re
import uuid
from collections import Counter
from dataclasses import dataclass, asdict
from datetime import datetime, timezone, timedelta
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple

try:
    import duckdb
    HAS_DUCKDB = True
except ImportError:
    HAS_DUCKDB = False

# ==============================================================================
# 1. HẰNG SỐ KIẾN TRÚC & QUY TẮC CHUẨN HÓA (ADR 0001, ADR 0002, ADR 0003)
# ==============================================================================

EDR_NAMESPACE = uuid.UUID("6f1d3c52-8a0e-4b7a-9c1e-3d5a7b9e2f10")

UUID_REGEX = re.compile(
    r"^[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}$"
)

SUPPORTED_SYSMON_IDS = {1, 3, 5, 11, 12, 13, 14, 15, 22, 23, 26, 29}

EVENT_ID_TO_TYPE_DEFAULT = {
    1: "PROCESS_START",
    5: "PROCESS_TERMINATE",
    3: "NETWORK_CONNECT",
    22: "DNS_QUERY",
    11: "FILE_CREATE",
    15: "FILE_STREAM_HASH",
    23: "FILE_DELETE",
    26: "FILE_DELETE",
    29: "FILE_EXECUTABLE_DETECTED",
    12: "REGISTRY_CREATE_KEY",
    13: "REGISTRY_SET_VALUE",
    14: "REGISTRY_RENAME",
}

VALID_HIVES = {"HKLM", "HKU", "HKCU", "HKCR", "HKCC", "HKEY_LOCAL_MACHINE", "HKEY_USERS"}


def generate_deterministic_event_id(hostname: str, channel: str, record_id: int) -> str:
    """Sinh khóa xác định UUIDv5 từ bộ ba (Computer, Channel, EventRecordID)."""
    composite_key = f"{hostname.strip()}|{channel.strip()}|{record_id}"
    return str(uuid.uuid5(EDR_NAMESPACE, composite_key))


def strip_guid(val: Optional[str]) -> str:
    """Loại bỏ ngoặc nhọn {} khỏi GUID của Sysmon và chuẩn hóa chữ thường."""
    if not val or not isinstance(val, str):
        return ""
    return val.strip().strip("{}").lower()


def parse_iso_utc(ts_str: Optional[str]) -> Optional[datetime]:
    """
    Parse chuỗi thời gian ISO 8601 UTC (hỗ trợ cả độ phân giải 100ns 7 chữ số của Windows
    và định dạng 'YYYY-MM-DD HH:MM:SS.fff' của Sysmon UtcTime).
    """
    if not ts_str or not isinstance(ts_str, str):
        return None
    s = ts_str.strip()
    try:
        # Xử lý định dạng 7 chữ số thập phân của Windows SystemTime (ví dụ: .8868056Z)
        if s.endswith("Z"):
            s_body = s[:-1]
            if "." in s_body:
                main_part, frac_part = s_body.split(".", 1)
                frac_part = (frac_part + "000000")[:6]
                s_norm = f"{main_part}.{frac_part}+00:00"
            else:
                s_norm = f"{s_body}+00:00"
            return datetime.fromisoformat(s_norm).astimezone(timezone.utc)
        # Xử lý định dạng UtcTime của Sysmon EventData: '2026-10-18 09:11:55.842'
        if " " in s and "T" not in s and "+" not in s:
            dt = datetime.strptime(s, "%Y-%m-%d %H:%M:%S.%f")
            return dt.replace(tzinfo=timezone.utc)
        dt = datetime.fromisoformat(s)
        if dt.tzinfo is None:
            dt = dt.replace(tzinfo=timezone.utc)
        return dt.astimezone(timezone.utc)
    except Exception:
        return None


def parse_sysmon_hashes(hashes_raw: Any) -> Tuple[Optional[str], Optional[str], Dict[str, str]]:
    """Trích xuất SHA256, IMPHASH và dictionary hashes từ chuỗi Hashes của Sysmon."""
    if isinstance(hashes_raw, dict):
        norm_dict = {k.lower(): str(v).upper() for k, v in hashes_raw.items() if v}
        return norm_dict.get("sha256"), norm_dict.get("imphash"), norm_dict
    if not hashes_raw or not isinstance(hashes_raw, str):
        return None, None, {}
    result: Dict[str, str] = {}
    for part in hashes_raw.split(","):
        if "=" in part:
            k, v = part.split("=", 1)
            result[k.strip().lower()] = v.strip().upper()
    return result.get("sha256"), result.get("imphash"), result


def infer_registry_value_type(details: Optional[str]) -> str:
    """Suy diễn kiểu dữ liệu Registry từ trường Details của Sysmon Event ID 13."""
    if not details:
        return "UNKNOWN"
    if details.startswith("DWORD ("):
        return "REG_DWORD"
    if details.startswith("QWORD ("):
        return "REG_QWORD"
    if details.startswith("Binary Data"):
        return "REG_BINARY"
    return "STRING_UNSPECIFIED"


def parse_registry_target(target_object: str, operation: str) -> Tuple[str, str, Optional[str]]:
    """Tách TargetObject thành (hive, key_path, value_name)."""
    parts = [p for p in target_object.split("\\") if p]
    if not parts:
        return "", "", None
    hive = parts[0].upper()
    if operation in ("SetValue", "DeleteValue") and len(parts) >= 3:
        key_path = "\\".join(parts[1:-1])
        value_name = parts[-1]
    else:
        key_path = "\\".join(parts[1:])
        value_name = None
    return hive, key_path, value_name


def calculate_shannon_entropy(text: Optional[str]) -> float:
    """Tính độ hỗn loạn Shannon Entropy H(X) của chuỗi dòng lệnh."""
    if not text:
        return 0.0
    length = len(text)
    counts = Counter(text)
    return round(-sum((c / length) * math.log2(c / length) for c in counts.values()), 4)


# ==============================================================================
# 2. CẤU TRÚC KẾT QUẢ VALIDATION & QUARANTINE ENVELOPE
# ==============================================================================

@dataclass
class QuarantineRecord:
    quarantine_id: str
    quarantined_at_utc: str
    error_code: str
    error_stage: str
    error_reason: str
    source_reference: str
    raw_payload: Dict[str, Any]


@dataclass
class PipelineMetrics:
    total_read: int = 0
    valid_silver_inserted: int = 0
    duplicates_dropped: int = 0
    quarantined_count: int = 0
    time_skew_warnings: int = 0


# ==============================================================================
# 3. BỘ KIỂM ĐỊNH & CHUẨN HÓA THEO LOẠI SỰ KIỆN (SILVER VALIDATOR ENGINE)
# ==============================================================================

class SilverValidatorEngine:
    """
    Kiểm định bản ghi Bronze, chống trùng lặp bằng UUIDv5 và phân luồng vào
    4 bảng Silver (process, file, registry, network) hoặc Quarantine DLQ.
    Tuyệt đối tuân thủ nguyên tắc Zero Data Fabrication.
    """

    def __init__(self) -> None:
        self.seen_event_ids: set[str] = set()
        self.metrics = PipelineMetrics()
        self.silver_process: List[Dict[str, Any]] = []
        self.silver_file: List[Dict[str, Any]] = []
        self.silver_registry: List[Dict[str, Any]] = []
        self.silver_network: List[Dict[str, Any]] = []
        self.quarantine_dlq: List[QuarantineRecord] = []

    def _quarantine(
        self,
        error_code: str,
        error_reason: str,
        source_ref: str,
        raw_record: Dict[str, Any],
        stage: str = "SCHEMA_VALIDATION",
    ) -> None:
        self.metrics.quarantined_count += 1
        q_rec = QuarantineRecord(
            quarantine_id=str(uuid.uuid4()),
            quarantined_at_utc=datetime.now(timezone.utc).isoformat(),
            error_code=error_code,
            error_stage=stage,
            error_reason=error_reason,
            source_reference=source_ref,
            raw_payload=raw_record,
        )
        self.quarantine_dlq.append(q_rec)

    def process_record(self, raw_record: Dict[str, Any], source_ref: str = "memory") -> bool:
        self.metrics.total_read += 1
        ingest_now = datetime.now(timezone.utc)

        # 1. Kiểm tra khóa tự nhiên (hostname, channel, record_id)
        raw_data = raw_record.get("raw_data") or {}
        data_block = raw_record.get("data") or {}

        hostname = str(raw_record.get("hostname") or "").strip()
        channel = str(
            raw_record.get("channel") or "Microsoft-Windows-Sysmon/Operational"
        ).strip()

        if not hostname:
            self._quarantine(
                "ERR_MISSING_NATURAL_KEY",
                "Missing mandatory field 'hostname' (System.Computer)",
                source_ref,
                raw_record,
            )
            return False

        try:
            record_id = int(raw_record.get("record_id"))
            if record_id <= 0:
                raise ValueError("record_id must be > 0")
        except (TypeError, ValueError):
            self._quarantine(
                "ERR_INVALID_RECORD_ID",
                f"Invalid or non-positive record_id: {raw_record.get('record_id')!r}",
                source_ref,
                raw_record,
                stage="TYPE_COERCION",
            )
            return False

        # 2. Kiểm tra sysmon_event_id
        try:
            sysmon_event_id = int(raw_record.get("sysmon_event_id"))
        except (TypeError, ValueError):
            self._quarantine(
                "ERR_UNSUPPORTED_EVENT_ID",
                f"Non-integer sysmon_event_id: {raw_record.get('sysmon_event_id')!r}",
                source_ref,
                raw_record,
            )
            return False

        if sysmon_event_id not in SUPPORTED_SYSMON_IDS:
            self._quarantine(
                "ERR_UNSUPPORTED_EVENT_ID",
                f"Sysmon Event ID {sysmon_event_id} is not in supported contract v1.1",
                source_ref,
                raw_record,
            )
            return False

        # 3. Kiểm tra và chuẩn hóa Timestamp UTC
        ts_dt = parse_iso_utc(raw_record.get("timestamp"))
        min_allowed_dt = datetime(2020, 1, 1, tzinfo=timezone.utc)
        max_allowed_dt = ingest_now + timedelta(days=365)  # Cho phép mẫu năm 2026
        if ts_dt is None or ts_dt < min_allowed_dt or ts_dt > max_allowed_dt:
            self._quarantine(
                "ERR_INVALID_TIMESTAMP",
                f"Timestamp {raw_record.get('timestamp')!r} is malformed or out of valid range",
                source_ref,
                raw_record,
            )
            return False

        utc_time_dt = parse_iso_utc(raw_data.get("UtcTime"))
        if utc_time_dt and abs((ts_dt - utc_time_dt).total_seconds()) > 5.0:
            self.metrics.time_skew_warnings += 1

        # 4. Kiểm tra và chuẩn hóa process_guid (ADR 0002)
        raw_pguid = (
            raw_record.get("process_guid")
            or data_block.get("process_guid")
            or raw_data.get("ProcessGuid")
        )
        process_guid = strip_guid(raw_pguid)
        if not process_guid or not UUID_REGEX.match(process_guid):
            self._quarantine(
                "ERR_MISSING_PROCESS_GUID",
                f"Invalid or empty process_guid: {raw_pguid!r}",
                source_ref,
                raw_record,
            )
            return False

        # 5. Sinh khóa xác định UUIDv5 & Deduplication (ADR 0001)
        deterministic_id = generate_deterministic_event_id(hostname, channel, record_id)
        if deterministic_id in self.seen_event_ids:
            self.metrics.duplicates_dropped += 1
            return False

        # Chuẩn bị Envelope chung v1.1
        raw_rule = raw_data.get("RuleName")
        rule_name = None if (not raw_rule or raw_rule == "-") else str(raw_rule)
        event_type = str(
            raw_record.get("event_type")
            or EVENT_ID_TO_TYPE_DEFAULT.get(sysmon_event_id, "UNKNOWN")
        )

        envelope = {
            "event_id": deterministic_id,
            "timestamp": ts_dt.isoformat(),
            "event_utc_time": utc_time_dt.isoformat() if utc_time_dt else None,
            "ingest_timestamp": ingest_now.isoformat(),
            "source": "SYSMON",
            "event_type": event_type,
            "sysmon_event_id": sysmon_event_id,
            "channel": channel,
            "record_id": record_id,
            "hostname": hostname.upper(),
            "process_guid": process_guid,
            "rule_name": rule_name,
            "raw_data": json.dumps(raw_data, ensure_ascii=False),
        }

        # 6. Phân luồng kiểm định theo từng nhóm sự kiện
        if sysmon_event_id in (1, 5):
            ok = self._validate_and_append_process(
                envelope, sysmon_event_id, data_block, raw_data, source_ref, raw_record
            )
        elif sysmon_event_id in (11, 15, 23, 26, 29):
            ok = self._validate_and_append_file(
                envelope, sysmon_event_id, data_block, raw_data, source_ref, raw_record
            )
        elif sysmon_event_id in (12, 13, 14):
            ok = self._validate_and_append_registry(
                envelope, sysmon_event_id, data_block, raw_data, source_ref, raw_record
            )
        elif sysmon_event_id in (3, 22):
            ok = self._validate_and_append_network(
                envelope, sysmon_event_id, data_block, raw_data, source_ref, raw_record
            )
        else:
            ok = False

        if ok:
            self.seen_event_ids.add(deterministic_id)
            self.metrics.valid_silver_inserted += 1
        return ok

    def _validate_and_append_process(
        self,
        envelope: Dict[str, Any],
        sysmon_id: int,
        data: Dict[str, Any],
        raw_data: Dict[str, Any],
        source_ref: str,
        raw_record: Dict[str, Any],
    ) -> bool:
        try:
            pid = int(data.get("pid") if "pid" in data else raw_data.get("ProcessId"))
            if pid <= 0:
                raise ValueError("pid <= 0")
        except (TypeError, ValueError):
            self._quarantine(
                "ERR_TYPE_COERCION_FAILED",
                "Failed to coerce ProcessId to positive integer",
                source_ref,
                raw_record,
                stage="TYPE_COERCION",
            )
            return False

        image_path = str(data.get("image_path") or raw_data.get("Image") or "").strip()
        if not image_path:
            self._quarantine(
                "ERR_PROC_START_MISSING_FIELD",
                "Missing mandatory 'image_path' in Process Event",
                source_ref,
                raw_record,
            )
            return False

        ppid: Optional[int] = None
        parent_guid: Optional[str] = None
        if sysmon_id == 1:
            try:
                ppid = int(
                    data.get("ppid") if "ppid" in data else raw_data.get("ParentProcessId")
                )
            except (TypeError, ValueError):
                self._quarantine(
                    "ERR_PROC_START_MISSING_FIELD",
                    "Missing or invalid ParentProcessId in Sysmon Event ID 1",
                    source_ref,
                    raw_record,
                )
                return False

            parent_guid = strip_guid(
                data.get("parent_guid") or raw_data.get("ParentProcessGuid")
            )
            if not parent_guid or not UUID_REGEX.match(parent_guid):
                self._quarantine(
                    "ERR_PROC_START_MISSING_FIELD",
                    "Missing or malformed ParentProcessGuid in Sysmon Event ID 1",
                    source_ref,
                    raw_record,
                )
                return False

        sha256, imphash, hashes_dict = parse_sysmon_hashes(
            data.get("hashes") or raw_data.get("Hashes")
        )
        file_sha256 = data.get("file_sha256") or sha256

        session_raw = data.get("session_id") if "session_id" in data else raw_data.get("TerminalSessionId")
        session_id = int(session_raw) if session_raw is not None and str(session_raw).isdigit() else None

        row = {
            **envelope,
            "pid": pid,
            "ppid": ppid,
            "parent_guid": parent_guid,
            "image_path": image_path,
            "command_line": data.get("command_line") or raw_data.get("CommandLine"),
            "current_working_directory": data.get("current_working_directory")
            or raw_data.get("CurrentDirectory"),
            "user_name": data.get("user_name") or raw_data.get("User"),
            "integrity_level": data.get("integrity_level") or raw_data.get("IntegrityLevel"),
            "session_id": session_id,
            "parent_image": data.get("parent_image") or raw_data.get("ParentImage"),
            "parent_command_line": data.get("parent_command_line")
            or raw_data.get("ParentCommandLine"),
            "file_sha256": file_sha256,
            "imphash": imphash,
            "hashes": json.dumps(hashes_dict),
        }
        self.silver_process.append(row)
        return True

    def _validate_and_append_file(
        self,
        envelope: Dict[str, Any],
        sysmon_id: int,
        data: Dict[str, Any],
        raw_data: Dict[str, Any],
        source_ref: str,
        raw_record: Dict[str, Any],
    ) -> bool:
        file_path = str(data.get("file_path") or raw_data.get("TargetFilename") or "").strip()
        image_path = str(data.get("image_path") or raw_data.get("Image") or "").strip()
        if not file_path or not image_path:
            self._quarantine(
                "ERR_FILE_EVENT_MISSING_PATH",
                "Missing mandatory 'file_path' (TargetFilename) or 'image_path' (Image)",
                source_ref,
                raw_record,
            )
            return False

        # Giải quyết INC-04: Tự động đồng bộ operation từ event_type nếu data.operation khuyết
        operation = str(data.get("operation") or envelope["event_type"])
        ext = data.get("file_extension")
        if not ext and "." in Path(file_path).name:
            ext = Path(file_path).suffix.lstrip(".").lower()

        sha256, _, hashes_dict = parse_sysmon_hashes(
            data.get("hashes") or raw_data.get("Hashes")
        )
        file_sha256 = data.get("file_sha256") or sha256
        pid_raw = raw_data.get("ProcessId")
        pid = int(pid_raw) if pid_raw and str(pid_raw).isdigit() else None
        creation_dt = parse_iso_utc(raw_data.get("CreationUtcTime"))

        row = {
            **envelope,
            "operation": operation,
            "pid": pid,
            "file_path": file_path,
            "file_extension": ext,
            "image_path": image_path,
            "creation_utc_time": creation_dt.isoformat() if creation_dt else None,
            "user_name": raw_data.get("User"),
            "file_sha256": file_sha256,
            "hashes": json.dumps(hashes_dict),
        }
        self.silver_file.append(row)
        return True

    def _validate_and_append_registry(
        self,
        envelope: Dict[str, Any],
        sysmon_id: int,
        data: Dict[str, Any],
        raw_data: Dict[str, Any],
        source_ref: str,
        raw_record: Dict[str, Any],
    ) -> bool:
        operation = str(data.get("operation") or raw_data.get("EventType") or "").strip()
        target_object = str(
            data.get("target_object") or raw_data.get("TargetObject") or ""
        ).strip()
        image_path = str(data.get("image_path") or raw_data.get("Image") or "").strip()

        if not operation or not target_object or not image_path:
            self._quarantine(
                "ERR_REG_INVALID_TARGET",
                "Missing mandatory operation, target_object, or image_path in Registry Event",
                source_ref,
                raw_record,
            )
            return False

        hive, key_path, value_name = parse_registry_target(target_object, operation)
        if hive not in VALID_HIVES:
            self._quarantine(
                "ERR_REG_INVALID_TARGET",
                f"Registry hive {hive!r} is not a valid Windows Registry root hive",
                source_ref,
                raw_record,
            )
            return False

        details = data.get("details") or data.get("new_data_str") or raw_data.get("Details")
        if sysmon_id == 13 and details is None:
            self._quarantine(
                "ERR_REG_MISSING_DETAILS",
                "Sysmon Event ID 13 (SetValue) requires non-null Details",
                source_ref,
                raw_record,
            )
            return False

        val_type = data.get("value_type_inferred") or infer_registry_value_type(details)
        pid_raw = raw_data.get("ProcessId")
        pid = int(pid_raw) if pid_raw and str(pid_raw).isdigit() else None

        row = {
            **envelope,
            "operation": operation,
            "pid": pid,
            "target_object": target_object,
            "hive": data.get("hive") or hive,
            "key_path": data.get("key_path") or key_path,
            "value_name": data.get("value_name") or value_name,
            "value_type_inferred": val_type,
            "details": details,
            "new_name": raw_data.get("NewName"),
            "image_path": image_path,
            "user_name": raw_data.get("User"),
        }
        self.silver_registry.append(row)
        return True

    def _validate_and_append_network(
        self,
        envelope: Dict[str, Any],
        sysmon_id: int,
        data: Dict[str, Any],
        raw_data: Dict[str, Any],
        source_ref: str,
        raw_record: Dict[str, Any],
    ) -> bool:
        image_path = str(data.get("image_path") or raw_data.get("Image") or "").strip()
        if not image_path:
            self._quarantine(
                "ERR_NET_MISSING_IMAGE",
                "Missing mandatory 'image_path' in Network/DNS Event",
                source_ref,
                raw_record,
            )
            return False

        pid_raw = raw_data.get("ProcessId")
        pid = int(pid_raw) if pid_raw and str(pid_raw).isdigit() else None

        # Phân nhánh rõ ràng giữa Event ID 3 (Socket Connect) và Event ID 22 (DNS Query)
        if sysmon_id == 3:
            src_ip = data.get("src_ip") or raw_data.get("SourceIp")
            dest_ip = data.get("dest_ip") or raw_data.get("DestinationIp")
            try:
                if not src_ip or not dest_ip:
                    raise ValueError("Missing IP")
                ipaddress.ip_address(str(src_ip))
                ipaddress.ip_address(str(dest_ip))
                src_port = int(
                    data.get("src_port")
                    if "src_port" in data
                    else raw_data.get("SourcePort")
                )
                dest_port = int(
                    data.get("dest_port")
                    if "dest_port" in data
                    else raw_data.get("DestinationPort")
                )
                if not (0 <= src_port <= 65535 and 0 <= dest_port <= 65535):
                    raise ValueError("Port out of range")
            except (TypeError, ValueError) as exc:
                self._quarantine(
                    "ERR_NET_INVALID_IP_OR_PORT",
                    f"Invalid IP or Port in Sysmon Event ID 3: {exc}",
                    source_ref,
                    raw_record,
                )
                return False

            protocol = str(data.get("protocol") or raw_data.get("Protocol") or "TCP").upper()
            initiated = str(raw_data.get("Initiated") or "").lower()
            direction = data.get("direction") or (
                "OUTBOUND" if initiated == "true" else "INBOUND"
            )
            ip_version = data.get("ip_version") or (
                "IPv6"
                if str(raw_data.get("SourceIsIpv6")).lower() == "true"
                else "IPv4"
            )
            dest_host = raw_data.get("DestinationHostname")
            dest_hostname = None if (not dest_host or dest_host == "-") else dest_host

            row = {
                **envelope,
                "pid": pid,
                "image_path": image_path,
                "user_name": raw_data.get("User"),
                "protocol": protocol,
                "direction": direction,
                "ip_version": ip_version,
                "src_ip": str(src_ip),
                "src_port": src_port,
                "dest_ip": str(dest_ip),
                "dest_port": dest_port,
                "dest_hostname": dest_hostname,
                "dns_query_name": None,
                "dns_query_status": None,
                "dns_query_results": None,
            }
        else:
            # Sysmon Event ID 22: DNS Query (Cho phép NULL trên 4-tuple IP/Port)
            dns_query_name = str(
                data.get("dns_query_name") or raw_data.get("QueryName") or ""
            ).strip()
            if not dns_query_name:
                self._quarantine(
                    "ERR_DNS_MISSING_QUERY_NAME",
                    "Missing mandatory 'QueryName' in Sysmon Event ID 22",
                    source_ref,
                    raw_record,
                )
                return False

            q_status_raw = raw_data.get("QueryStatus")
            q_status = (
                int(q_status_raw)
                if q_status_raw is not None and str(q_status_raw).isdigit()
                else None
            )
            row = {
                **envelope,
                "event_type": "DNS_QUERY",
                "pid": pid,
                "image_path": image_path,
                "user_name": raw_data.get("User"),
                "protocol": "UDP",
                "direction": "OUTBOUND",
                "ip_version": None,
                "src_ip": None,
                "src_port": None,
                "dest_ip": None,
                "dest_port": None,
                "dest_hostname": None,
                "dns_query_name": dns_query_name,
                "dns_query_status": q_status,
                "dns_query_results": raw_data.get("QueryResults"),
            }

        self.silver_network.append(row)
        return True


# ==============================================================================
# 4. BỘ DỮ LIỆU KIỂM THỬ (MẪU THẬT W03 + MẪU DNS ID 22 + MẪU LỖI CÓ NHÃN)
# ==============================================================================

def build_negative_and_edge_samples() -> List[Tuple[str, Dict[str, Any]]]:
    """Tạo 1 bản ghi DNS ID 22 hợp lệ và 4 bản ghi lỗi có nhãn để kiểm chứng Quarantine."""
    return [
        (
            "TC-POS-05 (Valid DNS Event ID 22)",
            {
                "timestamp": "2026-10-18T09:11:58.1200000Z",
                "source": "SYSMON",
                "event_type": "DNS_QUERY",
                "sysmon_event_id": 22,
                "channel": "Microsoft-Windows-Sysmon/Operational",
                "record_id": 193,
                "hostname": "DESKTOP-IDEMGQU",
                "process_guid": "{43f71ec6-8d48-6ad4-1c01-000000000400}",
                "raw_data": {
                    "RuleName": "network",
                    "UtcTime": "2026-10-18 09:11:58.115",
                    "ProcessGuid": "{43f71ec6-8d48-6ad4-1c01-000000000400}",
                    "ProcessId": "1616",
                    "QueryName": "cloudflare.com",
                    "QueryStatus": "0",
                    "QueryResults": "::ffff:172.66.147.243;",
                    "Image": "C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe",
                    "User": "DESKTOP-IDEMGQU\\Trankien",
                },
            },
        ),
        (
            "TC-NEG-01 (Missing Mandatory process_guid)",
            {
                "timestamp": "2026-10-18T09:12:00.0000000Z",
                "source": "SYSMON",
                "event_type": "PROCESS_START",
                "sysmon_event_id": 1,
                "channel": "Microsoft-Windows-Sysmon/Operational",
                "record_id": 90001,
                "hostname": "DESKTOP-IDEMGQU",
                "process_guid": "",
                "raw_data": {"ProcessId": "4000", "Image": "C:\\Windows\\System32\\cmd.exe"},
            },
        ),
        (
            "TC-NEG-02 (Corrupted record_id Type Failure)",
            {
                "timestamp": "2026-10-18T09:12:01.0000000Z",
                "source": "SYSMON",
                "event_type": "FILE_CREATE",
                "sysmon_event_id": 11,
                "channel": "Microsoft-Windows-Sysmon/Operational",
                "record_id": "CORRUPTED_ID",
                "hostname": "DESKTOP-IDEMGQU",
                "process_guid": "{43f71ec6-8d48-6ad4-1c01-000000000400}",
                "raw_data": {"TargetFilename": "C:\\Temp\\test.txt", "Image": "cmd.exe"},
            },
        ),
        (
            "TC-NEG-03 (Invalid 1970 Epoch Timestamp)",
            {
                "timestamp": "1970-01-01T00:00:00Z",
                "source": "SYSMON",
                "event_type": "REGISTRY_SET_VALUE",
                "sysmon_event_id": 13,
                "channel": "Microsoft-Windows-Sysmon/Operational",
                "record_id": 90003,
                "hostname": "DESKTOP-IDEMGQU",
                "process_guid": "{43f71ec6-8d48-6ad4-1c01-000000000400}",
                "raw_data": {
                    "EventType": "SetValue",
                    "TargetObject": "HKLM\\Software\\Test\\Val",
                    "Details": "DWORD (0x00000001)",
                    "Image": "reg.exe",
                },
            },
        ),
        (
            "TC-NEG-04 (Event ID 3 Invalid Destination IP)",
            {
                "timestamp": "2026-10-18T09:12:02.0000000Z",
                "source": "SYSMON",
                "event_type": "NETWORK_CONNECT",
                "sysmon_event_id": 3,
                "channel": "Microsoft-Windows-Sysmon/Operational",
                "record_id": 90004,
                "hostname": "DESKTOP-IDEMGQU",
                "process_guid": "{43f71ec6-8d48-6ad4-1c01-000000000400}",
                "raw_data": {
                    "Image": "powershell.exe",
                    "Protocol": "tcp",
                    "SourceIp": "10.0.2.15",
                    "SourcePort": "50000",
                    "DestinationIp": "999.999.999.999",
                    "DestinationPort": "443",
                },
            },
        ),
    ]


# ==============================================================================
# 5. KHỞI TẠO DUCKDB SILVER, FEATURE STORE & TRUY VẾT LINEAGE
# ==============================================================================

def run_duckdb_verification(engine: SilverValidatorEngine) -> None:
    """Khởi tạo DuckDB in-memory, nạp 4 bảng Silver và chạy truy vấn Feature + Lineage."""
    if not HAS_DUCKDB:
        print("[!] Thư viện 'duckdb' chưa được cài đặt. Bỏ qua bước truy vấn SQL.")
        return

    con = duckdb.connect(":memory:")
    con.execute("""
        CREATE TABLE silver_process_events (
            event_id VARCHAR PRIMARY KEY,
            timestamp TIMESTAMPTZ,
            sysmon_event_id INTEGER,
            record_id BIGINT,
            hostname VARCHAR,
            process_guid VARCHAR,
            parent_guid VARCHAR,
            pid INTEGER,
            ppid INTEGER,
            image_path VARCHAR,
            command_line VARCHAR,
            file_sha256 VARCHAR,
            imphash VARCHAR
        );
    """)

    for r in engine.silver_process:
        con.execute(
            """
            INSERT OR IGNORE INTO silver_process_events VALUES (
                ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?
            )
            """,
            [
                r["event_id"],
                r["timestamp"],
                r["sysmon_event_id"],
                r["record_id"],
                r["hostname"],
                r["process_guid"],
                r["parent_guid"],
                r["pid"],
                r["ppid"],
                r["image_path"],
                r["command_line"],
                r["file_sha256"],
                r["imphash"],
            ],
        )

    print("\n=== [DUCKDB SILVER] KIỂM CHỨNG CÂY PHẢ HỆ TIẾN TRÌNH & SHANNON ENTROPY ===")
    rows = con.execute("""
        SELECT record_id, event_id, pid, ppid, process_guid, parent_guid, image_path, command_line
        FROM silver_process_events
        ORDER BY record_id ASC
    """).fetchall()

    for rec_id, ev_id, pid, ppid, pguid, par_guid, img, cmd in rows:
        entropy = calculate_shannon_entropy(cmd)
        is_temp = "\\temp\\" in img.lower()
        print(
            f"  * Record {rec_id} | event_id={ev_id[:8]}... | PID={pid} (PPID={ppid}) "
            f"| GUID={pguid[:13]}... | Parent={str(par_guid)[:13]}... "
            f"| TempExec={is_temp} | CmdEntropy={entropy}"
        )


def main() -> None:
    engine = SilverValidatorEngine()

    # Tự động tìm 4 file JSON mẫu thật nếu có trong thư mục hiện tại hoặc references/samples
    sample_files = ["process.json", "file.json", "registry.json", "network.json"]
    loaded_real_count = 0

    for fname in sample_files:
        for candidate in [Path(fname), Path("references/samples") / fname]:
            if candidate.exists():
                records = json.loads(candidate.read_text(encoding="utf-8-sig"))
                for rec in records:
                    engine.process_record(rec, source_ref=str(candidate))
                    loaded_real_count += 1
                # Thử nạp lặp lại bản ghi đầu tiên của process.json và file.json để test Dedup
                if fname in ("process.json", "file.json") and records:
                    engine.process_record(records[0], source_ref=f"{candidate}#duplicate_replay")
                break

    # Chạy bộ mẫu DNS ID 22 và 4 mẫu lỗi có nhãn
    for label, sample_rec in build_negative_and_edge_samples():
        engine.process_record(sample_rec, source_ref=label)

    print("==========================================================================")
    print("       BÁO CÁO KẾT QUẢ KIỂM ĐỊNH PIPELINE BRONZE -> SILVER (W05 POC)      ")
    print("==========================================================================")
    print(f"  - Tổng số bản ghi đầu vào đã đọc     : {engine.metrics.total_read}")
    print(f"  - Số bản ghi hợp lệ nạp vào Silver   : {engine.metrics.valid_silver_inserted}")
    print(f"      + silver_process_events          : {len(engine.silver_process)}")
    print(f"      + silver_file_events             : {len(engine.silver_file)}")
    print(f"      + silver_registry_events         : {len(engine.silver_registry)}")
    print(f"      + silver_network_events          : {len(engine.silver_network)}")
    print(f"  - Số bản ghi trùng lặp đã loại bỏ    : {engine.metrics.duplicates_dropped}")
    print(f"  - Số bản ghi lỗi đẩy vào Quarantine  : {engine.metrics.quarantined_count}")
    print(f"  - Cảnh báo lệch giờ (UtcTime Skew)   : {engine.metrics.time_skew_warnings}")
    print("--------------------------------------------------------------------------")
    print("  CHI TIẾT CÁC BẢN GHI TRONG QUARANTINE DLQ:")
    for q in engine.quarantine_dlq:
        print(f"    [x] {q.error_code:<28} | Nguồn: {q.source_reference} | Lý do: {q.error_reason}")

    run_duckdb_verification(engine)


if __name__ == "__main__":
    main()