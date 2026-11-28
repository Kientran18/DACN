"""Ánh xạ logsource/field Sigma -> bảng và cột Silver CÓ THẬT của DACN (bảng đầy đủ: docs/implementation/SIGMA_RULES.md).

- Sysmon: field Sigma trùng tên field EventData gốc của Sysmon; Silver giữ nguyên EventData trong cột `raw_data` (JSON), nên
  field được đọc từ `raw_data` theo đúng tên, không cần cột mới. Danh sách field theo từng Event ID lấy từ schema Sysmon
  (v15, đã đối chiếu tên với mẫu XML thật Event 1 trong references/samples). Field không có trong Event ID của hàng là
  "không áp dụng" (điều kiện trên nó là sai), khác với field có trong schema nhưng vắng trong hàng (chưa biết).
- Defender (service windefend): DDL v1.3 đề xuất, cột kiểu hóa; chỉ các Event ID đang thu thập.
- PowerShell 4104 (category ps_script / service powershell): script block ĐÃ GHÉP như DACN-DET-203.
"""
from __future__ import annotations

import windows_channels as wc

_SYSMON_COMMON = ("EventID", "RuleName", "UtcTime", "ProcessGuid", "ProcessId", "Image", "User")
SYSMON_FIELDS = {
    1: _SYSMON_COMMON + ("FileVersion", "Description", "Product", "Company", "OriginalFileName", "CommandLine",
                         "CurrentDirectory", "LogonGuid", "LogonId", "TerminalSessionId", "IntegrityLevel", "Hashes",
                         "ParentProcessGuid", "ParentProcessId", "ParentImage", "ParentCommandLine", "ParentUser"),
    3: _SYSMON_COMMON + ("Protocol", "Initiated", "SourceIsIpv6", "SourceIp", "SourceHostname", "SourcePort",
                         "SourcePortName", "DestinationIsIpv6", "DestinationIp", "DestinationHostname", "DestinationPort",
                         "DestinationPortName"),
    11: _SYSMON_COMMON + ("TargetFilename", "CreationUtcTime"),
    12: _SYSMON_COMMON + ("EventType", "TargetObject"),
    13: _SYSMON_COMMON + ("EventType", "TargetObject", "Details"),
    14: _SYSMON_COMMON + ("EventType", "TargetObject", "NewName"),
    22: _SYSMON_COMMON + ("QueryName", "QueryStatus", "QueryResults"),
}

# category Sigma -> (bảng Silver, Event ID Sysmon, bộ lọc ngầm theo EventType như pipeline Sysmon của Sigma)
SYSMON_CATEGORIES = {
    "process_creation": ("silver_process_events", (1,), None),
    "file_event": ("silver_file_events", (11,), None),
    "registry_event": ("silver_registry_events", (12, 13, 14), None),
    "registry_set": ("silver_registry_events", (13,), None),
    "registry_add": ("silver_registry_events", (12,), ("CreateKey",)),
    "registry_delete": ("silver_registry_events", (12,), ("DeleteKey", "DeleteValue")),
    "registry_rename": ("silver_registry_events", (14,), None),
    "network_connection": ("silver_network_events", (3,), None),
    "dns_query": ("silver_network_events", (22,), None),
}

# Field Sigma của windefend -> cột silver_defender_events (DDL v1.3 đề xuất). Field khác bị từ chối (SIG-E003).
DEFENDER_FIELDS = {"EventID": "windows_event_id", "NewValue": "new_value", "OldValue": "old_value",
                   "ProcessName": "process_name", "SourceName": "source_name", "Path": "path_raw",
                   "ThreatName": "threat_name", "ThreatID": "threat_id", "SeverityName": "severity_name",
                   "CategoryName": "category_name", "ActionName": "action_name", "DetectionID": "detection_id"}
DEFENDER_EVENT_IDS = tuple(wc.SUPPORTED_EVENT_IDS[wc.DEFENDER_CHANNEL])

# Field Sigma của script block 4104. ScriptBlockText là văn bản đã ghép: NHẠY CẢM, không chép vào alert.
SCRIPT_FIELDS = ("EventID", "ScriptBlockText", "Path", "ScriptBlockId", "MessageTotal")   # MessageNumber: không có nghĩa sau khi ghép
SENSITIVE_FIELDS = ("ScriptBlockText",)


def resolve_logsource(ls: dict):
    """Trả spec JSON được: {kind, table, event_ids, fields, event_type_filter} hoặc None nếu không hỗ trợ."""
    if not isinstance(ls, dict) or ls.get("product") != "windows":
        return None
    cat, svc = ls.get("category"), ls.get("service")
    if cat in SYSMON_CATEGORIES and svc in (None, "sysmon"):
        table, ids, etf = SYSMON_CATEGORIES[cat]
        fields = sorted(set().union(*(SYSMON_FIELDS[i] for i in ids)))
        return {"kind": "sysmon", "table": table, "event_ids": list(ids), "fields": fields,
                "event_type_filter": list(etf) if etf else None}
    if (cat == "ps_script" and svc in (None, "powershell")) or (cat is None and svc == "powershell"):
        return {"kind": "scriptblock", "table": "silver_powershell_scriptblock_events", "event_ids": [4104],
                "fields": list(SCRIPT_FIELDS), "event_type_filter": None}
    if cat is None and svc == "windefend":
        return {"kind": "defender", "table": "silver_defender_events", "event_ids": list(DEFENDER_EVENT_IDS),
                "fields": sorted(DEFENDER_FIELDS), "event_type_filter": None}
    return None


def defined_fields(spec: dict, event_id: int) -> set:
    """Field định nghĩa cho MỘT hàng có Event ID này (Sysmon: theo schema của Event ID đó)."""
    if spec["kind"] == "sysmon":
        return set(SYSMON_FIELDS[event_id])
    return set(spec["fields"])
