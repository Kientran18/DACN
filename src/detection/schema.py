"""Schema rule và DetectionResult (PH4-T01/T02). Đề xuất — cần Cyber/Data duyệt (#38, #39)."""
import windows_channels as wc

OUTCOMES = ("MATCH", "NO_MATCH", "INSUFFICIENT_TELEMETRY", "PENDING_LATE_EVENTS")
OPS = ("equals", "contains_any", "endswith_any", "startswith_any", "regex")
# Bảng Silver chứa từng Sysmon Event ID (khớp cách validator_poc định tuyến SUPPORTED_SYSMON_IDS).
SILVER_TABLE_FOR_EVENT = {1: "silver_process_events", 5: "silver_process_events",
                          11: "silver_file_events", 15: "silver_file_events", 23: "silver_file_events",
                          26: "silver_file_events", 29: "silver_file_events",
                          12: "silver_registry_events", 13: "silver_registry_events", 14: "silver_registry_events",
                          3: "silver_network_events", 22: "silver_network_events"}
# Kênh không phải Sysmon (DDL v1.3 đề xuất, docs/architecture/w8 mục 5.1): rule khai `source_events`, cột ID là windows_event_id.
SILVER_TABLE_FOR_CHANNEL = {wc.DEFENDER_CHANNEL: "silver_defender_events",
                            wc.POWERSHELL_CHANNEL: "silver_powershell_scriptblock_events"}
DETECTION_SOURCES = ("EXTERNAL_DEFENDER",)     # alert phản ánh phát hiện của sản phẩm khác (D7); mặc định RULE/IOC

_COND = {
    "type": "object", "additionalProperties": False, "required": ["field", "op", "value"],
    "properties": {"field": {"type": "string", "pattern": "^[a-z_]+$"},
                   "op": {"enum": list(OPS)},
                   "value": {"oneOf": [{"type": "string"}, {"type": "array", "items": {"type": "string"}, "minItems": 1}]}},
}

RULE_SCHEMA = {
    "type": "object", "additionalProperties": False,
    "required": ["rule_id", "rule_version", "name", "type", "severity", "status", "description"],
    "properties": {
        "rule_id": {"type": "string", "pattern": r"^DACN-DET-\d{3}$"},
        "legacy_id": {"type": "string", "pattern": r"^DET-\d{3}$"},
        "rule_version": {"type": "integer", "minimum": 1},
        "name": {"type": "string"},
        "description": {"type": "string"},
        "type": {"enum": ["single", "correlation", "ioc"]},
        "status": {"enum": ["enabled", "disabled", "blocked", "candidate"]},
        "blocked_reason": {"type": "string"},
        "severity": {"enum": ["low", "medium", "high", "critical"]},
        "severity_reason": {"type": "string"},
        "sysmon_event_ids": {"type": "array", "items": {"type": "integer"}, "minItems": 1},
        # Kênh Windows khác Sysmon (w8 mục 5.1). Rule chỉ khai MỘT trong hai: sysmon_event_ids hoặc source_events.
        "source_events": {"type": "array", "minItems": 1, "items": {
            "type": "object", "additionalProperties": False, "required": ["channel", "event_ids"],
            "properties": {"channel": {"type": "string"},
                           "event_ids": {"type": "array", "items": {"type": "integer"}, "minItems": 1}}}},
        # Severity theo giá trị một trường của hàng (khóa so sánh dạng chuỗi); không khớp -> `severity` của rule.
        "severity_by": {"type": "object", "additionalProperties": False, "required": ["field", "map"],
                        "properties": {"field": {"type": "string", "pattern": "^[a-z_]+$"},
                                       "map": {"type": "object", "minProperties": 1, "additionalProperties": {
                                           "enum": ["low", "medium", "high", "critical"]}}}},
        # Trường ngữ cảnh chép vào matched_fields["context"] khi MATCH (chỉ trường có giá trị; không phải điều kiện khớp).
        "context_fields": {"type": "array", "items": {"type": "string", "pattern": "^[a-z_]+$"}},
        # Trường dùng gom alert (mặc định process_guid). Kênh không có process_guid cần trường khác, ví dụ detection_id.
        "group_by_field": {"type": "string", "pattern": "^[a-z_]+$"},
        "detection_source": {"enum": list(DETECTION_SOURCES)},
        "required_fields": {"type": "array", "items": {"type": "string"}},
        "match": {"type": "object", "additionalProperties": False,
                  "properties": {"all": {"type": "array", "items": _COND},
                                 "any": {"type": "array", "items": _COND}}},
        "exclude": {"type": "array", "items": _COND},
        "correlation_keys": {"type": "array", "items": {"type": "string"}},
        "time_window_seconds": {"type": "integer", "minimum": 1},
        "allowed_lateness_seconds": {"type": "integer", "minimum": 0, "maximum": 86400},
        "window_status": {"enum": ["TBD_UNCALIBRATED", "CALIBRATED"]},
        "mitre_technique_ids": {"type": "array", "items": {"type": "string", "pattern": r"^T\d{4}(\.\d{3})?$"}},
        "mitre_basis": {"type": "string"},
        "false_positives": {"type": "array", "items": {"type": "string"}},
        "limitations": {"type": "array", "items": {"type": "string"}},
        "validation_status": {"enum": ["synthetic_only", "lab_verified"]},
        "response_policy": {"enum": ["alert_only"], "default": "alert_only"},
    },
}

DETECTION_RESULT_SCHEMA = {
    "type": "object", "additionalProperties": False,
    "required": ["rule_id", "rule_version", "outcome", "subject", "contributing_event_ids",
                 "matched_fields", "missing_fields", "coverage_status", "severity", "severity_reason", "dedup_key"],
    "properties": {
        "rule_id": {"type": "string"}, "rule_version": {"type": "integer"},
        "outcome": {"enum": list(OUTCOMES)}, "subject": {"type": "string"},
        "contributing_event_ids": {"type": "array", "items": {"type": "string"}},
        "matched_fields": {"type": "object"}, "missing_fields": {"type": "array", "items": {"type": "string"}},
        "coverage_status": {"type": "string"}, "severity": {"type": ["string", "null"]},
        "severity_reason": {"type": "string"}, "dedup_key": {"type": "string"},
        "notes": {"type": "array", "items": {"type": "string"}},
    },
}
