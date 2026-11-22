"""Schema rule và DetectionResult (PH4-T01/T02). Đề xuất — cần Cyber/Data duyệt (#38, #39)."""
OUTCOMES = ("MATCH", "NO_MATCH", "INSUFFICIENT_TELEMETRY", "PENDING_LATE_EVENTS")
OPS = ("equals", "contains_any", "endswith_any", "startswith_any", "regex")
# Bảng Silver chứa từng Sysmon Event ID (khớp cách validator_poc định tuyến SUPPORTED_SYSMON_IDS).
SILVER_TABLE_FOR_EVENT = {1: "silver_process_events", 5: "silver_process_events",
                          11: "silver_file_events", 15: "silver_file_events", 23: "silver_file_events",
                          26: "silver_file_events", 29: "silver_file_events",
                          12: "silver_registry_events", 13: "silver_registry_events", 14: "silver_registry_events",
                          3: "silver_network_events", 22: "silver_network_events"}

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
