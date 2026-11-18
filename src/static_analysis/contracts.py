"""Contracts W07 có version riêng, không thay Bronze/Silver. Chờ review Data/Cyber."""
from detection.schema import DETECTION_RESULT_SCHEMA
from .knowledge import KNOWLEDGE_SCHEMA


def obj(properties, required=None):
    return {"type": "object", "additionalProperties": False, "properties": properties,
            "required": list(properties) if required is None else required}


TEXT = {"type": "string"}
IDS = {"type": "array", "items": TEXT, "uniqueItems": True}
HASH = {"type": ["string", "null"], "pattern": "^[a-f0-9]{64}$"}
FEATURE = obj({"status": TEXT, "value": {"type": ["object", "null"]}})
STATIC_RESULT_SCHEMA = obj({
    "schema_version": {"const": "dacn-static/1.0"},
    "analysis_id": {"type": "string", "format": "uuid"},
    "observed_at": {"type": "string", "format": "date-time"},
    "extractor_version": {"const": "1.0"}, "path": TEXT, "source_event_ids": IDS,
    "status": {"enum": ["OK", "ERROR"]}, "error_code": {"type": ["string", "null"]},
    "sha256": HASH, "size_bytes": {"type": ["integer", "null"], "minimum": 0},
    "entropy": {"type": ["number", "null"], "minimum": 0, "maximum": 8.000000001},
    "file_identity": {"type": ["array", "null"], "items": {"type": "integer"}, "minItems": 5, "maxItems": 5},
    "pe": FEATURE, "signature": obj({"status": {"const": "UNAVAILABLE"}, "reason": TEXT}),
    "pattern_ids": IDS, "historical_identity": {"enum": ["UNVERIFIED", "HASH_VERIFIED"]}})
STATIC_RESULT_SCHEMA["allOf"] = [{"if": {"properties": {"status": {"const": "OK"}}},
                                    "then": {"properties": {"sha256": {"type": "string"},
                                                            "size_bytes": {"type": "integer"},
                                                            "entropy": {"type": "number"}, "error_code": {"type": "null"}}}}]
SIGNATURE_HIT_SCHEMA = obj({"schema_version": {"const": "dacn-signature-hit/1.0"},
                            "ioc_ids": IDS, "pattern_ids": IDS, "suppressed": {"type": "boolean"}})
WHITELIST_VERDICT_SCHEMA = obj({"schema_version": {"const": "dacn-whitelist-verdict/1.0"},
                                "knowledge_revision": HASH, "knowledge_version": {"type": "integer", "minimum": 1},
                                "verdict": {"enum": ["UNAVAILABLE", "ALLOWLISTED", "HIT", "NO_HIT"]},
                                "allowlist_ids": IDS, "signature_hit": SIGNATURE_HIT_SCHEMA,
                                "policy": {"const": "STATIC_ALLOWLIST_FIRST_BEHAVIOR_UNCHANGED"},
                                "evaluated_at": {"type": "string", "format": "date-time"}})
CANDIDATE_SCHEMA = obj({"schema_version": {"const": "dacn-candidate/1.0"},
                       "candidate_id": {"type": "string", "format": "uuid"},
                       "state": {"enum": ["NEW", "TRIAGED", "ALLOWLISTED", "SUSPICIOUS", "REJECTED"]},
                       "revision": {"type": "integer", "minimum": 1}, "created_by": TEXT,
                       "analysis": STATIC_RESULT_SCHEMA, "verdict": WHITELIST_VERDICT_SCHEMA,
                       "detection": DETECTION_RESULT_SCHEMA, "alert_ids": IDS,
                       "created_at": {"type": "string", "format": "date-time"}})
CONTRACTS = {"static-result": STATIC_RESULT_SCHEMA, "signature-hit": SIGNATURE_HIT_SCHEMA,
             "whitelist-verdict": WHITELIST_VERDICT_SCHEMA, "candidate": CANDIDATE_SCHEMA,
             "knowledge": KNOWLEDGE_SCHEMA}
