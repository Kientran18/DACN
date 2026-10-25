"""Reference bridge: canonical Bronze v1.0 -> W05 SilverValidatorEngine input.

Design PoC only: it does not write DuckDB, segments, bookmarks or manifests.
Source-of-truth remains event_data/raw_xml. Do not invent absent event fields.
"""
from __future__ import annotations

import uuid
from typing import Any

import bronze_contract as bc
import sysmon_collector_poc as poc


def to_silver_input(record: dict[str, Any]) -> dict[str, Any]:
    """Validate one canonical Bronze event and adapt field names for Data W05."""
    errors = bc.validate_record(record)
    if errors:
        raise ValueError("INVALID_BRONZE_ENVELOPE: " + "; ".join(errors))

    # Fail closed on mismatched identity; do not normalize a forged event id.
    natural_key = f"{record['hostname']}|{record['channel']}|{record['record_id']}"
    expected = str(uuid.uuid5(poc.EVENT_ID_NAMESPACE, natural_key))
    if record["event_id"] != expected:
        raise ValueError("BRONZE_IDENTITY_MISMATCH: event_id differs from natural key")
    if record["host_id"] != bc.host_id_for(record["hostname"]):
        raise ValueError("BRONZE_IDENTITY_MISMATCH: host_id differs from hostname")

    parsed = poc.parse_event_xml(record["raw_xml"])
    system = parsed["system"]
    expected_system = {
        "computer": record["hostname"],
        "channel": record["channel"],
        "record_id": record["record_id"],
        "event_id": record["sysmon_event_id"],
        "time_created": record["time_created"],
    }
    for field, expected_value in expected_system.items():
        if system[field] != expected_value:
            raise ValueError(f"BRONZE_RAW_MISMATCH: {field}")
    if parsed["data"] != record["event_data"]:
        raise ValueError("BRONZE_RAW_MISMATCH: event_data")

    source = {
        "schema_version": record["schema_version"],
        "source_file": record["ingest"].get("source_file"),
        "batch_id": record["ingest"].get("batch_id"),
        "seq": record["ingest"].get("seq"),
    }
    data = record["event_data"]
    return {
        "timestamp": record["time_created"],
        "source": record["source"],
        "sysmon_event_id": record["sysmon_event_id"],
        "event_type": poc._event_type(record["sysmon_event_id"], data),
        "event_id": record["event_id"],
        "channel": record["channel"],
        "record_id": record["record_id"],
        "hostname": record["hostname"],
        "process_guid": data.get("ProcessGuid"),  # may be absent on Sysmon 4/16
        "raw_data": dict(data),
        "bronze_source": source,  # reference metadata, NOT a persisted Silver column yet
    }
