"""Bronze record contract v1: reference builder and validator (Week 5 design support).

Builds the record described in contracts/bronze-event.schema.json from a raw Sysmon event XML string.
This is a DESIGN-LEVEL reference: it is tested on SYNTHETIC events and has not run on a real Windows host.
It keeps the original XML text and the original EventData names, and does no semantic mapping
(mapping to Silver stays in the Silver transform owned by Data).
"""
from __future__ import annotations

import json
import re
import uuid
import xml.etree.ElementTree as ET
from datetime import datetime, timezone
from pathlib import Path
from typing import Iterator, Optional

import sysmon_collector_poc as poc

SCHEMA_VERSION = "bronze-event/1.0"
COLLECTOR_NAME = "sysmon_collector_poc"
COLLECTOR_VERSION = "0.2.0-contract"
SCHEMA_PATH = Path(__file__).parent / "contracts" / "bronze-event.schema.json"
# Fixed namespace: the same computer name always gives the same host_id (Phase 1 is a single host).
HOST_NAMESPACE = uuid.UUID("0b8f6c3e-5d21-4a7e-8f10-9c2d4e6a1b73")

_EVENT_RE = re.compile(r"<Event\b.*?</Event>", re.S)


def split_event_xml(text: str) -> list:
    """Split wevtutil / Get-WinEvent output into the original <Event>...</Event> strings."""
    cleaned = re.sub(r"<\?xml[^>]*\?>", "", text)
    cleaned = re.sub(r"<!--.*?-->", "", cleaned, flags=re.S)
    return _EVENT_RE.findall(cleaned)


def iter_raw_xml_from_file(path: Path) -> Iterator[str]:
    yield from split_event_xml(poc._read_text(Path(path)))


def host_id_for(computer: str) -> str:
    return str(uuid.uuid5(HOST_NAMESPACE, computer.strip().lower()))


def _now_utc() -> str:
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%S.%fZ")


def _system_metadata(ev: ET.Element) -> dict:
    ns = poc.NS
    system = ev.find("e:System", ns)
    use_ns = True
    if system is None:
        system = ev.find("System")
        use_ns = False
    if system is None:
        raise ValueError("C-002 missing System element")

    def find_node(tag: str) -> Optional[ET.Element]:
        return system.find(f"e:{tag}", ns) if use_ns else system.find(tag)

    def text(tag: str) -> Optional[str]:
        node = find_node(tag)
        return node.text if node is not None else None

    provider = find_node("Provider")
    execution = find_node("Execution")
    return {
        "provider": {"name": provider.get("Name") if provider is not None else None,
                     "guid": provider.get("Guid") if provider is not None else None},
        "event_version": poc._int(text("Version")),
        "level": poc._int(text("Level")),
        "task": poc._int(text("Task")),
        "opcode": poc._int(text("Opcode")),
        "keywords": text("Keywords"),
        "writer_process_id": poc._int(execution.get("ProcessID")) if execution is not None else None,
        "writer_thread_id": poc._int(execution.get("ThreadID")) if execution is not None else None,
    }


def build_bronze_record(raw_xml: str, *, mode: str, collected_at: Optional[str] = None,
                        source_file: Optional[str] = None, batch_id: Optional[str] = None,
                        seq: Optional[int] = None) -> dict:
    """Raise ValueError when the XML cannot form a valid envelope (collector error C-001/C-002)."""
    try:
        ev = ET.fromstring(raw_xml)
    except ET.ParseError as exc:
        raise ValueError(f"C-001 XML not well-formed: {exc}") from exc
    parsed = poc._parse_event_element(ev)
    s = parsed["system"]
    for name in ("record_id", "channel", "computer", "event_id", "time_created"):
        if s.get(name) in (None, ""):
            raise ValueError(f"C-002 missing System field: {name}")
    meta = _system_metadata(ev)
    key = f"{s['computer']}|{s['channel']}|{s['record_id']}"
    return {
        "schema_version": SCHEMA_VERSION,
        "event_id": str(uuid.uuid5(poc.EVENT_ID_NAMESPACE, key)),
        "source": "SYSMON",
        "channel": s["channel"],
        "provider": meta["provider"],
        "sysmon_event_id": s["event_id"],
        "event_version": meta["event_version"],
        "level": meta["level"],
        "task": meta["task"],
        "opcode": meta["opcode"],
        "keywords": meta["keywords"],
        "record_id": s["record_id"],
        "time_created": s["time_created"],
        "writer_process_id": meta["writer_process_id"],
        "writer_thread_id": meta["writer_thread_id"],
        "log_writer_sid": s["user_sid"],
        "hostname": s["computer"],
        "host_id": host_id_for(s["computer"]),
        "event_data": parsed["data"],
        "raw_xml": raw_xml,
        "ingest": {
            "collector": {"name": COLLECTOR_NAME, "version": COLLECTOR_VERSION},
            "mode": mode,
            "collected_at": collected_at or _now_utc(),
            "source_file": source_file,
            "batch_id": batch_id,
            "seq": seq,
        },
    }


def load_schema() -> dict:
    return json.loads(SCHEMA_PATH.read_text(encoding="utf-8"))


def validate_record(record: dict) -> list:
    """Return a list of readable schema violations (empty list = valid)."""
    from jsonschema import Draft202012Validator
    validator = Draft202012Validator(load_schema())
    errors = sorted(validator.iter_errors(record), key=lambda e: list(e.path))
    return [f"{'/'.join(str(p) for p in e.path) or '<root>'}: {e.message}" for e in errors]