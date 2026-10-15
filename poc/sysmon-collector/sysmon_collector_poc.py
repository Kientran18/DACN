"""Minimal Sysmon event collector PoC (Issue #16).

Reads Sysmon events either live from the Windows Event Log (pywin32, Windows only) or from
XML exported by `wevtutil` / `Get-WinEvent`, and writes normalized JSON.

Status
- File mode and the parser/normalizer are unit-tested on SYNTHETIC events (see test file).
- Live mode has NOT been run on a real Windows machine yet.
- No bookmark, no follow/subscribe mode, no enrichment: this is a PoC, not the production collector.

Usage
  python sysmon_collector_poc.py --mode file --input samples/raw/recent_events_all.xml \
      --event-id 1 --max 20 --output samples/json/process_events.json
  python sysmon_collector_poc.py --mode live --event-id 1 --max 20 --output samples/json/process_events.json
"""
from __future__ import annotations

import argparse
import json
import ntpath
import re
import sys
import uuid
import xml.etree.ElementTree as ET
from collections import Counter
from pathlib import Path
from typing import Iterator, Optional

NS = {"e": "http://schemas.microsoft.com/win/2004/08/events/event"}
SYSMON_CHANNEL = "Microsoft-Windows-Sysmon/Operational"
# Fixed namespace so the same (computer, channel, record id) always gives the same event_id.
EVENT_ID_NAMESPACE = uuid.UUID("6f1d3c52-8a0e-4b7a-9c1e-3d5a7b9e2f10")

# Event type names follow the Data envelope (edr_data_requirements_architecture.md section 3.1).
# Pending team decision Q-X3: Cyber uses different names (PROCESS_CREATE, REGISTRY_SET, ...).
STATIC_EVENT_TYPES = {
    1: "PROCESS_START",
    5: "PROCESS_TERMINATE",
    11: "FILE_CREATE",
    22: "DNS_QUERY",
    23: "FILE_DELETE",
    26: "FILE_DELETE",
    15: "FILE_STREAM_CREATE",
    29: "FILE_EXECUTABLE_DETECTED",
    4: "SYSMON_SERVICE_STATE",
    16: "SYSMON_CONFIG_CHANGE",
}
REGISTRY_TYPES = {
    "CreateKey": "REGISTRY_CREATE_KEY",
    "DeleteKey": "REGISTRY_DELETE_KEY",
    "DeleteValue": "REGISTRY_DELETE_VALUE",
    "SetValue": "REGISTRY_SET_VALUE",
    "RenameKey": "REGISTRY_RENAME_KEY",
}


# ----------------------------------------------------------------------------- parsing
def _int(value: Optional[str]) -> Optional[int]:
    try:
        return int(value) if value not in (None, "") else None
    except ValueError:
        return None


def strip_guid(value: Optional[str]) -> Optional[str]:
    """Remove the braces Sysmon puts around GUIDs; keep the original case."""
    return value.strip().strip("{}") if value else None


def parse_hashes(value: Optional[str]) -> dict:
    """'SHA256=ABC,IMPHASH=DEF' -> {'sha256': 'ABC', 'imphash': 'DEF'}"""
    out = {}
    for part in (value or "").split(","):
        if "=" in part:
            key, val = part.split("=", 1)
            out[key.strip().lower()] = val.strip()
    return out


def _parse_event_element(ev: ET.Element) -> dict:
    system = ev.find("e:System", NS)
    if system is None:
        raise ValueError("Event XML has no <System> element")

    def text(tag: str) -> Optional[str]:
        node = system.find(f"e:{tag}", NS)
        return node.text if node is not None else None

    time_created = system.find("e:TimeCreated", NS)
    provider = system.find("e:Provider", NS)
    security = system.find("e:Security", NS)
    event_id = _int(text("EventID"))
    if event_id is None or time_created is None:
        raise ValueError("Event XML is missing EventID or TimeCreated")

    data = {}
    event_data = ev.find("e:EventData", NS)
    if event_data is not None:
        for node in event_data.findall("e:Data", NS):
            name = node.get("Name")
            if name:
                data[name] = node.text or ""

    return {
        "system": {
            "provider": provider.get("Name") if provider is not None else None,
            "event_id": event_id,
            "version": _int(text("Version")),
            "time_created": time_created.get("SystemTime"),
            "record_id": _int(text("EventRecordID")),
            "channel": text("Channel"),
            "computer": text("Computer"),
            "user_sid": security.get("UserID") if security is not None else None,
        },
        "data": data,
    }


def parse_event_xml(xml_text: str) -> dict:
    """Parse one <Event> XML string."""
    return _parse_event_element(ET.fromstring(xml_text))


def _read_text(path: Path) -> str:
    raw = path.read_bytes()
    if raw.startswith((b"\xff\xfe", b"\xfe\xff")):
        return raw.decode("utf-16")
    return raw.decode("utf-8-sig")


def iter_events_from_xml_text(text: str) -> Iterator[dict]:
    """wevtutil / Get-WinEvent output is a series of <Event> elements without a root: wrap them."""
    cleaned = re.sub(r"<\?xml[^>]*\?>", "", text)
    root = ET.fromstring(f"<Events>{cleaned}</Events>")
    for ev in root:
        yield _parse_event_element(ev)


def iter_events_from_file(path: Path) -> Iterator[dict]:
    yield from iter_events_from_xml_text(_read_text(path))


def iter_events_live(channel: str = SYSMON_CHANNEL, event_ids: Optional[list] = None, max_events: int = 50) -> Iterator[dict]:
    """Newest-first read of the event log. Needs pywin32 and (usually) Administrator rights."""
    try:
        import win32evtlog  # type: ignore
    except ImportError as exc:
        raise RuntimeError("Live mode needs pywin32 on Windows: pip install pywin32") from exc

    query = "*"
    if event_ids:
        cond = " or ".join(f"EventID={i}" for i in event_ids)
        query = f"*[System[({cond})]]"
    flags = win32evtlog.EvtQueryChannelPath | win32evtlog.EvtQueryReverseDirection
    try:
        handle = win32evtlog.EvtQuery(channel, flags, query, None)
        count = 0
        while count < max_events:
            events = win32evtlog.EvtNext(handle, min(20, max_events - count))
            if not events:
                break
            for ev in events:
                xml_text = win32evtlog.EvtRender(ev, win32evtlog.EvtRenderEventXml)
                yield _parse_event_element(ET.fromstring(xml_text))
                count += 1
    except Exception as exc:  # pywintypes.error is (winerror, function, message)
        if exc.args and exc.args[0] == 5:
            raise PermissionError(f"Access denied reading '{channel}': run as Administrator") from exc
        raise


# ------------------------------------------------------------------------ normalization
def _event_type(event_id: int, data: dict) -> str:
    if event_id == 3:
        return "NETWORK_CONNECT" if data.get("Initiated", "").lower() == "true" else "NETWORK_ACCEPT"
    if event_id in (12, 13, 14):
        return REGISTRY_TYPES.get(data.get("EventType", ""), "REGISTRY_EVENT")
    return STATIC_EVENT_TYPES.get(event_id, f"SYSMON_EVENT_{event_id}")


def split_registry_target(target: str, operation: str) -> dict:
    """'HKU\\S-1-5-21-...\\Software\\X\\Name' -> hive / key_path / value_name (heuristic)."""
    parts = target.split("\\") if target else []
    hive = parts[0] if parts else None
    rest = parts[1:]
    value_name = None
    if operation in ("SetValue", "DeleteValue") and rest:
        value_name = rest[-1]
        rest = rest[:-1]
    return {"hive": hive, "key_path": "\\".join(rest), "value_name": value_name}


def infer_registry_value_type(details: str) -> str:
    """Heuristic only: Sysmon prints the value as text, so SZ / EXPAND_SZ / MULTI_SZ cannot be told apart."""
    if details.startswith("DWORD ("):
        return "REG_DWORD"
    if details.startswith("QWORD ("):
        return "REG_QWORD"
    if details.startswith("Binary Data"):
        return "REG_BINARY"
    return "STRING_UNSPECIFIED"


def _map_data(event_id: int, d: dict) -> dict:
    if event_id == 1:
        hashes = parse_hashes(d.get("Hashes"))
        return {
            "pid": _int(d.get("ProcessId")),
            "ppid": _int(d.get("ParentProcessId")),
            "parent_guid": strip_guid(d.get("ParentProcessGuid")),
            "image_path": d.get("Image"),
            "command_line": d.get("CommandLine"),
            "current_working_directory": d.get("CurrentDirectory"),
            "user_name": d.get("User"),
            "integrity_level": d.get("IntegrityLevel"),
            "session_id": _int(d.get("TerminalSessionId")),
            "parent_image": d.get("ParentImage"),
            "parent_command_line": d.get("ParentCommandLine"),
            "hashes": hashes,
            "file_sha256": hashes.get("sha256"),
        }
    if event_id == 5:
        return {"pid": _int(d.get("ProcessId")), "image_path": d.get("Image")}
    if event_id == 3:
        return {
            "protocol": (d.get("Protocol") or "").upper(),
            "direction": "OUTBOUND" if d.get("Initiated", "").lower() == "true" else "INBOUND",
            "src_ip": d.get("SourceIp"),
            "src_port": _int(d.get("SourcePort")),
            "dest_ip": d.get("DestinationIp"),
            "dest_port": _int(d.get("DestinationPort")),
            "ip_version": "IPv6" if d.get("DestinationIsIpv6", "").lower() == "true" else "IPv4",
            "image_path": d.get("Image"),
        }
    if event_id == 22:
        return {
            "dns_query_name": d.get("QueryName"),
            "query_status": d.get("QueryStatus"),
            "query_results": d.get("QueryResults"),
            "image_path": d.get("Image"),
        }
    if event_id in (11, 15, 23, 26, 29):
        path = d.get("TargetFilename") or ""
        hashes = parse_hashes(d.get("Hashes") or d.get("Hash"))
        out = {
            "file_path": path,
            "file_extension": ntpath.splitext(path)[1].lower().lstrip(".") or None,
            "image_path": d.get("Image"),
            "hashes": hashes,
            "file_sha256": hashes.get("sha256"),
        }
        if "IsExecutable" in d:
            out["is_executable"] = d["IsExecutable"].lower() == "true"
        if "Archived" in d:
            out["archived"] = d["Archived"].lower() == "true"
        return out
    if event_id in (12, 13, 14):
        operation = d.get("EventType", "")
        details = d.get("Details", "")
        out = {"operation": operation, "target_object": d.get("TargetObject"), "details": details,
               "image_path": d.get("Image")}
        out.update(split_registry_target(d.get("TargetObject", ""), operation))
        if operation == "SetValue":
            out["value_type_inferred"] = infer_registry_value_type(details)
            out["new_data_str"] = details
        return out
    if event_id == 4:
        return {"state": d.get("State"), "version": d.get("Version")}
    if event_id == 16:
        return {"configuration": d.get("Configuration"), "configuration_file_hash": d.get("ConfigurationFileHash")}
    return {}


def normalize(parsed: dict) -> dict:
    s, d = parsed["system"], parsed["data"]
    key = f"{s['computer']}|{s['channel']}|{s['record_id']}"
    return {
        "event_id": str(uuid.uuid5(EVENT_ID_NAMESPACE, key)),
        "timestamp": s["time_created"],
        "source": "SYSMON",
        "event_type": _event_type(s["event_id"], d),
        "sysmon_event_id": s["event_id"],
        "channel": s["channel"],
        "record_id": s["record_id"],
        "hostname": s["computer"],
        "process_guid": strip_guid(d.get("ProcessGuid")),
        "data": _map_data(s["event_id"], d),
        "raw_data": d,
    }


# -------------------------------------------------------------------------------- CLI
def main(argv: Optional[list] = None) -> int:
    ap = argparse.ArgumentParser(description="Minimal Sysmon collector PoC")
    ap.add_argument("--mode", choices=["live", "file"], default="file")
    ap.add_argument("--input", type=Path, help="XML exported by wevtutil / Get-WinEvent (file mode)")
    ap.add_argument("--channel", default=SYSMON_CHANNEL)
    ap.add_argument("--event-id", type=int, action="append", help="repeatable; default: all")
    ap.add_argument("--max", type=int, default=50, dest="max_events")
    ap.add_argument("--output", type=Path, required=True)
    ap.add_argument("--format", choices=["json", "jsonl"], default="json")
    args = ap.parse_args(argv)

    if args.mode == "file":
        if not args.input:
            ap.error("--input is required in file mode")
        source = iter_events_from_file(args.input)
    else:
        source = iter_events_live(args.channel, args.event_id, args.max_events)

    wanted = set(args.event_id or [])
    events = []
    for parsed in source:
        if wanted and parsed["system"]["event_id"] not in wanted:
            continue
        events.append(normalize(parsed))
        if len(events) >= args.max_events:
            break

    args.output.parent.mkdir(parents=True, exist_ok=True)
    with args.output.open("w", encoding="utf-8") as fh:
        if args.format == "jsonl":
            for ev in events:
                fh.write(json.dumps(ev, ensure_ascii=False) + "\n")
        else:
            json.dump(events, fh, indent=2, ensure_ascii=False)

    counts = Counter(ev["sysmon_event_id"] for ev in events)
    print(f"Wrote {len(events)} event(s) to {args.output}  by Sysmon event id: {dict(sorted(counts.items()))}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
