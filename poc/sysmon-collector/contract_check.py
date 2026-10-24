"""Field coverage check: raw samples -> Bronze contract -> Silver mapping (Week 5).

Input: Sysmon XML exports (*.xml), Bronze v1.0 segment files (*.jsonl), or collector PoC JSON output (*.json / *.jsonl).
Output: a Markdown report that shows, per Sysmon event id, which fields the mapping relies on are present,
which are missing or empty, which extra fields appear, and which targets do not exist in Silver yet.
Run it on real samples (e.g. references/samples) to replace the assumptions in the mapping tables with facts.

  python contract_check.py --samples references/samples --out coverage_report.md
"""
from __future__ import annotations

import argparse
import json
import sys
import xml.etree.ElementTree as ET
from collections import Counter, defaultdict
from pathlib import Path

import bronze_contract as bc
import sysmon_collector_poc as poc

# EventData name -> (target name, Silver status). Status per week_01_data_foundation_report.md section 3.1:
# "in_silver" = column exists, "missing_in_silver" = no column yet (Q-D6), "no_target" = no Silver table yet.
EXPECTED = {
    1: {"ProcessGuid": ("process_guid", "in_silver"), "ProcessId": ("pid", "in_silver"),
        "ParentProcessId": ("ppid", "in_silver"), "ParentProcessGuid": ("parent_guid", "in_silver"),
        "Image": ("image_path", "in_silver"), "CommandLine": ("command_line", "in_silver"),
        "CurrentDirectory": ("current_working_directory", "in_silver"), "User": ("user_name", "in_silver"),
        "Hashes": ("file_sha256", "in_silver"), "ParentImage": ("parent_image", "missing_in_silver"),
        "ParentCommandLine": ("parent_command_line", "missing_in_silver"),
        "IntegrityLevel": ("integrity_level", "missing_in_silver"),
        "TerminalSessionId": ("session_id", "missing_in_silver"), "UtcTime": ("(timestamp check)", "in_silver")},
    5: {"ProcessGuid": ("process_guid", "in_silver"), "ProcessId": ("pid", "in_silver"),
        "Image": ("image_path", "in_silver"), "UtcTime": ("end_time", "missing_in_silver")},
    3: {"ProcessGuid": ("process_guid", "in_silver"), "Protocol": ("protocol", "in_silver"),
        "Initiated": ("direction", "in_silver"), "SourceIp": ("source_ip", "in_silver"),
        "SourcePort": ("source_port", "in_silver"), "DestinationIp": ("dest_ip", "in_silver"),
        "DestinationPort": ("dest_port", "in_silver"), "DestinationIsIpv6": ("ip_version", "missing_in_silver"),
        "DestinationHostname": ("dest_hostname", "missing_in_silver")},
    22: {"ProcessGuid": ("process_guid", "in_silver"), "QueryName": ("dns_query_name", "missing_in_silver"),
         "QueryResults": ("dns_query_results", "missing_in_silver"),
         "QueryStatus": ("dns_query_status", "missing_in_silver")},
    11: {"ProcessGuid": ("process_guid", "in_silver"), "TargetFilename": ("file_path", "in_silver"),
         "Image": ("image_path", "missing_in_silver"), "CreationUtcTime": ("creation_utc_time", "missing_in_silver")},
    23: {"ProcessGuid": ("process_guid", "in_silver"), "TargetFilename": ("file_path", "in_silver"),
         "Hashes": ("file_sha256", "missing_in_silver"), "IsExecutable": ("is_executable", "missing_in_silver"),
         "Archived": ("archived", "missing_in_silver")},
    26: {"ProcessGuid": ("process_guid", "in_silver"), "TargetFilename": ("file_path", "in_silver"),
         "Hashes": ("file_sha256", "missing_in_silver"), "IsExecutable": ("is_executable", "missing_in_silver")},
    12: {"ProcessGuid": ("process_guid", "in_silver"), "EventType": ("operation", "missing_in_silver"),
         "TargetObject": ("target_object", "in_silver")},
    13: {"ProcessGuid": ("process_guid", "in_silver"), "EventType": ("operation", "missing_in_silver"),
         "TargetObject": ("target_object", "in_silver"), "Details": ("details", "in_silver")},
    14: {"ProcessGuid": ("process_guid", "in_silver"), "EventType": ("operation", "missing_in_silver"),
         "TargetObject": ("target_object", "in_silver"), "NewName": ("new_name", "missing_in_silver")},
    15: {"TargetFilename": ("(no Silver table)", "no_target"), "Hash": ("(no Silver table)", "no_target")},
    29: {"TargetFilename": ("(no Silver table)", "no_target"), "Hashes": ("(no Silver table)", "no_target")},
    4: {"State": ("(no Silver table)", "no_target")},
    16: {"Configuration": ("(no Silver table)", "no_target")},
}
EMPTY_VALUES = {"", "-"}


def _collect(paths: list) -> tuple:
    """Return (events, warnings). events = list of dicts: {event_id, data, bronze_errors}."""
    events, warnings = [], []
    for path in paths:
        suffix = path.suffix.lower()
        try:
            if suffix == ".xml":
                for raw in bc.iter_raw_xml_from_file(path):
                    try:
                        rec = bc.build_bronze_record(raw, mode="file", source_file=path.name)
                        events.append({"event_id": rec["sysmon_event_id"], "data": rec["event_data"],
                                       "bronze_errors": bc.validate_record(rec), "file": path.name})
                    except ValueError as exc:
                        warnings.append(f"{path.name}: {exc}")
            elif suffix in (".json", ".jsonl"):
                text = poc._read_text(path)
                items = ([json.loads(line) for line in text.splitlines() if line.strip()]
                         if suffix == ".jsonl" else json.loads(text))
                for item in items if isinstance(items, list) else [items]:
                    if not isinstance(item, dict):
                        warnings.append(f"{path.name}: non-object JSON item skipped")
                        continue
                    if "event_data" in item and "sysmon_event_id" in item:
                        # Bronze v1.0 record (from segment or build_bronze_record)
                        errs = bc.validate_record(item) if "raw_xml" in item else ["(Bronze JSON without raw_xml)"]
                        events.append({"event_id": item["sysmon_event_id"], "data": item["event_data"],
                                       "bronze_errors": errs, "file": path.name})
                    elif "raw_data" in item and "sysmon_event_id" in item:
                        # Collector PoC JSON output
                        events.append({"event_id": item["sysmon_event_id"], "data": item["raw_data"],
                                       "bronze_errors": ["(PoC JSON: no raw_xml, envelope not checked)"],
                                       "file": path.name})
                    elif "data" in item and isinstance(item.get("data"), dict) and isinstance(item.get("event_id"), int):
                        # Minimal Collector PoC W03 envelope output
                        events.append({"event_id": item["event_id"], "data": item["data"],
                                       "bronze_errors": ["(PoC W03 JSON: no raw_xml, envelope not checked)"],
                                       "file": path.name})
                    else:
                        warnings.append(f"{path.name}: record without event_data/raw_data/sysmon_event_id skipped")
        except (ET.ParseError, ValueError, OSError) as exc:
            warnings.append(f"{path.name}: cannot read ({exc})")
    return events, warnings


def build_report(events: list, warnings: list) -> str:
    by_id = defaultdict(list)
    for ev in events:
        by_id[ev["event_id"]].append(ev)
    out = ["# Field coverage report", "",
           f"Events analysed: {len(events)} across Sysmon event ids {sorted(by_id)}", ""]
    envelope_bad = sum(1 for e in events if e["bronze_errors"] and not e["bronze_errors"][0].startswith("("))
    out.append(f"Envelope (Bronze schema) violations: {envelope_bad}")
    out.append("")
    for eid in sorted(by_id):
        items = by_id[eid]
        expected = EXPECTED.get(eid, {})
        seen = Counter()
        empty = Counter()
        for it in items:
            for name, value in it["data"].items():
                seen[name] += 1
                if value in EMPTY_VALUES:
                    empty[name] += 1
        out += [f"## Sysmon event {eid} ({len(items)} sample(s))", "",
                "| EventData field | Silver target | Silver status | Present | Empty or '-' |", "|---|---|---|---|---|"]
        for name, (target, status) in expected.items():
            out.append(f"| {name} | {target} | {status} | {seen[name]}/{len(items)} | {empty[name]} |")
        extra = sorted(n for n in seen if n not in expected)
        out.append("")
        out.append("Extra fields seen (no mapping yet): " + (", ".join(extra) if extra else "none"))
        if not expected:
            out.append("(no mapping defined for this event id)")
        out.append("")
    if warnings:
        out += ["## Warnings", ""] + [f"- {w}" for w in warnings] + [""]
    return "\n".join(out)


def main(argv=None) -> int:
    ap = argparse.ArgumentParser(description="Check raw samples against the Bronze contract and Silver mapping")
    ap.add_argument("--samples", type=Path, required=True, help="file or directory (xml, json, jsonl)")
    ap.add_argument("--out", type=Path, help="write the Markdown report here")
    args = ap.parse_args(argv)
    paths = sorted(p for p in ([args.samples] if args.samples.is_file() else args.samples.rglob("*"))
                   if p.is_file() and p.suffix.lower() in (".xml", ".json", ".jsonl"))
    if not paths:
        print(f"No samples found under {args.samples}", file=sys.stderr)
        return 2
    events, warnings = _collect(paths)
    report = build_report(events, warnings)
    if args.out:
        args.out.write_text(report, encoding="utf-8")
        print(f"Report written to {args.out} ({len(events)} events)")
    else:
        print(report)
    return 0


if __name__ == "__main__":
    sys.exit(main())