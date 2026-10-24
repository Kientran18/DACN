"""Tests for the Bronze contract reference code. Input is SYNTHETIC (fixtures/synthetic_events.xml)."""
import json
from pathlib import Path

import pytest

import bronze_contract as bc
import contract_check as cc
import sysmon_collector_poc as poc

FIXTURE = Path(__file__).parent / "fixtures" / "synthetic_events.xml"


@pytest.fixture(scope="module")
def raw_events():
    return list(bc.iter_raw_xml_from_file(FIXTURE))


def test_split_keeps_original_text(raw_events):
    assert len(raw_events) == 4
    text = FIXTURE.read_text(encoding="utf-8")
    assert all(raw in text for raw in raw_events)          # byte-for-byte substrings of the file
    assert all(raw.startswith("<Event ") and raw.endswith("</Event>") for raw in raw_events)


def test_records_conform_to_schema(raw_events):
    for raw in raw_events:
        rec = bc.build_bronze_record(raw, mode="file", source_file="synthetic_events.xml")
        assert bc.validate_record(rec) == []
        assert rec["raw_xml"] == raw
        assert rec["time_created"].endswith("Z")


def test_system_metadata_is_kept(raw_events):
    rec = bc.build_bronze_record(raw_events[0], mode="file")
    assert rec["provider"]["name"] == "Microsoft-Windows-Sysmon"
    assert rec["provider"]["guid"] == "{5770385F-C22A-43E0-BF4C-06F5698FFBD9}"
    assert rec["event_version"] == 5 and rec["level"] == 4 and rec["task"] == 1
    assert rec["keywords"] == "0x8000000000000000"
    assert rec["writer_process_id"] == 2916 and rec["log_writer_sid"] == "S-1-5-18"
    assert rec["event_data"]["Image"] == "C:\\Windows\\System32\\cmd.exe"   # original name, not renamed


def test_event_id_matches_poc_and_is_stable(raw_events):
    rec = bc.build_bronze_record(raw_events[0], mode="file")
    again = bc.build_bronze_record(raw_events[0], mode="live")
    parsed = poc.parse_event_xml(raw_events[0])
    assert rec["event_id"] == again["event_id"] == poc.normalize(parsed)["event_id"]
    assert rec["host_id"] == bc.host_id_for("lab-host")             # case-insensitive host id


def test_schema_rejects_bad_records(raw_events):
    rec = bc.build_bronze_record(raw_events[0], mode="file")
    bad = dict(rec)
    del bad["raw_xml"]
    assert any("raw_xml" in e for e in bc.validate_record(bad))
    bad = dict(rec, time_created="2026-10-14 02:15:30.123")
    assert bc.validate_record(bad)
    bad = dict(rec, schema_version="bronze-event/2.0")
    assert bc.validate_record(bad)
    bad = dict(rec, record_id=0)
    assert bc.validate_record(bad)


def test_unknown_fields_are_allowed(raw_events):
    rec = bc.build_bronze_record(raw_events[0], mode="file")
    rec["future_field"] = 1
    assert bc.validate_record(rec) == []


def test_collector_errors_use_reason_codes():
    with pytest.raises(ValueError, match="C-001"):
        bc.build_bronze_record("<Event><System>", mode="file")
    xml_no_record_id = ('<Event xmlns="http://schemas.microsoft.com/win/2004/08/events/event"><System>'
                        '<EventID>1</EventID><TimeCreated SystemTime="2026-10-14T02:15:30.1Z"/>'
                        '<Channel>c</Channel><Computer>h</Computer></System><EventData/></Event>')
    with pytest.raises(ValueError, match="C-002"):
        bc.build_bronze_record(xml_no_record_id, mode="file")
    xml_no_time_created = ('<Event xmlns="http://schemas.microsoft.com/win/2004/08/events/event"><System>'
                           '<EventID>1</EventID><EventRecordID>10</EventRecordID>'
                           '<Channel>c</Channel><Computer>h</Computer></System><EventData/></Event>')
    with pytest.raises(ValueError, match="C-002"):
        bc.build_bronze_record(xml_no_time_created, mode="file")


def test_coverage_report_on_synthetic_samples(tmp_path):
    events, warnings = cc._collect([FIXTURE])
    assert warnings == [] and len(events) == 4
    report = cc.build_report(events, warnings)
    assert "## Sysmon event 1" in report and "## Sysmon event 13" in report
    assert "| ParentImage | parent_image | missing_in_silver | 1/1 | 0 |" in report
    assert "Envelope (Bronze schema) violations: 0" in report
    out = tmp_path / "report.md"
    assert cc.main(["--samples", str(FIXTURE), "--out", str(out)]) == 0 and out.exists()


def test_coverage_accepts_poc_json_output(tmp_path):
    out = tmp_path / "poc.json"
    poc.main(["--mode", "file", "--input", str(FIXTURE), "--output", str(out)])
    events, warnings = cc._collect([out])
    assert len(events) == 4 and warnings == []


def test_coverage_accepts_bronze_jsonl_segment(tmp_path, raw_events):
    seg = tmp_path / "sysmon_segment.jsonl"
    records = [bc.build_bronze_record(r, mode="file") for r in raw_events]
    seg.write_text("\n".join(json.dumps(r) for r in records) + "\n", encoding="utf-8")
    events, warnings = cc._collect([seg])
    assert len(events) == 4 and warnings == []
    assert all(e["bronze_errors"] == [] for e in events)