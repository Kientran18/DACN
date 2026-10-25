"""Unit tests for sysmon_collector_poc.

All input here is SYNTHETIC (poc/fixtures/synthetic_events.xml). Passing these tests shows that the
parser and normalizer work on events shaped like Sysmon output; it does NOT show that live
collection works on a real machine.
"""
import json
from pathlib import Path

import pytest

import sysmon_collector_poc as c

FIXTURE = Path(__file__).parent / "configs" / "synthetic_events.xml"


@pytest.fixture(scope="module")
def parsed():
    return list(c.iter_events_from_file(FIXTURE))


@pytest.fixture(scope="module")
def normalized(parsed):
    return {p["system"]["event_id"]: c.normalize(p) for p in parsed}


def test_reads_all_events_from_rootless_xml(parsed):
    assert [p["system"]["event_id"] for p in parsed] == [1, 3, 13, 11]


def test_parse_hashes():
    assert c.parse_hashes("SHA256=AB,IMPHASH=CD") == {"sha256": "AB", "imphash": "CD"}
    assert c.parse_hashes(None) == {}


def test_strip_guid_removes_braces_and_keeps_case():
    assert c.strip_guid("{AAAAAAAA-0000-0000-0000-000000000001}") == "AAAAAAAA-0000-0000-0000-000000000001"


def test_process_event_mapping(normalized):
    ev = normalized[1]
    assert ev["event_type"] == "PROCESS_START"
    assert ev["source"] == "SYSMON"
    assert ev["process_guid"] == "AAAAAAAA-0000-0000-0000-000000000001"
    d = ev["data"]
    assert d["pid"] == 4321 and d["ppid"] == 1234
    assert d["parent_guid"] == "AAAAAAAA-0000-0000-0000-000000000002"
    assert d["parent_image"].endswith("powershell.exe")
    assert d["file_sha256"].startswith("0123456789ABCDEF")
    assert d["integrity_level"] == "Medium"
    assert "EDR_POC_SYNTH" in d["command_line"]


def test_network_event_mapping(normalized):
    ev = normalized[3]
    assert ev["event_type"] == "NETWORK_CONNECT"
    d = ev["data"]
    assert d["direction"] == "OUTBOUND" and d["protocol"] == "TCP"
    assert d["dest_ip"] == "93.184.216.34" and d["dest_port"] == 443
    assert d["ip_version"] == "IPv4"


def test_registry_event_mapping(normalized):
    ev = normalized[13]
    assert ev["event_type"] == "REGISTRY_SET_VALUE"
    d = ev["data"]
    assert d["hive"] == "HKU"
    assert d["key_path"].endswith("Software\\EDR_PoC")
    assert d["value_name"] == "TestDword"
    assert d["value_type_inferred"] == "REG_DWORD"


def test_file_event_mapping(normalized):
    d = normalized[11]["data"]
    assert d["file_extension"] == "exe"
    assert d["file_path"].endswith("EDR_POC_SYNTH_drop.exe")
    assert d["file_sha256"] is None  # Event 11 carries no hash


def test_event_id_is_deterministic(parsed):
    first = c.normalize(parsed[0])["event_id"]
    again = c.normalize(parsed[0])["event_id"]
    assert first == again
    assert first != c.normalize(parsed[1])["event_id"]


def test_raw_data_is_kept(normalized):
    assert normalized[1]["raw_data"]["Image"] == "C:\\Windows\\System32\\cmd.exe"


def test_registry_type_inference():
    assert c.infer_registry_value_type("DWORD (0x00000001)") == "REG_DWORD"
    assert c.infer_registry_value_type("QWORD (0x0000000000000001)") == "REG_QWORD"
    assert c.infer_registry_value_type("Binary Data") == "REG_BINARY"
    assert c.infer_registry_value_type("C:\\x.exe") == "STRING_UNSPECIFIED"


def test_cli_exports_json_for_one_event_type(tmp_path):
    out = tmp_path / "process.json"
    rc = c.main(["--mode", "file", "--input", str(FIXTURE), "--event-id", "1", "--output", str(out)])
    assert rc == 0
    data = json.loads(out.read_text(encoding="utf-8"))
    assert len(data) == 1 and data[0]["sysmon_event_id"] == 1


def test_cli_jsonl_output(tmp_path):
    out = tmp_path / "all.jsonl"
    c.main(["--mode", "file", "--input", str(FIXTURE), "--format", "jsonl", "--output", str(out)])
    lines = out.read_text(encoding="utf-8").strip().splitlines()
    assert len(lines) == 4 and all(json.loads(line) for line in lines)


def test_live_mode_gives_clear_error_without_pywin32():
    with pytest.raises(RuntimeError, match="pywin32"):
        next(c.iter_events_live())
