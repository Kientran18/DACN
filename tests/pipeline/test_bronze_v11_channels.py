"""bronze-event/1.1 (D1/D2, docs/architecture/w8/telemetry-defender-powershell-proposal.md): source/schema_version suy ra
từ Channel, định danh theo ADR 0001 không đổi, Sysmon giữ 1.0. Dữ liệu SYNTHETIC (tests/fixtures/windows_channels/)."""
import copy
import uuid
from pathlib import Path

import pytest

import bronze_contract as bc
import bronze_to_silver_adapter as ad
import sysmon_collector_poc as poc
import windows_channels as wc
from validator_poc import SilverValidatorEngine

ROOT = Path(__file__).resolve().parents[2]
FIX = ROOT / "tests/fixtures/windows_channels"
SYSMON_XML = next(bc.iter_raw_xml_from_file(ROOT / "poc/sysmon-collector/configs/synthetic_events.xml"))


def xml(name):
    return next(bc.iter_raw_xml_from_file(FIX / name))


@pytest.mark.parametrize("name,source", [("defender_1116.synthetic.xml", "WINDOWS_DEFENDER"),
                                         ("defender_5001.synthetic.xml", "WINDOWS_DEFENDER"),
                                         ("ps4104_single.synthetic.xml", "POWERSHELL")])
def test_new_channels_get_their_own_source_and_v11(name, source):
    rec = bc.build_bronze_record(xml(name), mode="file")
    assert rec["source"] == source and rec["schema_version"] == "bronze-event/1.1"
    assert bc.validate_record(rec) == []
    assert rec["raw_xml"] == xml(name)                      # ADR 0003: giữ nguyên byte


def test_sysmon_record_unchanged_v10():
    rec = bc.build_bronze_record(SYSMON_XML, mode="file")
    assert rec["source"] == "SYSMON" and rec["schema_version"] == "bronze-event/1.0"
    assert bc.validate_record(rec) == []


def test_identity_formula_unchanged_and_channel_separates_same_record_id():
    recs = [bc.build_bronze_record(xml(n), mode="file")
            for n in ("defender_1116.synthetic.xml", "ps4104_single.synthetic.xml")]
    assert recs[0]["record_id"] == recs[1]["record_id"] == 42
    assert recs[0]["event_id"] != recs[1]["event_id"]
    for r in recs:
        key = f"{r['hostname']}|{r['channel']}|{r['record_id']}"
        assert r["event_id"] == str(uuid.uuid5(poc.EVENT_ID_NAMESPACE, key))
        assert r["host_id"] == bc.host_id_for("SYNTH-HOST")


def test_unsupported_channel_is_c007_not_mislabelled():
    other = SYSMON_XML.replace("Microsoft-Windows-Sysmon/Operational", "Security")
    with pytest.raises(ValueError, match=r"^C-007 "):
        bc.build_bronze_record(other, mode="file")


def test_source_or_version_not_matching_channel_is_rejected():
    rec = bc.build_bronze_record(xml("defender_1116.synthetic.xml"), mode="file")
    bad = copy.deepcopy(rec); bad["source"] = "SYSMON"
    assert any(e.startswith("source:") for e in bc.validate_record(bad))
    sysmon = bc.build_bronze_record(SYSMON_XML, mode="file")
    bad = copy.deepcopy(sysmon); bad["schema_version"] = "bronze-event/1.1"
    assert bc.validate_record(bad)                          # Sysmon phải giữ 1.0
    bad = copy.deepcopy(rec); bad["source"] = "POWERSHELL"
    assert bc.validate_record(bad)


def test_v10_schema_still_rejects_new_sources():
    rec = bc.build_bronze_record(xml("ps4104_single.synthetic.xml"), mode="file")
    rec["schema_version"] = "bronze-event/1.0"
    assert any("source" in e for e in bc.validate_record(rec))


def test_adapter_accepts_v11_and_names_event_type_by_channel():
    flat = ad.to_silver_input(bc.build_bronze_record(xml("ps4104_single.synthetic.xml"), mode="file"))
    assert flat["event_type"] == "POWERSHELL_SCRIPT_BLOCK" and flat["source"] == "POWERSHELL"
    flat = ad.to_silver_input(bc.build_bronze_record(xml("defender_1116.synthetic.xml"), mode="file"))
    assert flat["event_type"] == "DEFENDER_MALWARE_DETECTED"
    assert ad.to_silver_input(bc.build_bronze_record(SYSMON_XML, mode="file"))["event_type"] == "PROCESS_START"


def test_adapter_still_fails_closed_on_v11_identity():
    rec = bc.build_bronze_record(xml("defender_1116.synthetic.xml"), mode="file")
    rec["event_id"] = str(uuid.uuid4())
    with pytest.raises(ValueError, match="BRONZE_IDENTITY_MISMATCH"):
        ad.to_silver_input(rec)


def test_sysmon_validator_never_accepts_new_channels():
    """Validator Sysmon (W05) không nhận bản ghi kênh mới (SilverStore route chúng sang validator_windows_channels)."""
    for n in ("defender_1116.synthetic.xml", "ps4104_single.synthetic.xml"):
        eng = SilverValidatorEngine()
        assert not eng.process_record(ad.to_silver_input(bc.build_bronze_record(xml(n), mode="file")), "t")
        assert [q.error_code for q in eng.quarantine_dlq] == ["ERR_UNSUPPORTED_EVENT_ID"]


def test_channel_table_helpers():
    assert wc.canonical_channel("microsoft-windows-powershell/operational") == wc.POWERSHELL_CHANNEL
    assert wc.event_type_for(wc.DEFENDER_CHANNEL, 4104) is None
    assert wc.channel_slug(wc.DEFENDER_CHANNEL) == "microsoft_windows_windows_defender_operational"
    assert set(wc.DEFAULT_XPATH) == set(wc.CHANNEL_SOURCES)
    for ch, ids in wc.SUPPORTED_EVENT_IDS.items():
        assert all(wc.event_type_for(ch, i) for i in ids)
