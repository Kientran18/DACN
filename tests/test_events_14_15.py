"""PH1-T07: Event 14/15 synthetic qua collector -> Bronze -> adapter -> validator. KHÔNG phải telemetry thật."""
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "poc" / "sysmon-collector"))
sys.path.insert(0, str(ROOT / "src" / "pipeline"))

import bronze_contract as bc  # noqa: E402
import sysmon_collector_poc as poc  # noqa: E402
from bronze_to_silver_adapter import to_silver_input  # noqa: E402
from validator_poc import SilverValidatorEngine  # noqa: E402

FX = ROOT / "tests" / "fixtures" / "synthetic_events_14_15.xml"


def records():
    return [bc.build_bronze_record(x, mode="file", collected_at="2026-10-14T02:22:00.000000Z", source_file=FX.name,
                                   batch_id="synthetic-14-15", seq=i) for i, x in enumerate(bc.iter_raw_xml_from_file(FX), 1)]


def test_fixture_is_labelled_synthetic():
    assert "SYNTHETIC" in FX.read_text(encoding="utf-8").splitlines()[0]


def test_collector_maps_event_14_and_15():
    evs = {n["sysmon_event_id"]: n for n in map(poc.normalize, poc.iter_events_from_file(FX))}
    assert evs[14]["event_type"] == "REGISTRY_RENAME_KEY" and evs[14]["data"]["operation"] == "RenameKey"
    assert evs[15]["event_type"] == "FILE_STREAM_CREATE"
    assert evs[15]["data"]["file_sha256"].lower() == "0123456789abcdef" * 4


def test_bronze_adapter_validator_route_14_and_15():
    eng = SilverValidatorEngine()
    for n, rec in enumerate(records(), 1):
        assert bc.validate_record(rec) == []
        assert eng.process_record(to_silver_input(rec), source_ref=f"s:{n}")
    assert eng.metrics.valid_silver_inserted == 2
