"""Cross-team W05: synthetic golden-example checks (not Windows/live tests)."""
import copy
import json
import sys
from pathlib import Path

import pytest

HERE = Path(__file__).resolve().parent
ROOT = HERE.parents[1]
EXAMPLES = ROOT / "docs" / "architecture" / "w5" / "contracts" / "examples"
sys.path.insert(0, str(HERE))
sys.path.insert(0, str(ROOT / "src" / "pipeline"))

import bronze_contract as bc
from bronze_to_silver_adapter import to_silver_input
from validator_poc import SilverValidatorEngine


def test_shared_xml_to_bronze_to_silver_input():
    xml = (EXAMPLES / "synthetic_process_event1.xml").read_text(encoding="utf-8").strip()
    expected = json.loads((EXAMPLES / "bronze_process_event1.json").read_text(encoding="utf-8"))
    output = bc.build_bronze_record(
        xml, mode="file", collected_at="2026-10-14T02:16:00.000000Z",
        source_file="synthetic_process_event1.xml", batch_id="lab-batch-001", seq=1
    )
    assert bc.validate_record(output) == []
    assert output == expected
    silver_expected = json.loads((EXAMPLES / "silver_input_process_event1.json").read_text(encoding="utf-8"))
    assert to_silver_input(output) == silver_expected
    engine = SilverValidatorEngine()
    assert engine.process_record(silver_expected, source_ref="lab-batch-001:1")
    assert engine.metrics.valid_silver_inserted == 1
    assert engine.process_record(silver_expected, source_ref="lab-batch-001:1:replay") is False
    assert engine.metrics.duplicates_dropped == 1


def test_missing_bronze_identity_is_rejected():
    example = json.loads((EXAMPLES / "bronze_process_event1.json").read_text(encoding="utf-8"))
    bad = copy.deepcopy(example)
    bad["event_id"] = "00000000-0000-0000-0000-000000000000"
    with pytest.raises(ValueError, match="IDENTITY_MISMATCH"):
        to_silver_input(bad)


def test_raw_payload_mismatch_is_rejected():
    example = json.loads((EXAMPLES / "bronze_process_event1.json").read_text(encoding="utf-8"))
    bad = copy.deepcopy(example)
    bad["event_data"]["Image"] = "C:\\different.exe"
    with pytest.raises(ValueError, match="RAW_MISMATCH"):
        to_silver_input(bad)
