import json
from pathlib import Path

import jsonschema

from scripts.contracts.export_issue40_contracts import ERROR_SCHEMA, outputs
from detection.schema import DETECTION_RESULT_SCHEMA
from static_analysis.contracts import CONTRACTS

ROOT = Path(__file__).resolve().parents[2]


def test_exported_schemas_and_synthetic_examples_are_valid_and_not_stale():
    values = outputs()
    for relative, expected in values.items():
        assert json.loads((ROOT / relative).read_text(encoding="utf-8")) == expected, relative
        if relative.endswith(".schema.json"):
            jsonschema.Draft202012Validator.check_schema(expected)
    w6 = values["docs/architecture/w6/contracts/examples.json"]
    for result in w6["results"]:
        jsonschema.validate(result, DETECTION_RESULT_SCHEMA)
    jsonschema.validate(w6["error"], ERROR_SCHEMA)
    w7 = values["docs/architecture/w7/contracts/examples.json"]
    for name, key in [("knowledge", "knowledge"), ("static-result", "static_result"), ("static-result", "error_result"),
                      ("signature-hit", "signature_hit"), ("whitelist-verdict", "whitelist_verdict"), ("candidate", "candidate")]:
        jsonschema.validate(w7[key], CONTRACTS[name], format_checker=jsonschema.FormatChecker())
