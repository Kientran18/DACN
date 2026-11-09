"""ML-T03 và AT-43: detector giả hoạt động nhưng không đổi kết quả rule và không kích hoạt response."""
import hashlib
import json

import pytest

from detection.engine import DetectionEngine
from detection.ml.interface import AnomalyResult
from detection.ml.loader import ModelError, load_model
from detection.loader import load_rules
from pipeline.silver_store import SilverStore

import harness


def make_model(d, schema="fs1", content=b"fake-artifact", sha=None):
    d.mkdir(exist_ok=True)
    (d / "m.bin").write_bytes(content)
    (d / "model_card.json").write_text(json.dumps({"model_version": "0.1-fake", "feature_schema_version": schema,
        "artifact_file": "m.bin", "artifact_sha256": sha or hashlib.sha256(b"fake-artifact").hexdigest()}), encoding="utf-8")
    return d


def test_load_ok_and_score_is_not_response_trigger(tmp_path):
    m = load_model(make_model(tmp_path / "m"), expected_feature_schema_version="fs1", predictor_factory=lambda p: (lambda f: 0.7))
    r = m.score({"x": 1})
    assert isinstance(r, AnomalyResult) and r.score == 0.7 and r.triggers_response is False and r.model_version == "0.1-fake"


@pytest.mark.parametrize("kw,msg", [({"schema": "fs2"}, "feature_schema_version"), ({"sha": "0" * 64}, "hash artifact")])
def test_rejects_wrong_schema_or_hash(tmp_path, kw, msg):
    with pytest.raises(ModelError, match=msg):
        load_model(make_model(tmp_path / "m", **kw), expected_feature_schema_version="fs1", predictor_factory=lambda p: (lambda f: 0.1))


def test_rejects_missing_card_and_out_of_range_score(tmp_path):
    with pytest.raises(ModelError):
        load_model(tmp_path, expected_feature_schema_version="fs1", predictor_factory=lambda p: None)
    m = load_model(make_model(tmp_path / "m"), expected_feature_schema_version="fs1", predictor_factory=lambda p: (lambda f: 1.5))
    with pytest.raises(ModelError):
        m.score({})


def test_enabled_fake_detector_does_not_change_rule_results(tmp_path):
    rows = {"name": "ml", "rows": [{"id": "p", "table": "process", "image_path": "C:\\a\\powershell.exe",
                                    "command_line": "powershell.exe -enc AAAA", "parent_image": "C:\\Windows\\explorer.exe"}]}
    def run(ml, name):
        st = SilverStore(tmp_path / name)
        for t, _, row in harness.build_rows(rows):
            st._insert(t, row)
        out = DetectionEngine(st.con, rules=load_rules(), ml=ml).run()
        return sorted((r.rule_id, r.outcome, r.severity) for r in out)
    fake = load_model(make_model(tmp_path / "m"), expected_feature_schema_version="fs1", predictor_factory=lambda p: (lambda f: 0.99))
    assert run(fake, "a.duckdb") == run(None, "b.duckdb") != []
