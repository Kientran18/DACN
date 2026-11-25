"""Detector bất thường hành vi theo độ hiếm (ML_BEHAVIOR, nháp, tắt mặc định).
Dữ liệu SYNTHETIC; KHÔNG đo độ chính xác (chưa có dữ liệu có nhãn của DACN)."""
import json
import sys
from datetime import datetime, timedelta, timezone
from pathlib import Path

import pytest

HERE = Path(__file__).resolve().parent
sys.path.insert(0, str(HERE))
import harness  # noqa: E402

from detection.ml import behavior as B  # noqa: E402
from detection.ml.interface import MLDetector  # noqa: E402
from detection.ml.loader import ModelError  # noqa: E402
from detection.ml.signals import MLSignalStore  # noqa: E402
from pipeline.silver_store import SilverStore  # noqa: E402

T0 = datetime(2026, 1, 1, 8, tzinfo=timezone.utc)
EXPLORER = "C:\\Windows\\explorer.exe"
NOTEPAD = "C:\\Windows\\System32\\notepad.exe"


def guid(i):
    return f"00000000-0000-0000-0000-{i:012d}"


def baseline_rows(n=30):
    rows = []
    for i in range(n):
        rows.append({"id": f"b{i}", "table": "process", "process_guid": guid(i), "image_path": NOTEPAD,
                     "parent_image": EXPLORER, "user_name": "LAB\\user", "timestamp": (T0 + timedelta(minutes=i)).isoformat()})
        rows.append({"id": f"n{i}", "table": "network", "process_guid": guid(i), "image_path": NOTEPAD, "dest_port": 443,
                     "timestamp": (T0 + timedelta(minutes=i, seconds=1)).isoformat()})
    return rows


@pytest.fixture
def db(tmp_path):
    st = SilverStore(tmp_path / "b.duckdb")
    ids = {}
    later = T0 + timedelta(hours=2)
    rows = baseline_rows() + [
        {"id": "known", "table": "process", "process_guid": guid(100), "image_path": NOTEPAD, "parent_image": EXPLORER,
         "user_name": "LAB\\user", "timestamp": later.isoformat()},
        {"id": "odd", "table": "process", "process_guid": guid(101), "image_path": "C:\\lab\\odd.exe",
         "parent_image": "C:\\Windows\\System32\\winword.exe", "user_name": "LAB\\user", "timestamp": later.isoformat()},
        {"id": "oddnet", "table": "network", "process_guid": guid(101), "image_path": "C:\\lab\\odd.exe", "dest_port": 4444,
         "timestamp": (later + timedelta(seconds=2)).isoformat()},
        {"id": "noparent", "table": "process", "process_guid": guid(102), "image_path": NOTEPAD, "parent_image": None,
         "user_name": None, "timestamp": later.isoformat()},
    ]
    for t, rid, row in harness.build_rows({"name": "beh", "rows": rows}):
        st._insert(t, row)
        ids[rid] = row["event_id"]
    return st, ids


def train(db, tmp_path, min_processes=20):
    st, _ = db
    vecs = B.extract_features(st.con, since=T0, until=T0 + timedelta(hours=1))
    model = B.train(vecs, min_processes=min_processes)
    out = tmp_path / "model"
    B.save_model(model, out, model_version="beh-test-1", trained_since=T0, trained_until=T0 + timedelta(hours=1))
    return out


def test_feature_contract_names_sources_for_every_feature():
    for name, spec in B.FEATURES.items():
        assert spec["source_table"].startswith("silver_") and spec["columns"] and spec["description"]
        assert 0 < spec["weight"] <= 1
    assert B.FEATURE_SCHEMA_VERSION.startswith("dacn-behavior-rarity/")


def test_extract_features_keeps_source_event_ids(db):
    st, ids = db
    vecs = {v["process_guid"]: v for v in B.extract_features(st.con, since=T0 + timedelta(hours=1))}
    odd = vecs[guid(101)]["features"]
    assert odd["parent_child_pair"]["values"] == ["winword.exe>odd.exe"]
    assert odd["parent_child_pair"]["source_event_ids"] == [ids["odd"]]
    assert odd["network_dest_port"]["values"] == ["odd.exe:4444"]
    assert odd["network_dest_port"]["source_event_ids"] == [ids["oddnet"]]
    miss = vecs[guid(102)]["features"]
    assert miss["parent_child_pair"]["values"] == [] and "parent_image" in miss["parent_child_pair"]["missing"]


def test_train_refuses_small_baseline(db):
    st, _ = db
    vecs = B.extract_features(st.con, since=T0, until=T0 + timedelta(hours=1))
    with pytest.raises(ValueError, match="BASELINE_TOO_SMALL"):
        B.train(vecs, min_processes=1000)


def test_saved_model_stores_hashes_not_plaintext(db, tmp_path):
    out = train(db, tmp_path)
    text = (out / "baseline.json").read_text(encoding="utf-8").lower()
    assert "notepad" not in text and "explorer" not in text and "lab\\\\user" not in text
    card = json.loads((out / "model_card.json").read_text(encoding="utf-8"))
    assert card["feature_schema_version"] == B.FEATURE_SCHEMA_VERSION and card["status"] == "DRAFT_UNVALIDATED"
    assert card["trained_until"] == (T0 + timedelta(hours=1)).isoformat()
    assert "accuracy" not in json.dumps(card).lower()


def test_rare_process_scores_higher_and_is_explained(db, tmp_path):
    st, ids = db
    det = B.load_behavior_model(train(db, tmp_path))
    assert callable(getattr(det, "score", None)) and MLDetector.score.__name__ == "score"
    vecs = {v["process_guid"]: v for v in B.extract_features(st.con, since=T0 + timedelta(hours=1))}
    known, odd = det.score(vecs[guid(100)]["features"]), det.score(vecs[guid(101)]["features"])
    assert odd.score > known.score
    assert odd.score == pytest.approx(1.0) and known.score < 0.1
    assert odd.triggers_response is False and odd.model_version == "beh-test-1"
    e = json.loads(odd.explanation)
    assert e["features"]["parent_child_pair"]["baseline_count"] == 0
    assert e["features"]["parent_child_pair"]["source_event_ids"] == [ids["odd"]]


def test_missing_features_are_excluded_not_invented(db, tmp_path):
    st, _ = db
    det = B.load_behavior_model(train(db, tmp_path))
    vecs = {v["process_guid"]: v for v in B.extract_features(st.con, since=T0 + timedelta(hours=1))}
    r = det.score(vecs[guid(102)]["features"])
    e = json.loads(r.explanation)
    assert "parent_child_pair" in e["missing"] and "image_user" in e["missing"]
    assert det.score({k: {"values": [], "source_event_ids": [], "missing": ["x"]} for k in B.FEATURES}) is None


def test_load_rejects_tampered_baseline(db, tmp_path):
    out = train(db, tmp_path)
    (out / "baseline.json").write_text("{}", encoding="utf-8")
    with pytest.raises(ModelError):
        B.load_behavior_model(out)


def test_score_signals_only_after_training_window_and_idempotent(db, tmp_path):
    st, ids = db
    out = train(db, tmp_path)
    store = MLSignalStore(st.con)
    s1 = B.score_signals(st.con, B.load_behavior_model(out), store)
    rows = {r["process_guid"]: r for r in store.list()}
    assert set(rows) == {guid(100), guid(101), guid(102)}           # không chấm dữ liệu train
    assert rows[guid(101)]["status"] == "SCORED" and rows[guid(101)]["score"] > rows[guid(100)]["score"]
    assert ids["odd"] in rows[guid(101)]["source_event_ids"]
    assert s1["scored"] == 3
    assert B.score_signals(st.con, B.load_behavior_model(out), store)["scored"] == 0


def test_cli_train_and_score(db, tmp_path):
    st, _ = db
    path = st.path
    st.close()
    out = tmp_path / "cli_model"
    assert B.main(["train", "--db", str(path), "--since", T0.isoformat(),
                   "--until", (T0 + timedelta(hours=1)).isoformat(), "--out", str(out), "--model-version", "cli-1",
                   "--min-processes", "20"]) == 0
    assert B.main(["score", "--db", str(path), "--model-dir", str(out)]) == 0
    st2 = SilverStore(path)
    assert len(MLSignalStore(st2.con).list()) == 3
