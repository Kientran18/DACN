"""Kho tín hiệu ML (_ml_signals, bảng nội bộ do module sở hữu). Không kích hoạt response."""
from datetime import datetime, timezone

import duckdb
import pytest

from detection.ml.signals import INSUFFICIENT, SCORED, MLSignalStore

T = datetime(2026, 1, 1, 10, tzinfo=timezone.utc)


@pytest.fixture
def store():
    return MLSignalStore(duckdb.connect(":memory:"))


def test_record_scored_and_list(store):
    sid = store.record("ML_BEHAVIOR", SCORED, score=0.7, hostname="H", process_guid="g1", source_event_ids=["e1"],
                       observed_at=T, model_version="m1", feature_schema_version="f1",
                       explanation={"top": "parent_child_pair"})
    rows = store.list(hostname="H")
    assert len(rows) == 1 and rows[0]["signal_id"] == sid and rows[0]["score"] == 0.7
    assert rows[0]["explanation"] == {"top": "parent_child_pair"} and rows[0]["source_event_ids"] == ["e1"]


def test_record_is_idempotent_per_detector_model_subject(store):
    a = store.record("ML_BEHAVIOR", SCORED, score=0.2, hostname="H", process_guid="g", source_event_ids=[],
                     observed_at=T, model_version="m1")
    b = store.record("ML_BEHAVIOR", SCORED, score=0.9, hostname="H", process_guid="g", source_event_ids=[],
                     observed_at=T, model_version="m1")
    assert a == b and len(store.list()) == 1 and store.list()[0]["score"] == 0.2
    assert store.has("ML_BEHAVIOR", "m1", "H", "g") and not store.has("ML_BEHAVIOR", "m2", "H", "g")


def test_insufficient_needs_reason_and_no_score(store):
    with pytest.raises(ValueError):
        store.record("ML_STATIC", INSUFFICIENT, hostname="H", process_guid="g", source_event_ids=[], observed_at=T)
    with pytest.raises(ValueError):
        store.record("ML_STATIC", INSUFFICIENT, reason="X", score=0.5, hostname="H", process_guid="g",
                     source_event_ids=[], observed_at=T)
    store.record("ML_STATIC", INSUFFICIENT, reason="DEPENDENCY_MISSING", hostname="H", process_guid="g",
                 source_event_ids=[], observed_at=T)
    assert store.list()[0]["score"] is None and store.list()[0]["reason"] == "DEPENDENCY_MISSING"


@pytest.mark.parametrize("bad", [-0.1, 1.5, None, float("nan")])
def test_scored_needs_score_in_unit_interval(store, bad):
    with pytest.raises(ValueError):
        store.record("ML_STATIC", SCORED, score=bad, hostname="H", process_guid="g", source_event_ids=[], observed_at=T)


def test_unknown_detector_rejected(store):
    with pytest.raises(ValueError):
        store.record("ML_MAGIC", SCORED, score=0.1, hostname="H", process_guid="g", source_event_ids=[], observed_at=T)
