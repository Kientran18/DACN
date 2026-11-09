import json
from datetime import datetime, timedelta, timezone

import pytest

from pipeline.retention import plan_retention
from pipeline.silver_store import SilverStore

NOW = datetime(2026, 11, 9, tzinfo=timezone.utc)


def seg(d, name, days_old, manifest=True):
    p = d / name
    p.write_text("{}\n", encoding="utf-8")
    if manifest:
        p.with_suffix(".manifest.json").write_text(json.dumps({"sealed_at": (NOW - timedelta(days=days_old)).isoformat()}), encoding="utf-8")
    return p


def add_alert(con, aid, status, eids, segment):
    con.execute("insert into alerts (alert_id, detection_dedup_key, group_key, created_at_utc, first_seen_utc, last_seen_utc, occurrence_count,"
                " detection_source, rule_id, rule_version, rule_name, severity, severity_reason, status, hostname, contributing_event_ids,"
                " matched_fields, missing_fields, coverage_status) values (?,?,?,?,?,?,1,'RULE','R',1,'r','low','x',?,'h',?,'{}','[]','FULL')",
                [aid, aid, aid, NOW, NOW, NOW, status, eids])
    for e in eids:
        con.execute("insert into silver_event_lineage values (?,?,?,?,?,?)", [e, segment, 1, "h", "m", None])


def test_plan_is_dry_run_and_respects_hold(tmp_path):
    st = SilverStore(tmp_path / "s.duckdb")
    seg(tmp_path, "seg-old-free.jsonl", 40)
    seg(tmp_path, "seg-old-held.jsonl", 40)
    seg(tmp_path, "seg-old-closed.jsonl", 40)
    seg(tmp_path, "seg-new.jsonl", 1)
    seg(tmp_path, "seg-noman.jsonl", 99, manifest=False)
    add_alert(st.con, "a1", "INVESTIGATING", ["e1"], "seg-old-held.jsonl")
    add_alert(st.con, "a2", "CLOSED", ["e2"], "seg-old-closed.jsonl")
    before = sorted(p.name for p in tmp_path.iterdir())
    rep = plan_retention(tmp_path, st.con, raw_days=30, now=NOW)
    assert sorted(p.name for p in tmp_path.iterdir()) == before          # không xóa gì
    assert {c["segment"] for c in rep["would_delete"]} == {"seg-old-free.jsonl", "seg-old-closed.jsonl"}
    reasons = {k["segment"]: k["reason"] for k in rep["kept"]}
    assert "EVIDENCE_HOLD" in reasons["seg-old-held.jsonl"] and "thời hạn" in reasons["seg-new.jsonl"]
    assert [u["segment"] for u in rep["unknown"]] == ["seg-noman.jsonl"] and rep["dry_run"] is True


def test_threshold_is_required(tmp_path):
    st = SilverStore(tmp_path / "s.duckdb")
    with pytest.raises(ValueError):
        plan_retention(tmp_path, st.con, raw_days=0)
