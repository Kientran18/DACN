import json
import sys
import uuid
from pathlib import Path

import pytest

HERE = Path(__file__).resolve().parent
sys.path.insert(0, str(HERE.parent / "detection"))
import harness  # noqa: E402

import bronze_contract as bc  # noqa: E402
from agent.bronze_writer import BronzeWriter  # noqa: E402
from alerts.builder import build_from_results  # noqa: E402
from alerts.evidence import resolve_evidence  # noqa: E402
from alerts.store import AlertStore, InvalidTransition  # noqa: E402
from alerts.timeline import process_tree, timeline  # noqa: E402
from detection.engine import DetectionEngine  # noqa: E402
from detection.loader import load_rules  # noqa: E402
from pipeline.silver_store import SilverStore  # noqa: E402

SYN = Path(__file__).resolve().parents[2] / "poc/sysmon-collector/configs/synthetic_events.xml"


def silver_with_rows(tmp_path, rows):
    st = SilverStore(tmp_path / "s.duckdb")
    for t, _, row in harness.build_rows({"name": "al", "rows": rows}):
        st._insert(t, row)
    return st


PS_ROWS = [{"id": "p", "table": "process", "image_path": "C:\\a\\powershell.exe",
            "command_line": "powershell.exe -enc AAAAAAAA", "timestamp": "2026-01-01T10:00:00+00:00"}]


def mk_alert(store, eid):
    from datetime import datetime, timezone
    t = datetime(2026, 1, 1, tzinfo=timezone.utc)
    return store.insert_alert(detection_dedup_key="k-" + eid, group_key="g", first_seen_utc=t, last_seen_utc=t,
                              detection_source="RULE", rule_id="DACN-DET-001", rule_version=1, rule_name="n",
                              severity="low", severity_reason="thử", hostname="H", contributing_event_ids=[eid])


def alerts_for(tmp_path, rows=PS_ROWS):
    st = silver_with_rows(tmp_path, rows)
    rules = load_rules()
    results = DetectionEngine(st.con, rules=rules).run()
    store = AlertStore(st.con)
    return st, store, rules, results


def test_match_becomes_alert_with_rule_version_and_mitre(tmp_path):
    st, store, rules, results = alerts_for(tmp_path)
    out = build_from_results(store, rules, results, st.con)
    a = store.get(out["alerts"][0])
    assert a["status"] == "NEW" and a["rule_version"] == 1 and a["rule_id"] == "DACN-DET-001"
    assert json.loads(a["mitre_technique_ids"]) == ["T1059.001"]
    assert a["contributing_event_ids"] and a["severity_reason"]


def test_insufficient_telemetry_is_coverage_gap_not_alert(tmp_path):
    rows = [{"id": "p", "table": "process", "image_path": "C:\\a\\powershell.exe", "command_line": None}]
    st, store, rules, results = alerts_for(tmp_path, rows)
    out = build_from_results(store, rules, results, st.con)
    assert out["alerts"] == [] and len(out["gaps"]) == 1
    assert st.con.execute("select count(*) from alerts").fetchone()[0] == 0


def test_rebuild_is_idempotent(tmp_path):
    st, store, rules, results = alerts_for(tmp_path)
    build_from_results(store, rules, results, st.con)
    build_from_results(store, rules, results, st.con)
    assert st.con.execute("select count(*) from alerts").fetchone()[0] == 1


def test_duplicate_group_is_suppressed_and_counted(tmp_path):
    rows = PS_ROWS + [{"id": "p2", "table": "process", "image_path": "C:\\a\\powershell.exe",
                       "command_line": "powershell.exe -enc BBBBBBBB", "timestamp": "2026-01-01T10:01:00+00:00"}]
    st, store, rules, results = alerts_for(tmp_path, rows)
    out = build_from_results(store, rules, results, st.con)
    assert len(out["alerts"]) == 1 and out["suppressed"] == 1
    a = store.get(out["alerts"][0])
    assert a["occurrence_count"] == 2


def test_state_machine_and_history(tmp_path):
    st, store, rules, results = alerts_for(tmp_path)
    aid = build_from_results(store, rules, results, st.con)["alerts"][0]
    with pytest.raises(InvalidTransition):
        store.transition(aid, "CONFIRMED", actor="analyst", note="nhảy cóc")
    store.transition(aid, "TRIAGED", actor="analyst", note="đã xem")
    store.transition(aid, "INVESTIGATING", actor="analyst", note="điều tra")
    store.transition(aid, "FALSE_POSITIVE", actor="analyst", note="script quản trị")
    with pytest.raises(InvalidTransition):
        store.transition(aid, "NEW", actor="analyst", note="quay lại")
    with pytest.raises(ValueError):
        store.transition(aid, "CLOSED", actor="", note="x")
    hist = store.history(aid)
    assert [h["to_status"] for h in hist] == ["NEW", "TRIAGED", "INVESTIGATING", "FALSE_POSITIVE"]


def test_audit_chain_detects_tampering(tmp_path):
    st, store, rules, results = alerts_for(tmp_path)
    aid = build_from_results(store, rules, results, st.con)["alerts"][0]
    store.transition(aid, "TRIAGED", actor="a", note="n")
    assert store.verify_audit() == []
    st.con.execute("update audit_log set reason='đã sửa' where seq=1")
    assert store.verify_audit() != []


def test_incident_notes_and_links_are_audited(tmp_path):
    st, store, rules, results = alerts_for(tmp_path)
    aid = build_from_results(store, rules, results, st.con)["alerts"][0]
    iid = store.create_incident("Sự cố thử nghiệm", actor="a")
    store.link_alert(iid, aid, actor="a")
    store.add_note(iid, "ghi chú", actor="a")
    actions = [r[0] for r in st.con.execute("select action from audit_log order by seq").fetchall()]
    assert {"INCIDENT_CREATE", "INCIDENT_LINK_ALERT", "INCIDENT_NOTE"} <= set(actions)
    with pytest.raises(ValueError):
        store.add_note(iid, "", actor="a")


def test_evidence_resolves_to_raw_xml_both_ways(tmp_path):
    seg_dir = tmp_path / "b"
    w = BronzeWriter(seg_dir)
    xmls = list(bc.iter_raw_xml_from_file(SYN))
    for i, x in enumerate(xmls):
        w.append(bc.build_bronze_record(x, mode="file", seq=i))
    w.seal()
    st = SilverStore(tmp_path / "s.duckdb"); st.ingest_dir(seg_dir, "r")
    eid = st.con.execute("select event_id from silver_process_events limit 1").fetchone()[0]
    rules = load_rules(); store = AlertStore(st.con)
    # alert thủ công trỏ tới một sự kiện thật để thử resolver
    aid = mk_alert(store, eid)
    ev = resolve_evidence(st.con, aid, seg_dir)
    assert ev["status"] == "FULL" and ev["events"][0]["raw_xml"].startswith("<Event")
    # chiều ngược: từ raw -> Silver event_id
    from alerts.evidence import event_for_raw
    assert event_for_raw(st.con, ev["events"][0]["raw_xml"]) == eid


def test_evidence_partial_when_bronze_missing_or_tampered(tmp_path):
    seg_dir = tmp_path / "b"
    w = BronzeWriter(seg_dir)
    for i, x in enumerate(bc.iter_raw_xml_from_file(SYN)):
        w.append(bc.build_bronze_record(x, mode="file", seq=i))
    seg = w.seal()
    st = SilverStore(tmp_path / "s.duckdb"); st.ingest_dir(seg_dir, "r")
    eid = st.con.execute("select event_id from silver_process_events limit 1").fetchone()[0]
    store = AlertStore(st.con); aid = mk_alert(store, eid)
    data = bytearray(seg.read_bytes()); data[8] ^= 1; seg.write_bytes(bytes(data))
    assert resolve_evidence(st.con, aid, seg_dir)["status"] == "SEGMENT_INVALID"
    seg.unlink()
    r = resolve_evidence(st.con, aid, seg_dir)
    assert r["status"] == "RAW_EXPIRED" and r["events"][0]["silver"]["event_id"] == eid


def test_timeline_orders_and_reports_skew_and_tree_flags_partial_ancestry(tmp_path):
    rows = [
        {"id": "par", "table": "process", "process_guid": "aaaaaaaa-0000-0000-0000-000000000001",
         "parent_guid": "ffffffff-0000-0000-0000-00000000dead", "timestamp": "2026-01-01T10:00:00+00:00"},
        {"id": "kid", "table": "process", "process_guid": "aaaaaaaa-0000-0000-0000-000000000002",
         "parent_guid": "aaaaaaaa-0000-0000-0000-000000000001", "timestamp": "2026-01-01T10:00:05+00:00",
         "event_utc_time": "2026-01-01T09:59:50+00:00"},
        {"id": "f", "table": "file", "process_guid": "aaaaaaaa-0000-0000-0000-000000000002",
         "timestamp": "2026-01-01T10:00:06+00:00"},
    ]
    st = silver_with_rows(tmp_path, rows)
    tl = timeline(st.con, "aaaaaaaa-0000-0000-0000-000000000002")
    assert [e["sysmon_event_id"] for e in tl] == [1, 11]
    assert tl[0]["skew_seconds"] == 15.0
    tree = process_tree(st.con, "aaaaaaaa-0000-0000-0000-000000000002")
    assert [n["process_guid"][-1] for n in tree["ancestors"]] == ["1"]
    assert tree["coverage_status"] == "PARTIAL_ANCESTRY"


def test_state_change_and_audit_are_one_transaction(tmp_path, monkeypatch):
    st, store, rules, results = alerts_for(tmp_path)
    aid = build_from_results(store, rules, results, st.con)["alerts"][0]
    n_audit = st.con.execute("select count(*) from audit_log").fetchone()[0]
    real = store._audit

    def crash(*a, **k):
        raise RuntimeError("crash giữa lúc ghi audit")
    monkeypatch.setattr(store, "_audit", crash)
    with pytest.raises(RuntimeError):
        store.transition(aid, "TRIAGED", actor="u", note="n")
    monkeypatch.setattr(store, "_audit", real)
    assert store.get(aid)["status"] == "NEW"                                           # trạng thái không đổi
    assert len(store.history(aid)) == 1                                                 # không có dòng lịch sử mồ côi
    assert st.con.execute("select count(*) from audit_log").fetchone()[0] == n_audit   # và audit không lệch
    store.transition(aid, "TRIAGED", actor="u", note="n")                               # store vẫn dùng được sau rollback
    assert store.verify_audit() == []
