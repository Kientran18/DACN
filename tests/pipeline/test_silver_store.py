import json
from pathlib import Path
import pytest
import bronze_contract as bc
from agent.bronze_writer import BronzeWriter
from pipeline.segment_reader import read_segment, SegmentError
from pipeline.silver_store import SilverStore

SYN = Path(__file__).resolve().parents[2] / "poc/sysmon-collector/configs/synthetic_events.xml"


def make_seg(d, xmls=None, extra=()):
    w = BronzeWriter(d)
    for i, x in enumerate(xmls or bc.iter_raw_xml_from_file(SYN)):
        w.append(bc.build_bronze_record(x, mode="file", seq=i))
    for r in extra:
        w.append(r)
    return w.seal()


def counts(st):
    return {t: st.con.execute(f"select count(*) from {t}").fetchone()[0] for t in
            ("silver_process_events", "silver_file_events", "silver_registry_events",
             "silver_network_events", "silver_quarantine_dlq")}


def test_reader_rejects_tampered_segment(tmp_path):
    seg = make_seg(tmp_path)
    b = bytearray(seg.read_bytes()); b[5] ^= 1; seg.write_bytes(bytes(b))
    with pytest.raises(SegmentError) as e:
        list(read_segment(seg))
    assert e.value.code == "V-007"


def test_reader_ignores_part_files(tmp_path):
    (tmp_path / "a.jsonl.part").write_text("x")
    from pipeline.segment_reader import list_sealed
    assert list_sealed(tmp_path) == []


def test_ingest_and_total_accounting(tmp_path):
    seg = make_seg(tmp_path / "b")
    st = SilverStore(tmp_path / "s.duckdb")
    res = st.ingest_segment(seg, run_id="r1")
    c = counts(st)
    assert res["read"] == 4
    assert res["read"] == res["inserted"] + res["duplicates"] + res["quarantined"]
    assert sum(v for k, v in c.items() if k != "silver_quarantine_dlq") == res["inserted"]


def test_replay_is_idempotent(tmp_path):
    seg = make_seg(tmp_path / "b")
    st = SilverStore(tmp_path / "s.duckdb")
    st.ingest_segment(seg, run_id="r1")
    before = counts(st)
    r2 = st.ingest_segment(seg, run_id="r2")
    assert r2["status"] == "SKIPPED_ALREADY_INGESTED" and counts(st) == before


def test_same_events_in_new_segment_are_deduped(tmp_path):
    st = SilverStore(tmp_path / "s.duckdb")
    st.ingest_segment(make_seg(tmp_path / "b1"), run_id="r1")
    before = counts(st)
    r = st.ingest_segment(make_seg(tmp_path / "b2"), run_id="r2")
    assert r["inserted"] == 0 and r["duplicates"] == r["read"] and counts(st) == before


def test_tampered_segment_is_quarantined_not_ingested(tmp_path):
    seg = make_seg(tmp_path / "b")
    b = bytearray(seg.read_bytes()); b[5] ^= 1; seg.write_bytes(bytes(b))
    st = SilverStore(tmp_path / "s.duckdb")
    r = st.ingest_segment(seg, run_id="r1")
    assert r["status"] == "QUARANTINED_SEGMENT" and sum(counts(st).values()) == 0
    led = st.con.execute("select status from _ingest_ledger").fetchall()
    assert led == [("QUARANTINED_SEGMENT",)]


def test_bad_bronze_record_goes_to_dlq_with_payload(tmp_path):
    good = list(bc.iter_raw_xml_from_file(SYN))[0]
    bad = bc.build_bronze_record(good, mode="file", seq=9)
    bad["event_id"] = "00000000-0000-0000-0000-000000000000"  # giả mạo định danh
    seg = make_seg(tmp_path / "b", xmls=[], extra=[bad])
    st = SilverStore(tmp_path / "s.duckdb")
    r = st.ingest_segment(seg, run_id="r1")
    assert r["quarantined"] == 1 and counts(st)["silver_quarantine_dlq"] == 1
    code, payload = st.con.execute("select error_code, raw_payload from silver_quarantine_dlq").fetchone()
    assert code == "BRONZE_IDENTITY_MISMATCH" and "event_id" in payload


def test_failure_mid_transaction_rolls_back(tmp_path, monkeypatch):
    seg = make_seg(tmp_path / "b")
    st = SilverStore(tmp_path / "s.duckdb")
    orig = st._write_ledger
    def boom(*a, **k): raise RuntimeError("crash")
    monkeypatch.setattr(st, "_write_ledger", boom)
    with pytest.raises(RuntimeError):
        st.ingest_segment(seg, run_id="r1")
    assert sum(counts(st).values()) == 0
    monkeypatch.setattr(st, "_write_ledger", orig)
    assert st.ingest_segment(seg, run_id="r2")["status"] == "INGESTED"
