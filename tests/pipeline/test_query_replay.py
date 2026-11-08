import json
from pathlib import Path
import bronze_contract as bc
from agent.bronze_writer import BronzeWriter
from pipeline.silver_store import SilverStore
from pipeline.query import Query
from pipeline.replay import replay
from pipeline.worker import IngestWorker
from pipeline.quality import quality_metrics

SYN = Path(__file__).resolve().parents[2] / "poc/sysmon-collector/configs/synthetic_events.xml"


def build(d):
    w = BronzeWriter(d)
    for i, x in enumerate(bc.iter_raw_xml_from_file(SYN)):
        w.append(bc.build_bronze_record(x, mode="file", seq=i))
    return w.seal()


def test_replay_rebuilds_same_event_ids(tmp_path):
    build(tmp_path / "b")
    a = SilverStore(tmp_path / "a.duckdb"); a.ingest_dir(tmp_path / "b", "r1")
    rep = replay(tmp_path / "b", tmp_path / "new.duckdb")
    b = SilverStore(tmp_path / "new.duckdb")
    q = "select event_id from silver_process_events union all select event_id from silver_file_events " \
        "union all select event_id from silver_registry_events union all select event_id from silver_network_events"
    assert sorted(a.con.execute(q).fetchall()) == sorted(b.con.execute(q).fetchall())
    assert rep["inserted"] == 4


def test_replay_refuses_existing_target(tmp_path):
    import pytest
    build(tmp_path / "b"); (tmp_path / "x.duckdb").write_text("")
    with pytest.raises(FileExistsError):
        replay(tmp_path / "b", tmp_path / "x.duckdb")


def test_query_events_parameterized_and_paged(tmp_path):
    build(tmp_path / "b")
    st = SilverStore(tmp_path / "s.duckdb"); st.ingest_dir(tmp_path / "b", "r")
    q = Query(st.con)
    rows = q.events("silver_process_events", limit=1, offset=0)
    assert len(rows) <= 1
    # chuỗi giống SQL injection chỉ là giá trị, không làm hỏng truy vấn
    assert q.events("silver_process_events", image_path="x'; drop table silver_process_events;--") == []
    assert st.con.execute("select count(*) from silver_process_events").fetchone()[0] >= 0


def test_query_rejects_unknown_table_and_filter(tmp_path):
    import pytest
    q = Query(SilverStore(tmp_path / "s.duckdb").con)
    with pytest.raises(ValueError):
        q.events("users")
    with pytest.raises(ValueError):
        q.events("silver_process_events", bogus=1)


def test_worker_ingests_new_segments_once_and_writes_metrics(tmp_path):
    build(tmp_path / "b")
    w = IngestWorker(tmp_path / "b", SilverStore(tmp_path / "s.duckdb"), tmp_path / "metrics.jsonl")
    w.run_once(); w.run_once()
    lines = [json.loads(l) for l in (tmp_path / "metrics.jsonl").read_text().splitlines()]
    assert lines[0]["segments_ingested"] == 1 and lines[0]["records_inserted"] == 4
    assert lines[1]["segments_ingested"] == 0


def test_quality_metrics_report_measured_values_only(tmp_path):
    build(tmp_path / "b")
    st = SilverStore(tmp_path / "s.duckdb"); st.ingest_dir(tmp_path / "b", "r")
    m = quality_metrics(st.con)
    assert m["records_read"] == 4 and m["quarantine_ratio"] == 0.0
    assert "slo_met" not in m
