import json
from pathlib import Path
from agent.runner import AgentRunner
from agent.bronze_writer import BronzeWriter, recover_dir, verify_segment
from agent.checkpoint import Checkpoint
from agent.sources.base import SourceError
from agent.sources.fake_source import FakeEventSource
import bronze_contract as bc

SYN = Path(__file__).resolve().parents[2] / "poc/sysmon-collector/configs/synthetic_events.xml"
XMLS = list(bc.iter_raw_xml_from_file(SYN))


def mk(tmp_path, src, **kw):
    return AgentRunner(src, BronzeWriter(tmp_path / "b", max_records=3),
                       Checkpoint(tmp_path / "cp.json"), tmp_path / "health.json", batch_size=2, **kw)


def ids(tmp_path):
    out = []
    for s in sorted((tmp_path / "b").glob("*.jsonl")):
        assert verify_segment(s) == []
        out += [json.loads(l)["event_id"] for l in s.read_text().splitlines()]
    return out


def test_full_run_writes_all_and_health(tmp_path):
    r = mk(tmp_path, FakeEventSource(XMLS)); r.run()
    assert len(ids(tmp_path)) == 4
    h = json.loads((tmp_path / "health.json").read_text())
    assert h["events_written"] == 4 and h["state"] == "stopped"


def test_stop_midway_then_restart_loses_nothing(tmp_path):
    mk(tmp_path, FakeEventSource(XMLS, stop_after=2)).run()
    mk(tmp_path, FakeEventSource(XMLS)).run()
    assert len(set(ids(tmp_path))) == 4


def test_crash_after_write_before_checkpoint_may_duplicate_not_lose(tmp_path):
    mk(tmp_path, FakeEventSource(XMLS)).run()
    (tmp_path / "cp.json").unlink()            # mô phỏng mất checkpoint
    mk(tmp_path, FakeEventSource(XMLS)).run()
    got = ids(tmp_path)
    assert len(got) == 8 and len(set(got)) == 4  # at-least-once; Silver dedup theo event_id


def test_bad_xml_is_counted_and_preserved_not_dropped(tmp_path):
    r = mk(tmp_path, FakeEventSource(["<Event><oops", XMLS[0]])); r.run()
    assert len(ids(tmp_path)) == 1
    h = json.loads((tmp_path / "health.json").read_text())
    assert h["errors_by_code"]["C-001"] == 1
    assert "<oops" in (tmp_path / "b" / "errors" / "collector_errors.jsonl").read_text()


def test_source_error_recorded_and_data_kept(tmp_path):
    r = mk(tmp_path, FakeEventSource(XMLS, fail_after=2)); r.run()
    h = json.loads((tmp_path / "health.json").read_text())
    assert h["errors_by_code"]["C-006"] == 1 and len(ids(tmp_path)) == 2


def test_stop_file_stops_loop(tmp_path):
    (tmp_path / "STOP").write_text("")
    r = mk(tmp_path, FakeEventSource(XMLS), stop_file=tmp_path / "STOP"); r.run()
    assert ids(tmp_path) == []


def test_corrupt_checkpoint_reported(tmp_path):
    (tmp_path / "cp.json").write_text("{bad")
    mk(tmp_path, FakeEventSource(XMLS)).run()
    h = json.loads((tmp_path / "health.json").read_text())
    assert h["errors_by_code"]["C-005"] == 1 and len(ids(tmp_path)) == 4
