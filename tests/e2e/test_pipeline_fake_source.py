"""Tích hợp end-to-end trên Linux bằng NGUỒN GIẢ (PH10-T03): FakeEventSource -> agent -> Bronze -> core -> Silver -> rule -> alert -> API -> evidence.
Đây KHÔNG thay cho kiểm chứng trên Windows thật: dữ liệu là XML synthetic, tên máy/người dùng giả."""
import json
import sys
import threading
from pathlib import Path

import pytest
import yaml
from fastapi.testclient import TestClient

sys.path.insert(0, str(Path(__file__).parent))
import scenario_xml as sx  # noqa: E402

from agent.bronze_writer import BronzeWriter, verify_segment  # noqa: E402
from agent.checkpoint import Checkpoint  # noqa: E402
from agent.runner import AgentRunner  # noqa: E402
from agent.sources.fake_source import FakeEventSource  # noqa: E402
from api.app import create_app  # noqa: E402
from api.auth import TokenStore, hash_token  # noqa: E402
from common.config import Config  # noqa: E402
from core.service import CoreService  # noqa: E402
from detection.loader import load_rules  # noqa: E402
from pipeline.segment_reader import list_sealed  # noqa: E402
from pipeline.silver_store import SilverStore  # noqa: E402
from response.policy import Policy  # noqa: E402

TOK = "tok-e2e-analyst-0123456789"


def run_agent(home: Path, xmls, **src_kw):
    r = AgentRunner(FakeEventSource(xmls, **src_kw), BronzeWriter(home / "bronze", max_records=3),
                    Checkpoint(home / "agent" / "cp.json"), home / "agent" / "health.json", batch_size=2)
    r.run()
    return r


def make_core(home: Path, db="silver.duckdb"):
    (home / "ioc").mkdir(exist_ok=True)
    (home / "ioc" / "ioc.yaml").write_text(yaml.safe_dump({"version": "e2e", "ioc_hashes": [{"sha256": sx.IOC_SHA, "source": "e2e-synthetic"}]}))
    st = SilverStore(home / db)
    return st, CoreService(st, home / "bronze", home / "metrics.jsonl", load_rules(), home / "ioc" / "ioc.yaml")


def alert_keys(st):
    return sorted(st.con.execute("select rule_id, detection_dedup_key from alerts").fetchall())


def api_client(st, svc, home):
    pol = Policy(mode="dry_run", execute_unlocked=False, allowed_actions=set(), protected_process_names=set(), protected_dirs=[],
                 lab_dirs=[home / "lab"], lab_marker_prefix="DACN_LAB_", quarantine_dir=home / "lab" / "q")
    app = create_app(Config(home=home), TokenStore({hash_token(TOK): {"role": "analyst", "actor": "e2e"}}), store=st, rules=svc.rules,
                     policy=pol, bronze_dir=home / "bronze", data_label="SAMPLE", lock=svc.lock)
    c = TestClient(app); c.headers["Authorization"] = f"Bearer {TOK}"
    return c


def test_full_chain_each_interface(tmp_path):
    xmls = sx.full_scenario()
    # 1. agent -> Bronze
    run_agent(tmp_path, xmls)
    segs = list_sealed(tmp_path / "bronze")
    assert len(segs) >= 3 and all(verify_segment(s) == [] for s in segs)
    assert sum(json.loads((s.with_suffix(".manifest.json")).read_text())["record_count"] for s in segs) == len(xmls)
    # 2. Bronze -> Silver -> detection -> alert
    st, svc = make_core(tmp_path)
    m = svc.cycle()
    assert m["records_read"] == len(xmls) and m["records_quarantined"] == 0
    silver_rows = sum(st.con.execute(f"select count(*) from {t}").fetchone()[0] for t in
                      ("silver_process_events", "silver_file_events", "silver_registry_events", "silver_network_events"))
    assert silver_rows == len(xmls) == st.con.execute("select count(*) from silver_event_lineage").fetchone()[0]
    by_rule = {}
    for r, _ in alert_keys(st):
        by_rule[r] = by_rule.get(r, 0) + 1
    assert by_rule == {"DACN-DET-001": 1, "DACN-DET-003": 1, "DACN-DET-010": 1, "DACN-DET-101": 1}, by_rule
    assert st.con.execute("select count(*) from coverage_gaps").fetchone()[0] == 1       # event 1 thiếu CommandLine
    # 3. API
    c = api_client(st, svc, tmp_path)
    items = c.get("/alerts").json()["items"]
    assert len(items) == 4 and all(a["status"] == "NEW" for a in items)
    ps = next(a for a in items if a["rule_id"] == "DACN-DET-001")
    assert ps["command_line"].endswith("AAAAAAAAAAAAAAAA") and ps["mitre_technique_ids"] == ["T1059.001"]
    # 4. evidence: alert -> Silver -> Bronze -> raw_xml đúng bằng XML do nguồn phát
    ev = c.get(f"/alerts/{ps['alert_id']}/evidence", params={"include_raw": "true"}).json()
    assert ev["status"] == "FULL" and ev["events"][0]["raw_xml"] == xmls[0]
    chain = next(a for a in items if a["rule_id"] == "DACN-DET-010")
    ev2 = c.get(f"/alerts/{chain['alert_id']}/evidence", params={"include_raw": "true"}).json()
    assert ev2["status"] == "FULL" and {e["raw_xml"] for e in ev2["events"]} == {xmls[2], xmls[3], xmls[4]}
    # 5. kịch bản lành tính không có alert nào gắn với nó
    benign_guid = sx.guid("sc06").strip("{}").lower()
    assert all(a["process_guid"] != benign_guid for a in items)
    # 6. health đo thật
    h = c.get("/health").json()
    assert h["pipeline"]["records_read"] == len(xmls) and h["agent"]["status"] == "REPORTED"
    assert h["agent"]["events_written"] == len(xmls) and h["agent"]["state"] == "stopped"


def test_interrupted_agent_then_restart_gives_same_alerts_as_uninterrupted(tmp_path):
    xmls = sx.full_scenario()
    ref = tmp_path / "ref"; ref.mkdir(); run_agent(ref, xmls)
    st_ref, svc_ref = make_core(ref); svc_ref.cycle()
    cut = tmp_path / "cut"; cut.mkdir()
    run_agent(cut, xmls, stop_after=3)            # dừng giữa chừng
    st, svc = make_core(cut); svc.cycle()
    run_agent(cut, xmls)                           # khởi động lại, tiếp tục từ checkpoint
    svc.cycle()
    assert alert_keys(st) == alert_keys(st_ref)
    ids = lambda s: sorted(r[0] for r in s.con.execute("select event_id from silver_process_events union all select event_id from silver_file_events union all select event_id from silver_registry_events").fetchall())
    assert ids(st) == ids(st_ref)                  # không mất, không trùng ở Silver


def test_replay_from_bronze_reproduces_alerts(tmp_path):
    run_agent(tmp_path, sx.full_scenario())
    st, svc = make_core(tmp_path); svc.cycle()
    st2, svc2 = make_core(tmp_path, db="replay.duckdb"); svc2.cycle()
    assert alert_keys(st) == alert_keys(st2)
    n = svc.cycle()
    assert n["alerts_created"] == 0 and n["records_read"] == 0      # chạy lại không tạo trùng


def test_corrupt_segment_quarantined_others_still_processed(tmp_path):
    xmls = sx.full_scenario()
    run_agent(tmp_path, xmls)
    segs = list_sealed(tmp_path / "bronze")
    data = bytearray(segs[0].read_bytes()); data[20] ^= 1; segs[0].write_bytes(bytes(data))
    st, svc = make_core(tmp_path)
    m = svc.cycle()
    assert m["segments_quarantined"] == 1 and m["segments_ingested"] == len(segs) - 1
    statuses = [r[0] for r in st.con.execute("select status from _ingest_ledger").fetchall()]
    assert statuses.count("QUARANTINED_SEGMENT") == 1
    assert m["records_read"] < len(xmls)            # phần bị hỏng không được đọc


def test_core_cycle_and_api_can_run_concurrently(tmp_path):
    run_agent(tmp_path, sx.full_scenario())
    st, svc = make_core(tmp_path)
    c = api_client(st, svc, tmp_path)
    errors, stop = [], threading.Event()

    def poll():
        while not stop.is_set():
            r = c.get("/alerts")
            if r.status_code != 200:
                errors.append(r.status_code)
    t = threading.Thread(target=poll); t.start()
    try:
        for _ in range(5):
            svc.cycle()
    finally:
        stop.set(); t.join()
    assert errors == [] and len(c.get("/alerts").json()["items"]) == 4
