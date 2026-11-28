"""Hạng mục 4 (docs/architecture/w8 mục 4.6): nối sự kiện Defender/PowerShell với tiến trình Sysmon. Suy luận tính khi truy vấn,
không ghi DB. Dữ liệu SYNTHETIC."""
import json
import sys
from pathlib import Path

import pytest
from fastapi.testclient import TestClient

HERE = Path(__file__).resolve().parent
sys.path.insert(0, str(HERE.parent / "detection"))
import harness  # noqa: E402

import bronze_contract as bc  # noqa: E402
from agent.bronze_writer import BronzeWriter  # noqa: E402
from alerts.builder import build_from_results  # noqa: E402
from alerts.process_link import link_defender, link_powershell, links_for_alert  # noqa: E402
from alerts.store import AlertStore  # noqa: E402
from api.app import create_app  # noqa: E402
from api.auth import TokenStore, hash_token  # noqa: E402
from common.config import Config  # noqa: E402
from detection.engine import DetectionEngine  # noqa: E402
from detection.loader import load_rules  # noqa: E402
from pipeline.silver_store import SilverStore  # noqa: E402
from response.policy import Policy  # noqa: E402

ROOT = HERE.parents[1]
FIX = ROOT / "tests/fixtures/windows_channels"
PS_IMG = "C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe"
EICAR = "C:\\Users\\labuser\\AppData\\Local\\Temp\\dacn_lab\\eicar_sample.txt"
G = lambda i: f"dddddddd-0000-0000-0000-{i:012d}"      # noqa: E731
H = "SYNTH-HOST"


def store_with(tmp_path, fixtures, rows):
    st = SilverStore(tmp_path / "s.duckdb")
    w = BronzeWriter(tmp_path / "b")
    for n in fixtures:
        for x in bc.iter_raw_xml_from_file(FIX / n):
            w.append(bc.build_bronze_record(x, mode="file"))
    st.ingest_segment(w.seal(), "t")
    for i, r in enumerate(rows):
        for t, _, row in harness.build_rows({"name": f"pl{i}", "rows": [{"id": "x", "hostname": H, "record_id": 5000 + i, **r}]}):
            st._insert(t, row)
    return st


def ps_start(i, pid, ts, img=PS_IMG):
    return {"table": "process", "process_guid": G(i), "pid": pid, "image_path": img, "timestamp": ts}


def row(st, table):
    cur = st.con.execute(f"select * from {table} order by record_id limit 1")
    return dict(zip([c[0] for c in cur.description], cur.fetchone()))


def guids(link):
    return [c["process_guid"] for c in link["candidates"]]


def test_powershell_unique_by_pid_and_image_ignores_pid_reuse_with_other_image(tmp_path):
    st = store_with(tmp_path, ["ps4104_single.synthetic.xml"], [
        ps_start(1, 3333, "2026-11-28T00:59:00+00:00"),
        ps_start(2, 3333, "2026-11-28T00:58:00+00:00", img="C:\\Windows\\notepad.exe")])        # cùng PID, khác ảnh
    link = link_powershell(st.con, row(st, "silver_powershell_scriptblock_events"))
    assert link["confidence"] == "UNIQUE" and guids(link) == [G(1)] and link["method"] == "PID_IMAGE_LIFETIME"


def test_powershell_pid_reuse_same_image_is_ambiguous_until_terminated(tmp_path):
    rows = [ps_start(1, 3333, "2026-11-28T00:59:00+00:00"), ps_start(2, 3333, "2026-11-28T00:30:00+00:00")]
    st = store_with(tmp_path, ["ps4104_single.synthetic.xml"], rows)
    assert link_powershell(st.con, row(st, "silver_powershell_scriptblock_events"))["confidence"] == "AMBIGUOUS"
    st2 = store_with(tmp_path / "b", ["ps4104_single.synthetic.xml"], rows + [
        {"table": "process", "process_guid": G(2), "pid": 3333, "image_path": PS_IMG, "sysmon_event_id": 5,
         "event_type": "PROCESS_TERMINATE", "timestamp": "2026-11-28T00:40:00+00:00"}])
    link = link_powershell(st2.con, row(st2, "silver_powershell_scriptblock_events"))
    assert link["confidence"] == "UNIQUE" and guids(link) == [G(1)]


def test_powershell_none_when_process_starts_after_or_outside_lookback(tmp_path):
    st = store_with(tmp_path, ["ps4104_single.synthetic.xml"], [
        ps_start(1, 3333, "2026-11-28T02:00:00+00:00"),                 # sau sự kiện
        ps_start(2, 3333, "2026-11-26T00:00:00+00:00")])                # quá 24 giờ
    assert link_powershell(st.con, row(st, "silver_powershell_scriptblock_events"))["confidence"] == "NONE"


def test_defender_by_process_name_and_by_file(tmp_path):
    st = store_with(tmp_path, ["defender_1116.synthetic.xml"], [
        ps_start(1, 3333, "2026-11-28T00:59:00+00:00"),
        ps_start(2, 4444, "2026-11-28T00:58:00+00:00"),
        {"table": "file", "process_guid": G(1), "file_path": EICAR, "image_path": PS_IMG, "timestamp": "2026-11-28T01:01:30+00:00"}])
    by_name, by_file = link_defender(st.con, row(st, "silver_defender_events"))
    assert by_name["method"] == "PROCESS_NAME_LIFETIME" and by_name["confidence"] == "AMBIGUOUS"     # hai powershell còn sống
    assert sorted(guids(by_name)) == [G(1), G(2)]
    assert by_file["method"] == "FILE_CREATE" and by_file["confidence"] == "UNIQUE" and guids(by_file) == [G(1)]


def test_defender_unknown_process_is_not_applicable(tmp_path):
    st = store_with(tmp_path, ["defender_1116_cmdline.synthetic.xml"], [ps_start(1, 3333, "2026-11-28T00:59:00+00:00")])
    (by_name,) = link_defender(st.con, row(st, "silver_defender_events"))   # CmdLine: không có nối theo tệp
    assert by_name["confidence"] == "NOT_APPLICABLE" and by_name["candidates"] == []


def test_links_for_alert_one_link_per_script_block(tmp_path):
    st = store_with(tmp_path, ["ps4104_three_parts.synthetic.xml"], [ps_start(1, 3333, "2026-11-28T01:00:00+00:00")])
    ids = [r[0] for r in st.con.execute("select event_id from silver_powershell_scriptblock_events").fetchall()]
    out = links_for_alert(st.con, ids)
    assert len(out["events"]) == 1 and out["kind"] == "INFERENCE"
    assert out["events"][0]["links"][0]["confidence"] == "UNIQUE"


def test_api_process_links_reads_only_and_never_sets_alert_guid(tmp_path):
    st = store_with(tmp_path, ["defender_1116.synthetic.xml", "defender_1117.synthetic.xml"], [ps_start(1, 3333, "2026-11-28T00:59:00+00:00")])
    rules = load_rules()
    store = AlertStore(st.con)
    out = build_from_results(store, rules, DetectionEngine(st.con, rules=rules).run(), st.con)
    (aid,) = out["alerts"]
    tok = "tok-viewer-0123456789"
    pol = Policy(mode="dry_run", execute_unlocked=False, allowed_actions=set(), protected_process_names=set(),
                 protected_dirs=[], lab_dirs=[tmp_path / "lab"], quarantine_dir=tmp_path / "lab" / "q")
    app = create_app(Config(home=tmp_path), TokenStore({hash_token(tok): {"role": "viewer", "actor": "v"}}), store=st,
                     rules=rules, policy=pol, bronze_dir=tmp_path / "b")
    c = TestClient(app)
    c.headers["Authorization"] = f"Bearer {tok}"
    r = c.get(f"/alerts/{aid}/process-links")
    assert r.status_code == 200
    body = r.json()
    assert len(body["events"]) == 2                                    # 1116 và 1117
    assert {e["links"][0]["confidence"] for e in body["events"]} == {"UNIQUE"}
    assert body["events"][0]["links"][0]["candidates"][0]["process_guid"] == G(1)
    assert store.get(aid)["process_guid"] is None                      # không ghi suy luận vào alert
    assert c.get("/alerts/khong-co/process-links").status_code == 404
    assert "script_block_text" not in json.dumps(body)


@pytest.mark.parametrize("bad", ["", None, "2026-11-28 01:00"])       # không có múi giờ / rỗng -> không đoán
def test_unparseable_time_is_not_applicable(bad):
    assert link_powershell(None, {"writer_process_id": 1, "timestamp": bad, "hostname": H})["confidence"] == "NOT_APPLICABLE"
