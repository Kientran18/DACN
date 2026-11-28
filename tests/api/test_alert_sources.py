"""/alerts lọc theo nguồn phát hiện và trả source_label (hạng mục 9, docs/architecture/w8). Dữ liệu SYNTHETIC."""
from pathlib import Path

from fastapi.testclient import TestClient

import bronze_contract as bc
from agent.bronze_writer import BronzeWriter
from alerts.builder import build_from_results
from alerts.store import AlertStore
from api.app import create_app
from api.auth import TokenStore, hash_token
from common.config import Config
from detection.engine import DetectionEngine
from detection.loader import load_rules
from pipeline.silver_store import SilverStore
from response.policy import Policy

ROOT = Path(__file__).resolve().parents[2]
FIX = ROOT / "tests/fixtures/windows_channels"
SYN = ROOT / "poc/sysmon-collector/configs/synthetic_events.xml"


def test_source_filter_and_label(tmp_path):
    w = BronzeWriter(tmp_path / "b")
    for x in list(bc.iter_raw_xml_from_file(FIX / "defender_1116.synthetic.xml")) + list(bc.iter_raw_xml_from_file(SYN)):
        w.append(bc.build_bronze_record(x, mode="file"))
    w.seal()
    st = SilverStore(tmp_path / "s.duckdb")
    st.ingest_dir(tmp_path / "b", "t")
    rules = load_rules()
    store = AlertStore(st.con)
    build_from_results(store, rules, DetectionEngine(st.con, rules=rules).run(), st.con)
    from datetime import datetime, timezone
    t = datetime(2026, 1, 1, tzinfo=timezone.utc)
    store.insert_alert(detection_dedup_key="k-dacn", group_key="g", first_seen_utc=t, last_seen_utc=t, detection_source="RULE",
                       rule_id="DACN-DET-001", rule_version=1, rule_name="n", severity="low", severity_reason="thử",
                       hostname="H", contributing_event_ids=["x"])
    tok = "tok-viewer-0123456789"
    pol = Policy(mode="dry_run", execute_unlocked=False, allowed_actions=set(), protected_process_names=set(),
                 protected_dirs=[], lab_dirs=[tmp_path / "lab"], quarantine_dir=tmp_path / "lab" / "q")
    app = create_app(Config(home=tmp_path), TokenStore({hash_token(tok): {"role": "viewer", "actor": "v"}}), store=st,
                     rules=rules, policy=pol, bronze_dir=tmp_path / "b")
    c = TestClient(app)
    c.headers["Authorization"] = f"Bearer {tok}"
    allv = c.get("/alerts").json()["items"]
    assert {a["source_label"] for a in allv} == {"Defender", "DACN"}
    d = c.get("/alerts?source=DEFENDER").json()["items"]
    assert d and all(a["source_label"] == "Defender" and a["detection_source"] == "EXTERNAL_DEFENDER" for a in d)
    n = c.get("/alerts?source=DACN").json()["items"]
    assert n and all(a["source_label"] == "DACN" for a in n)
    assert len(d) + len(n) == len(allv)
    assert c.get("/alerts?source=OTHER").status_code == 422
    assert c.get(f"/alerts/{d[0]['alert_id']}").json()["source_label"] == "Defender"
