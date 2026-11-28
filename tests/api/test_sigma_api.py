"""API chỉ đọc cho rule Sigma (/sigma/rules) và bộ lọc nguồn Sigma trên /alerts. Dữ liệu SYNTHETIC."""
from datetime import datetime, timezone

from fastapi.testclient import TestClient

from alerts.store import AlertStore
from api.app import create_app
from api.auth import TokenStore, hash_token
from common.config import Config
from detection.loader import load_rules
from detection.sigma.loader import load_sigma
from pipeline.silver_store import SilverStore
from response.policy import Policy

ON = {"enabled": True, "allow_experimental": False, "max_rules": 50, "regex_max_length": 1000}
TOK = "tok-viewer-0123456789"


def client(tmp_path, sigma=None):
    st = SilverStore(tmp_path / "s.duckdb")
    rules = {**load_rules(), **(sigma.rules if sigma else {})}
    pol = Policy(mode="dry_run", execute_unlocked=False, allowed_actions=set(), protected_process_names=set(),
                 protected_dirs=[], lab_dirs=[tmp_path / "lab"], quarantine_dir=tmp_path / "lab" / "q")
    app = create_app(Config(home=tmp_path), TokenStore({hash_token(TOK): {"role": "viewer", "actor": "v"}}), store=st,
                     rules=rules, policy=pol, bronze_dir=tmp_path / "b", sigma_report=sigma.report if sigma else None)
    c = TestClient(app)
    return c, st


def auth(c):
    c.headers["Authorization"] = f"Bearer {TOK}"
    return c


def test_sigma_rules_listing_and_detail(tmp_path):
    c, _ = client(tmp_path, load_sigma(ON))
    assert c.get("/sigma/rules").status_code == 401
    auth(c)
    body = c.get("/sigma/rules").json()
    assert body["enabled"] is True and len(body["loaded"]) == 28 and body["rejected"] == []
    assert body["source"]["commit"].startswith("ddf1d4f87fd2") and "SIG-E002" in body["error_codes"]
    one = next(x for x in body["loaded"] if x["rule_id"] == "DACN-SIG-92626ddd")
    assert one["author"] and one["license"] == "DRL-1.1" and one["source_url"].endswith(".yml")
    assert not any(k.startswith("_") for x in body["loaded"] for k in x)          # đường dẫn nội bộ không lộ ra API
    d = c.get("/sigma/rules/DACN-SIG-92626ddd").json()
    assert d["summary"]["sigma_id"].startswith("92626ddd") and "detection:" in d["source_text"]
    assert d["rule"]["type"] == "sigma"
    assert c.get("/sigma/rules/DACN-SIG-00000000").status_code == 404


def test_sigma_rules_when_disabled_or_absent(tmp_path):
    c, _ = client(tmp_path, load_sigma({**ON, "enabled": False}))
    auth(c)
    body = c.get("/sigma/rules").json()
    assert body["enabled"] is False and all(x["active"] is False for x in body["loaded"])
    c2, _ = client(tmp_path / "x", None)
    auth(c2)
    assert c2.get("/sigma/rules").json() == {"enabled": False, "loaded": [], "rejected": [], "source": {},
                                              "note": "chưa nạp cấu hình Sigma"}


def test_alerts_source_filter_sigma(tmp_path):
    sig = load_sigma(ON)
    c, st = client(tmp_path, sig)
    auth(c)
    store = AlertStore(st.con)
    t = datetime(2026, 1, 1, tzinfo=timezone.utc)
    for key, src, rid in (("k1", "RULE", "DACN-DET-001"), ("k2", "SIGMA", "DACN-SIG-92626ddd"),
                          ("k3", "EXTERNAL_DEFENDER", "DACN-DET-201")):
        store.insert_alert(detection_dedup_key=key, group_key=key, first_seen_utc=t, last_seen_utc=t, detection_source=src,
                           rule_id=rid, rule_version=1, rule_name="n", severity="low", severity_reason="thử",
                           hostname="H", contributing_event_ids=["x"])
    allv = c.get("/alerts").json()["items"]
    assert {a["source_label"] for a in allv} == {"DACN", "Sigma", "Defender"}
    s = c.get("/alerts?source=SIGMA").json()["items"]
    assert [a["rule_id"] for a in s] == ["DACN-SIG-92626ddd"] and s[0]["source_label"] == "Sigma"
    n = c.get("/alerts?source=DACN").json()["items"]
    assert [a["rule_id"] for a in n] == ["DACN-DET-001"]
    assert len(c.get("/alerts?source=DEFENDER").json()["items"]) == 1
