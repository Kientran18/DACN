"""Cơ chế rủi ro EXTERNAL_AV (hạng mục 7, docs/architecture/w8 D7): alert Defender (detection_source EXTERNAL_DEFENDER).
Heuristic chưa hiệu chỉnh; dữ liệu SYNTHETIC. Điểm rủi ro không kích hoạt response."""
import sys
from pathlib import Path

import pytest
import yaml

HERE = Path(__file__).resolve().parent
sys.path.insert(0, str(HERE.parent / "detection"))
import harness  # noqa: E402

import bronze_contract as bc  # noqa: E402
from agent.bronze_writer import BronzeWriter  # noqa: E402
from alerts.builder import build_from_results  # noqa: E402
from alerts.store import AlertStore  # noqa: E402
from detection.engine import DetectionEngine  # noqa: E402
from detection.loader import load_rules  # noqa: E402
from pipeline.silver_store import SilverStore  # noqa: E402
from risk.config import RiskConfigError, load_risk_config  # noqa: E402
from risk.scoring import Component, score_components  # noqa: E402
from risk.service import RiskService  # noqa: E402

ROOT = HERE.parents[1]
FIX = ROOT / "tests/fixtures/windows_channels"


@pytest.fixture
def cfg():
    return load_risk_config()


def comp(cat, sev="medium", rid="a"):
    return Component(category=cat, ref_type="alert", ref_id=rid, severity=sev, label=cat)


def test_external_av_points_and_diversity_bonus(cfg):
    r = score_components([comp("EXTERNAL_AV")], cfg)
    assert r["score"] == 25 and r["diversity_bonus"] == 0
    assert "trọng số EXTERNAL_AV=1.0" in r["components"][0]["reason"]
    r = score_components([comp("EXTERNAL_AV"), comp("RULE", rid="b")], cfg)
    assert r["score"] == 25 + 25 + 10 and r["diversity_bonus"] == 10      # hai cơ chế độc lập
    many = score_components([comp("EXTERNAL_AV", "critical", str(i)) for i in range(3)], cfg)
    assert many["categories"]["EXTERNAL_AV"]["capped"] == 60 and many["triggers_response"] is False


def test_config_without_external_av_is_rejected(tmp_path):
    raw = yaml.safe_load((ROOT / "config/risk-scoring.yaml").read_text(encoding="utf-8"))
    raw["weights"].pop("EXTERNAL_AV")
    p = tmp_path / "r.yaml"
    p.write_text(yaml.safe_dump(raw), encoding="utf-8")
    with pytest.raises(RiskConfigError, match="weights"):
        load_risk_config(p)


def test_defender_alert_scores_as_external_av_on_host_subject(tmp_path, cfg):
    st = SilverStore(tmp_path / "s.duckdb")
    w = BronzeWriter(tmp_path / "b")
    for n in ("defender_1116.synthetic.xml", "defender_1117.synthetic.xml"):
        for x in bc.iter_raw_xml_from_file(FIX / n):
            w.append(bc.build_bronze_record(x, mode="file"))
    st.ingest_segment(w.seal(), "t")
    for t, _, row in harness.build_rows({"name": "ext", "rows": [{
            "id": "p", "table": "process", "hostname": "SYNTH-HOST", "image_path": "C:\\a\\powershell.exe",
            "command_line": "powershell.exe -enc AAAAAAAA", "timestamp": "2026-11-28T01:30:00+00:00"}]}):
        st._insert(t, row)
    rules = load_rules()
    store = AlertStore(st.con)
    build_from_results(store, rules, DetectionEngine(st.con, rules=rules).run(), st.con)
    svc = RiskService(st.con, rules, cfg)
    host = svc.host("SYNTH-HOST")
    cats = {c["category"]: c for c in host["components"]}
    assert set(cats) == {"EXTERNAL_AV", "RULE"}
    assert cats["EXTERNAL_AV"]["label"].startswith("DACN-DET-201") and cats["EXTERNAL_AV"]["process_guid"] is None
    assert host["diversity_bonus"] == 10 and host["triggers_response"] is False
    ext_alert = cats["EXTERNAL_AV"]["ref_id"]
    assert svc.for_alert(ext_alert)["subject"]["kind"] == "host"          # không có process_guid
    assert all(i["subject"]["process_guid"] != None for i in svc.subjects("process"))  # noqa: E711
