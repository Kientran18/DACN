"""Nhóm rủi ro SIGMA (config risk-scoring.yaml v3, người dùng duyệt 2026-11-28): trọng số 1.0, trần 40, KHÔNG tính thưởng
đa dạng cùng RULE (cùng là rule trên cùng telemetry, không độc lập). Heuristic chưa hiệu chỉnh; dữ liệu SYNTHETIC."""
import pytest
import yaml
from pathlib import Path

from risk.config import RiskConfigError, load_risk_config
from risk.scoring import Component, score_components
from risk.service import RiskService

ROOT = Path(__file__).resolve().parents[2]


@pytest.fixture
def cfg():
    return load_risk_config()


def comp(cat, sev="medium", rid="a"):
    return Component(category=cat, ref_type="alert", ref_id=rid, severity=sev, label=cat)


def test_config_v3_has_sigma(cfg):
    assert cfg.version == 3
    assert cfg.data["weights"]["SIGMA"] == 1.0 and cfg.data["category_caps"]["SIGMA"] == 40


def test_sigma_points_and_cap(cfg):
    r = score_components([comp("SIGMA")], cfg)
    assert r["score"] == 25 and r["triggers_response"] is False
    many = score_components([comp("SIGMA", "critical", str(i)) for i in range(3)], cfg)
    assert many["categories"]["SIGMA"]["capped"] == 40


def test_sigma_and_rule_are_not_independent_for_diversity(cfg):
    r = score_components([comp("SIGMA"), comp("RULE", rid="b")], cfg)
    assert r["diversity_bonus"] == 0 and r["score"] == 50
    r = score_components([comp("SIGMA"), comp("IOC", rid="b")], cfg)
    assert r["diversity_bonus"] == 10                         # SIGMA + cơ chế khác RULE: vẫn được thưởng
    r = score_components([comp("SIGMA"), comp("RULE", rid="b"), comp("IOC", rid="c")], cfg)
    assert r["diversity_bonus"] == 10                         # {RULE/SIGMA, IOC} = 2 nhóm độc lập


def test_config_without_sigma_rejected(tmp_path):
    raw = yaml.safe_load((ROOT / "config/risk-scoring.yaml").read_text(encoding="utf-8"))
    raw["category_caps"].pop("SIGMA")
    p = tmp_path / "r.yaml"
    p.write_text(yaml.safe_dump(raw), encoding="utf-8")
    with pytest.raises(RiskConfigError, match="category_caps"):
        load_risk_config(p)


def test_service_maps_sigma_alert_to_sigma_category(cfg):
    svc = RiskService.__new__(RiskService)
    svc.rules = {"DACN-SIG-92626ddd": {"type": "sigma"}}
    a = {"rule_id": "DACN-SIG-92626ddd", "detection_source": "SIGMA"}
    assert svc._category(a) == "SIGMA"
