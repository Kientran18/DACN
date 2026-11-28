"""Chấm điểm rủi ro tổng hợp (src/risk). Dữ liệu SYNTHETIC; trọng số là heuristic chưa hiệu chỉnh."""
from pathlib import Path

import pytest
import yaml

from risk.config import RiskConfigError, load_risk_config
from risk.scoring import Component, score_components

ROOT = Path(__file__).resolve().parents[2]


@pytest.fixture
def cfg():
    return load_risk_config()


def comp(cat, **kw):
    base = {"category": cat, "ref_type": "alert", "ref_id": f"{cat}-{kw.get('severity') or kw.get('ml_score')}",
            "label": cat}
    return Component(**{**base, **kw})


# ---- cấu hình có phiên bản -------------------------------------------------------------
def test_default_config_is_versioned_and_labelled_uncalibrated(cfg):
    assert cfg.version == 2 and cfg.status == "heuristic_uncalibrated"        # v2: thêm EXTERNAL_AV (2026-11-28)
    assert len(cfg.sha256) == 64
    assert cfg.data["weights"]["RULE"] == 1.0


def test_config_rejects_unknown_key_and_bad_values(tmp_path):
    raw = yaml.safe_load((ROOT / "config/risk-scoring.yaml").read_text(encoding="utf-8"))
    bad = dict(raw, surprise=1)
    p = tmp_path / "r.yaml"
    p.write_text(yaml.safe_dump(bad), encoding="utf-8")
    with pytest.raises(RiskConfigError):
        load_risk_config(p)
    bad = dict(raw, weights={**raw["weights"], "RULE": -1})
    p.write_text(yaml.safe_dump(bad), encoding="utf-8")
    with pytest.raises(RiskConfigError):
        load_risk_config(p)
    bad = dict(raw, level_thresholds={"low": 50, "medium": 30, "high": 60, "critical": 85})
    p.write_text(yaml.safe_dump(bad), encoding="utf-8")
    with pytest.raises(RiskConfigError, match="tăng dần"):
        load_risk_config(p)


def test_config_must_say_uncalibrated(tmp_path):
    raw = yaml.safe_load((ROOT / "config/risk-scoring.yaml").read_text(encoding="utf-8"))
    p = tmp_path / "r.yaml"
    p.write_text(yaml.safe_dump(dict(raw, status="calibrated")), encoding="utf-8")
    with pytest.raises(RiskConfigError):
        load_risk_config(p)


# ---- công thức ---------------------------------------------------------------------------
def test_single_medium_rule_is_explained(cfg):
    r = score_components([comp("RULE", severity="medium")], cfg)
    assert r["score"] == 25 and r["level"] == "low"
    c = r["components"][0]
    assert c["base_points"] == 25 and c["weight"] == 1.0 and c["points"] == 25 and c["included"] is True
    assert "severity=medium" in c["reason"]
    assert r["config"]["version"] == 2 and r["config"]["status"] == "heuristic_uncalibrated"
    assert r["triggers_response"] is False


def test_category_cap_limits_many_alerts_of_same_kind(cfg):
    r = score_components([comp("RULE", severity="high", ref_id=str(i)) for i in range(5)], cfg)
    assert r["score"] == 60
    assert r["categories"]["RULE"] == {"raw": 225.0, "capped": 60.0, "cap": 60}


def test_independent_mechanisms_get_diversity_bonus(cfg):
    r = score_components([comp("RULE", severity="medium"), comp("IOC", severity="high")], cfg)
    assert r["diversity_bonus"] == 10
    assert r["score"] == 80 and r["level"] == "high"


def test_ml_alone_cannot_exceed_low_and_gets_no_bonus(cfg):
    r = score_components([comp("ML_STATIC", ref_type="ml_signal", ml_score=1.0),
                          comp("ML_BEHAVIOR", ref_type="ml_signal", ml_score=1.0)], cfg)
    assert r["diversity_bonus"] == 0
    assert r["score"] == 24 and r["level"] == "low"


def test_correlation_weight_applies(cfg):
    r = score_components([comp("CORRELATION", severity="high")], cfg)
    assert r["score"] == 54.0 and r["components"][0]["weight"] == 1.2


def test_excluded_component_has_reason_and_no_points(cfg):
    r = score_components([comp("RULE", severity="high", included=False, exclude_reason="alert FALSE_POSITIVE")], cfg)
    assert r["score"] == 0 and r["level"] == "NONE"
    assert r["components"][0]["points"] == 0 and r["components"][0]["reason"].endswith("alert FALSE_POSITIVE")


def test_allowlist_reduces_with_reason(cfg):
    r = score_components([comp("RULE", severity="high", allowlist_reason="hash trong allowlist cục bộ")], cfg)
    c = r["components"][0]
    assert c["allowlist_factor"] == 0.3 and c["points"] == pytest.approx(13.5)
    assert "allowlist" in c["reason"]


def test_no_signal_is_none_and_lists_what_was_not_evaluated(cfg):
    r = score_components([], cfg, not_evaluated=[{"source": "ML_STATIC", "reason": "DISABLED"}],
                         data_gaps=[{"rule_id": "DACN-DET-001", "missing_fields": ["command_line"]}])
    assert r["score"] == 0 and r["level"] == "NONE"
    assert r["not_evaluated"] == [{"source": "ML_STATIC", "reason": "DISABLED"}]
    assert r["completeness"] == "PARTIAL"
    assert r["data_gaps"][0]["missing_fields"] == ["command_line"]


def test_ml_component_without_score_is_rejected(cfg):
    with pytest.raises(ValueError):
        score_components([comp("ML_STATIC", ref_type="ml_signal", ml_score=None)], cfg)


def test_score_never_exceeds_100(cfg):
    comps = [comp(c, severity="critical", ref_id=c) for c in ("RULE", "CORRELATION", "IOC", "STATIC")]
    r = score_components(comps, cfg)
    assert r["score"] == 100 and r["level"] == "critical"
