"""Công thức điểm rủi ro tổng hợp (thuần, không I/O). Mọi điểm đều truy được về thành phần, nguồn, trọng số, lý do.

score = min(100, Σ_nhóm min(Σ điểm_thành_phần, trần_nhóm) + thưởng_đa_dạng)
điểm_thành_phần = điểm_gốc × trọng_số_nhóm × hệ_số_allowlist (0 nếu bị loại có lý do)
  điểm_gốc: alert → severity_points[severity]; tín hiệu ML → ml_score × ml_max_points[nhóm]
thưởng_đa_dạng = min(max, per_extra_category × (số nhóm KHÔNG phải ML có điểm > 0 − 1))
Heuristic chưa hiệu chỉnh. Kết quả KHÔNG kích hoạt response (triggers_response luôn False)."""
from __future__ import annotations

from dataclasses import dataclass, field
from typing import Dict, List, Optional

from .config import CATEGORIES, LEVELS, ML_CATEGORIES, RiskConfig


@dataclass
class Component:
    category: str                       # RULE | CORRELATION | IOC | STATIC | EXTERNAL_AV | ML_STATIC | ML_BEHAVIOR
    ref_type: str                       # alert | ml_signal
    ref_id: str
    label: str = ""
    severity: Optional[str] = None      # với alert
    ml_score: Optional[float] = None    # với tín hiệu ML, trong [0,1]
    included: bool = True
    exclude_reason: str = ""
    allowlist_reason: str = ""          # khác rỗng => áp hệ số allowlist
    observed_at: Optional[object] = None
    hostname: Optional[str] = None
    process_guid: Optional[str] = None
    details: Dict[str, object] = field(default_factory=dict)


def _r(x: float) -> float:
    return round(float(x), 4)


def _level(score: float, cfg: RiskConfig) -> str:
    th, out = cfg.data["level_thresholds"], "NONE"
    for lv in LEVELS:
        if score >= th[lv]:
            out = lv
    return out


def explain(c: Component, cfg: RiskConfig) -> dict:
    if c.category not in CATEGORIES:
        raise ValueError(f"nhóm không hỗ trợ: {c.category}")
    d = cfg.data
    if c.category in ML_CATEGORIES:
        if c.ml_score is None or not 0.0 <= float(c.ml_score) <= 1.0:
            raise ValueError("tín hiệu ML phải có ml_score trong [0,1]; không chấm được thì để ở not_evaluated")
        base = float(c.ml_score) * d["ml_max_points"][c.category]
        why = f"điểm ML={_r(c.ml_score)} × tối đa {d['ml_max_points'][c.category]} (mô hình nháp, chưa hiệu chỉnh)"
    else:
        if c.severity not in d["severity_points"]:
            raise ValueError(f"severity không hợp lệ: {c.severity}")
        base = float(d["severity_points"][c.severity])
        why = f"severity={c.severity} do rule gán"
    weight = d["weights"][c.category]
    factor = d["allowlist_factor"] if c.allowlist_reason else 1.0
    points = base * weight * factor if c.included else 0.0
    why += f"; trọng số {c.category}={weight}"
    if c.allowlist_reason:
        why += f"; × {factor} vì {c.allowlist_reason}"
    if not c.included:
        why += f"; KHÔNG tính: {c.exclude_reason}"
    return {"category": c.category, "ref_type": c.ref_type, "ref_id": c.ref_id, "label": c.label,
            "severity": c.severity, "ml_score": c.ml_score, "base_points": _r(base), "weight": weight,
            "allowlist_factor": factor, "points": _r(points), "included": c.included, "reason": why,
            "observed_at": c.observed_at.isoformat() if hasattr(c.observed_at, "isoformat") else c.observed_at,
            "hostname": c.hostname, "process_guid": c.process_guid, "details": c.details}


def score_components(components: List[Component], cfg: RiskConfig, *, not_evaluated: Optional[List[dict]] = None,
                     data_gaps: Optional[List[dict]] = None) -> dict:
    d = cfg.data
    rows = [explain(c, cfg) for c in components]
    cats: Dict[str, dict] = {}
    for row in rows:
        cats.setdefault(row["category"], {"raw": 0.0, "capped": 0.0, "cap": d["category_caps"][row["category"]]})
        cats[row["category"]]["raw"] = _r(cats[row["category"]]["raw"] + row["points"])
    for v in cats.values():
        v["capped"] = _r(min(v["raw"], v["cap"]))
    independent = [k for k, v in cats.items() if k not in ML_CATEGORIES and v["capped"] > 0]
    bonus = min(d["diversity_bonus"]["max"], d["diversity_bonus"]["per_extra_category"] * max(0, len(independent) - 1))
    score = _r(min(100.0, sum(v["capped"] for v in cats.values()) + bonus))
    not_evaluated, data_gaps = list(not_evaluated or []), list(data_gaps or [])
    return {"score": score, "level": _level(score, cfg), "categories": cats, "diversity_bonus": bonus,
            "components": rows, "not_evaluated": not_evaluated, "data_gaps": data_gaps,
            "completeness": "PARTIAL" if (not_evaluated or data_gaps) else "FULL",
            "config": cfg.summary(), "triggers_response": False,
            "formula": "min(100, Σ_nhóm min(Σ điểm, trần) + thưởng đa dạng (không tính ML)); "
                       "điểm = gốc × trọng số × hệ số allowlist"}
