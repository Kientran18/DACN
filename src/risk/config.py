"""Nạp cấu hình chấm điểm rủi ro (có phiên bản, kiểm hợp lệ chặt). Heuristic chưa hiệu chỉnh."""
from __future__ import annotations

import hashlib
from dataclasses import dataclass
from pathlib import Path
from typing import Optional

import yaml

DEFAULT_PATH = Path(__file__).resolve().parents[2] / "config" / "risk-scoring.yaml"
# EXTERNAL_AV: alert phản ánh phát hiện của sản phẩm khác trên máy (Microsoft Defender, rule detection_source EXTERNAL_DEFENDER;
# docs/architecture/w8 D7). Không phải ML nên được tính vào thưởng đa dạng như một cơ chế độc lập với rule của DACN.
# SIGMA: alert của rule cộng đồng Sigma (detection_source SIGMA, docs/implementation/SIGMA_RULES.md; config v3).
CATEGORIES = ("RULE", "CORRELATION", "IOC", "STATIC", "EXTERNAL_AV", "SIGMA", "ML_STATIC", "ML_BEHAVIOR")
# Nhóm cùng bản chất khi tính thưởng đa dạng: SIGMA và RULE đều là rule trên cùng telemetry -> tính là MỘT cơ chế.
DIVERSITY_GROUP = {"SIGMA": "RULE"}
ML_CATEGORIES = ("ML_STATIC", "ML_BEHAVIOR")
SEVERITIES = ("low", "medium", "high", "critical")
LEVELS = ("low", "medium", "high", "critical")
_KEYS = {"version", "status", "changelog", "severity_points", "ml_max_points", "weights", "category_caps",
         "diversity_bonus", "allowlist_factor", "level_thresholds", "host_window_seconds"}


class RiskConfigError(ValueError):
    pass


@dataclass(frozen=True)
class RiskConfig:
    data: dict
    sha256: str

    @property
    def version(self) -> int:
        return self.data["version"]

    @property
    def status(self) -> str:
        return self.data["status"]

    def summary(self) -> dict:
        return {"version": self.version, "status": self.status, "sha256": self.sha256,
                "note": "heuristic chưa hiệu chỉnh trên dữ liệu có nhãn của DACN; không kích hoạt response"}


def _num(v, where, lo=0.0, hi=None):
    if isinstance(v, bool) or not isinstance(v, (int, float)) or v < lo or (hi is not None and v > hi):
        raise RiskConfigError(f"RISK-CFG: {where} phải là số trong [{lo}, {hi if hi is not None else '∞'}]")
    return v


def _map(d, keys, where, **kw):
    if not isinstance(d, dict) or set(d) != set(keys):
        raise RiskConfigError(f"RISK-CFG: {where} phải có đúng các khóa {list(keys)}")
    for k in keys:
        _num(d[k], f"{where}.{k}", **kw)
    return d


def validate(data: dict) -> dict:
    if not isinstance(data, dict):
        raise RiskConfigError("RISK-CFG: cấu hình phải là mapping")
    extra, missing = set(data) - _KEYS, _KEYS - set(data) - {"changelog"}
    if extra or missing:
        raise RiskConfigError(f"RISK-CFG: khóa thừa {sorted(extra)} / thiếu {sorted(missing)}")
    if not isinstance(data["version"], int) or isinstance(data["version"], bool) or data["version"] < 1:
        raise RiskConfigError("RISK-CFG: version phải là số nguyên >= 1")
    if data["status"] != "heuristic_uncalibrated":
        # Chỉ đổi khi có hiệu chỉnh đo được trên dữ liệu có nhãn và được Cyber/Data duyệt.
        raise RiskConfigError("RISK-CFG: status phải là 'heuristic_uncalibrated' (chưa có hiệu chỉnh)")
    _map(data["severity_points"], SEVERITIES, "severity_points", hi=100)
    _map(data["ml_max_points"], ML_CATEGORIES, "ml_max_points", hi=100)
    _map(data["weights"], CATEGORIES, "weights", hi=5)
    _map(data["category_caps"], CATEGORIES, "category_caps", hi=100)
    _map(data["diversity_bonus"], ("per_extra_category", "max"), "diversity_bonus", hi=100)
    _num(data["allowlist_factor"], "allowlist_factor", hi=1)
    th = _map(data["level_thresholds"], LEVELS, "level_thresholds", lo=0.0001, hi=100)
    if [th[k] for k in LEVELS] != sorted(th[k] for k in LEVELS) or len({th[k] for k in LEVELS}) != 4:
        raise RiskConfigError("RISK-CFG: level_thresholds phải tăng dần nghiêm ngặt low < medium < high < critical")
    _num(data["host_window_seconds"], "host_window_seconds", lo=1, hi=30 * 86400)
    return data


def load_risk_config(path: Optional[Path] = None) -> RiskConfig:
    p = Path(path) if path else DEFAULT_PATH
    try:
        raw = p.read_bytes()
        data = yaml.safe_load(raw.decode("utf-8"))
    except (OSError, UnicodeDecodeError, yaml.YAMLError) as exc:
        raise RiskConfigError(f"RISK-CFG: không đọc được {p.name}") from exc
    return RiskConfig(validate(data), hashlib.sha256(raw).hexdigest())
