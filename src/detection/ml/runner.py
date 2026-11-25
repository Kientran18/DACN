"""Chạy các nguồn tín hiệu ML theo cấu hình (mặc định TẮT). Lỗi của ML không làm hỏng vòng phát hiện.
Tín hiệu chỉ góp vào điểm rủi ro; runner không tạo alert và không gọi response."""
from __future__ import annotations

from pathlib import Path
from typing import Optional

import yaml

from .signals import MLSignalStore

DEFAULT_PATH = Path(__file__).resolve().parents[3] / "config" / "ml-detectors.yaml"
_KEYS = {"version", "static_pe", "behavior"}
_STATIC = {"enabled", "allowed_dirs", "models_root", "max_bytes"}
_BEHAVIOR = {"enabled", "model_dir"}


class MLConfigError(ValueError):
    pass


def load_ml_config(path: Optional[Path] = None) -> dict:
    p = Path(path) if path else DEFAULT_PATH
    try:
        data = yaml.safe_load(p.read_text(encoding="utf-8"))
    except (OSError, yaml.YAMLError) as exc:
        raise MLConfigError(f"ML-CFG: không đọc được {p.name}") from exc
    if not isinstance(data, dict) or set(data) != _KEYS:
        raise MLConfigError(f"ML-CFG: cần đúng các khóa {sorted(_KEYS)}")
    for key, allowed in (("static_pe", _STATIC), ("behavior", _BEHAVIOR)):
        sec = data[key]
        if not isinstance(sec, dict) or set(sec) != allowed:
            raise MLConfigError(f"ML-CFG: mục {key} cần đúng các khóa {sorted(allowed)}")
        if not isinstance(sec["enabled"], bool):
            raise MLConfigError(f"ML-CFG: {key}.enabled phải là true/false")
    if not isinstance(data["static_pe"]["allowed_dirs"], list):
        raise MLConfigError("ML-CFG: static_pe.allowed_dirs phải là danh sách")
    return data


class MLRunner:
    def __init__(self, cfg: dict, *, static_scorer=None):
        self.cfg, self._scorer, self._behavior = cfg, static_scorer, None

    @classmethod
    def from_config(cls, cfg: dict, *, static_scorer=None) -> "MLRunner":
        return cls(cfg, static_scorer=static_scorer)

    def enabled(self) -> dict:
        return {"ML_STATIC": self.cfg["static_pe"]["enabled"], "ML_BEHAVIOR": self.cfg["behavior"]["enabled"]}

    def _static(self):
        if self._scorer is None:
            from .static_scorer import StaticScorer, StaticScorerConfig
            s = self.cfg["static_pe"]
            self._scorer = StaticScorer(StaticScorerConfig(allowed_dirs=[Path(d) for d in s["allowed_dirs"]],
                                                           models_root=Path(s["models_root"]), max_bytes=int(s["max_bytes"])))
        return self._scorer

    def _behavior_model(self):
        if self._behavior is None:
            from .behavior import load_behavior_model
            if not self.cfg["behavior"]["model_dir"]:
                raise ValueError("behavior.model_dir chưa cấu hình")
            self._behavior = load_behavior_model(Path(self.cfg["behavior"]["model_dir"]))
        return self._behavior

    def run(self, con) -> dict:
        """Trả trạng thái từng detector: DISABLED | dict đếm | 'ERROR: <loại lỗi>'. Không ném lỗi của detector."""
        out = {}
        store = MLSignalStore(con) if any(self.enabled().values()) else None
        if self.cfg["static_pe"]["enabled"]:
            try:
                from .static_signal import score_static_signals
                out["ML_STATIC"] = score_static_signals(con, self._static(), store)
            except Exception as exc:      # noqa: BLE001 - lỗi ML không được làm chết vòng phát hiện
                out["ML_STATIC"] = f"ERROR: {type(exc).__name__}"
        else:
            out["ML_STATIC"] = "DISABLED"
        if self.cfg["behavior"]["enabled"]:
            try:
                from .behavior import score_signals
                out["ML_BEHAVIOR"] = score_signals(con, self._behavior_model(), store)
            except Exception as exc:      # noqa: BLE001
                out["ML_BEHAVIOR"] = f"ERROR: {type(exc).__name__}"
        else:
            out["ML_BEHAVIOR"] = "DISABLED"
        return out
