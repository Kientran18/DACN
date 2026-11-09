"""Nạp mô hình ML đã huấn luyện (ML-T03). KHÔNG tự giải tuần tự hóa (không pickle/eval): người dùng cung cấp `predictor_factory`.
Từ chối model: thiếu/hỏng model_card, sai feature_schema_version, sai hash artifact, thiếu phiên bản. Kết quả ML không kích hoạt response."""
from __future__ import annotations

import hashlib
import json
from pathlib import Path
from typing import Callable, Mapping, Optional

from .interface import AnomalyResult


class ModelError(ValueError):
    pass


class LoadedModel:
    def __init__(self, card: dict, predict: Callable[[Mapping[str, object]], float]):
        self.card, self._predict = card, predict

    def score(self, features: Mapping[str, object]) -> Optional[AnomalyResult]:
        s = float(self._predict(features))
        if not (0.0 <= s <= 1.0):
            raise ModelError("điểm bất thường phải nằm trong [0,1]")
        return AnomalyResult(score=s, feature_schema_version=self.card["feature_schema_version"],
                             model_version=self.card["model_version"], explanation="ML score; chỉ tăng rủi ro, không kích hoạt response")


def load_model(model_dir: Path, *, expected_feature_schema_version: str,
               predictor_factory: Callable[[Path], Callable[[Mapping[str, object]], float]]) -> LoadedModel:
    d = Path(model_dir)
    try:
        card = json.loads((d / "model_card.json").read_text(encoding="utf-8"))
    except (OSError, ValueError) as exc:
        raise ModelError("thiếu hoặc hỏng model_card.json") from exc
    for k in ("model_version", "feature_schema_version", "artifact_file", "artifact_sha256"):
        if not card.get(k):
            raise ModelError(f"model_card thiếu {k}")
    if card["feature_schema_version"] != expected_feature_schema_version:
        raise ModelError(f"sai feature_schema_version: model={card['feature_schema_version']} hệ thống={expected_feature_schema_version}")
    art = d / card["artifact_file"]
    if art.resolve().parent != d.resolve() or not art.is_file():
        raise ModelError("artifact phải là tệp nằm trong thư mục model")
    if hashlib.sha256(art.read_bytes()).hexdigest() != str(card["artifact_sha256"]).lower():
        raise ModelError("hash artifact không khớp model_card")
    return LoadedModel(card, predictor_factory(art))
