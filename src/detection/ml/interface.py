"""Giao diện ML (PH4-T10). Mặc định NullDetector; kết quả ML chỉ tăng rủi ro, không kích hoạt response."""
from __future__ import annotations

from dataclasses import dataclass
from typing import Mapping, Optional, Protocol


@dataclass(frozen=True)
class AnomalyResult:
    score: float
    feature_schema_version: str
    model_version: str
    explanation: str = ""
    triggers_response: bool = False   # luôn False theo thiết kế


class MLDetector(Protocol):
    def score(self, features: Mapping[str, object]) -> Optional[AnomalyResult]: ...


class NullDetector:
    def score(self, features):
        return None
