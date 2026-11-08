from __future__ import annotations

import hashlib
from dataclasses import dataclass, field, asdict
from typing import Dict, List, Optional


def make_dedup_key(rule_id: str, rule_version: int, subject: str, window: str = "") -> str:
    return hashlib.sha256(f"{rule_id}|{rule_version}|{subject}|{window}".encode()).hexdigest()


@dataclass
class DetectionResult:
    rule_id: str
    rule_version: int
    outcome: str
    subject: str                       # event_id (single) hoặc khóa chuỗi (correlation)
    contributing_event_ids: List[str]
    matched_fields: Dict[str, object] = field(default_factory=dict)
    missing_fields: List[str] = field(default_factory=list)
    coverage_status: str = "FULL"
    severity: Optional[str] = None
    severity_reason: str = ""
    dedup_key: str = ""
    notes: List[str] = field(default_factory=list)

    def to_dict(self) -> dict:
        return asdict(self)
