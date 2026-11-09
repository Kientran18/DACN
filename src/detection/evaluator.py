"""Đánh giá rule đơn sự kiện trên một hàng Silver (PH4-T03). Chỉ dùng cột có thật."""
from __future__ import annotations

import re
from typing import Dict, List, Optional, Tuple

from .result import DetectionResult, make_dedup_key


def _vals(c) -> List[str]:
    return [c["value"]] if isinstance(c["value"], str) else list(c["value"])


def cond_match(c: dict, row: dict) -> Tuple[bool, Optional[str]]:
    """Trả (khớp?, giá trị đã so). Không phân biệt hoa/thường."""
    v = row.get(c["field"])
    if v is None:
        return False, None
    s = str(v)
    low = s.lower()
    vals = _vals(c)
    op = c["op"]
    if op == "equals":
        ok = any(low == x.lower() for x in vals)
    elif op == "contains_any":
        ok = any(x.lower() in low for x in vals)
    elif op == "endswith_any":
        ok = any(low.endswith(x.lower()) for x in vals)
    elif op == "startswith_any":
        ok = any(low.startswith(x.lower()) for x in vals)
    else:  # regex
        ok = any(re.search(x, s) for x in vals)
    return ok, s


def evaluate_single(rule: dict, row: dict) -> DetectionResult:
    rid, ver = rule["rule_id"], rule["rule_version"]
    base = dict(rule_id=rid, rule_version=ver, subject=row["event_id"],
                contributing_event_ids=[row["event_id"]],
                dedup_key=make_dedup_key(rid, ver, row["event_id"]))
    missing = [f for f in rule.get("required_fields", []) if row.get(f) in (None, "")]
    if missing:
        # Điều kiện `all` trên trường ĐÃ CÓ mà không khớp thì chắc chắn không match: không cần trường thiếu để kết luận.
        for c in (rule.get("match") or {}).get("all", []):
            if row.get(c["field"]) not in (None, "") and not cond_match(c, row)[0]:
                return DetectionResult(outcome="NO_MATCH", **base)
        return DetectionResult(outcome="INSUFFICIENT_TELEMETRY", missing_fields=missing,
                               coverage_status="MISSING_REQUIRED_FIELDS",
                               severity_reason="thiếu trường bắt buộc; không kết luận lành tính", **base)
    m = rule.get("match") or {}
    matched: Dict[str, object] = {}
    for c in m.get("all", []):
        ok, val = cond_match(c, row)
        if not ok:
            return DetectionResult(outcome="NO_MATCH", **base)
        matched[c["field"]] = val
    anys = m.get("any", [])
    if anys:
        hit = False
        for c in anys:
            ok, val = cond_match(c, row)
            if ok:
                hit = True
                matched[c["field"]] = val
        if not hit:
            return DetectionResult(outcome="NO_MATCH", **base)
    for c in rule.get("exclude", []) or []:
        if cond_match(c, row)[0]:
            return DetectionResult(outcome="NO_MATCH", notes=[f"excluded_by:{c['field']}"], **base)
    return DetectionResult(outcome="MATCH", matched_fields=matched, severity=rule["severity"],
                           severity_reason=rule.get("severity_reason", ""), **base)
