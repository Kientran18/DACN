"""Đánh giá rule `type: sigma` trên hàng Silver -> DetectionResult (cùng contract với rule DACN, không đổi DetectionResult).

- MATCH: matched_fields["sigma"] giải thích (selection đúng, condition, giá trị các field đã khớp) và
  matched_fields["attribution"] giữ tác giả + giấy phép + link rule gốc (DRL 1.1: thông điệp khớp phải giữ tác giả).
- INSUFFICIENT_TELEMETRY: field cần cho kết luận vắng trong hàng; missing_fields liệt kê field Sigma.
- NO_MATCH: trả về để kiểm thử; engine không lưu (như rule single).
- ScriptBlockText (PowerShell 4104) KHÔNG chép vào kết quả: chỉ sha256 và độ dài (w8 mục 2.7).
"""
from __future__ import annotations

import hashlib
import json
from typing import Dict, List, Optional

from ..result import DetectionResult, make_dedup_key
from .compiler import CompiledSigma, Event, compile_rule
from .fieldmap import DEFENDER_FIELDS, SCRIPT_FIELDS, SENSITIVE_FIELDS, defined_fields

_CACHE: Dict[tuple, CompiledSigma] = {}


def compiled_for(rule: dict) -> CompiledSigma:
    s = rule["sigma"]
    key = (rule["rule_id"], rule["rule_version"], s["source_sha256"])
    if key not in _CACHE:
        # regex đã kiểm giới hạn độ dài khi nạp (loader); ở đây chỉ biên dịch lại
        _CACHE[key] = compile_rule({"title": s["title"], "id": s["id"], "logsource": s["logsource"],
                                    "detection": s["detection"]}, regex_max_length=None)
    return _CACHE[key]


def _raw(row: dict) -> dict:
    raw = row.get("raw_data")
    if isinstance(raw, str):
        try:
            raw = json.loads(raw)
        except ValueError:
            raw = {}
    return raw if isinstance(raw, dict) else {}


def sysmon_event(rule: dict, row: dict) -> Event:
    """Field Sigma = tên EventData gốc trong raw_data; EventID lấy từ cột sysmon_event_id."""
    values = dict(_raw(row))
    values["EventID"] = row["sysmon_event_id"]
    return Event(values, defined_fields(rule["sigma"]["dacn_logsource"], row["sysmon_event_id"]))


def defender_event(row: dict) -> Event:
    return Event({k: row.get(col) for k, col in DEFENDER_FIELDS.items()}, set(DEFENDER_FIELDS))


def script_event(text: str, parts: List[dict], total: int) -> Event:
    first = parts[0]
    raw = _raw(first)
    values = {"EventID": 4104, "ScriptBlockText": text, "ScriptBlockId": first.get("script_block_id"), "MessageTotal": total}
    if "Path" in raw:
        values["Path"] = raw["Path"] if raw["Path"] is not None else ""     # phần tử Path có trong sự kiện nhưng rỗng
    return Event(values, set(SCRIPT_FIELDS))


def evaluate_event(rule: dict, event: Event, subject: str, contributing: List[str], *,
                   extra: Optional[dict] = None, missing_parts: Optional[List[str]] = None) -> DetectionResult:
    c = compiled_for(rule)
    r = c.evaluate(event)
    rid, ver = rule["rule_id"], rule["rule_version"]
    base = dict(rule_id=rid, rule_version=ver, subject=subject, contributing_event_ids=list(contributing),
                dedup_key=make_dedup_key(rid, ver, subject))
    if r.value is False:
        return DetectionResult(outcome="NO_MATCH", **base)
    if r.value is None:
        return DetectionResult(outcome="INSUFFICIENT_TELEMETRY", missing_fields=r.missing,
                               coverage_status="MISSING_REQUIRED_FIELDS",
                               severity_reason="field Sigma cần cho kết luận vắng trong sự kiện; không kết luận lành tính",
                               notes=[f"sigma_id:{rule['sigma']['id']}"], **base)
    fields: Dict[str, object] = {}
    for k, v in r.fields.items():
        if k in SENSITIVE_FIELDS:
            fields[k] = {"redacted": True, "sha256": hashlib.sha256(v.encode("utf-8")).hexdigest(), "length": len(v)}
        else:
            fields[k] = v
    s = rule["sigma"]
    matched: Dict[str, object] = {
        "sigma": {"id": s["id"], "title": s["title"], "condition": c.condition, "selections_true": r.true_selections,
                  "fields": fields, "level": s["level"], "status": s["status"]},
        "attribution": {"author": s["author"], "license": s["license"], "license_url": s.get("license_url"),
                        "source_url": s.get("source_url"), "source_path": s["source_path"]},
    }
    if extra:
        matched.update(extra)
    reason = rule.get("severity_reason", "")
    if missing_parts:
        reason = f"{reason} [script block thiếu {len(missing_parts)} phần; kết luận trên phần đã có]".strip()
    return DetectionResult(outcome="MATCH", matched_fields=matched, missing_fields=list(missing_parts or []),
                           coverage_status="PARTIAL_SCRIPT_BLOCK" if missing_parts else "FULL",
                           severity=rule["severity"], severity_reason=reason, **base)
