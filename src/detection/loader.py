"""Nạp và kiểm hợp lệ rule YAML (PH4-T01). Rule sai → RuleError nêu rõ, không nạp một phần âm thầm."""
from __future__ import annotations

import re
from pathlib import Path
from typing import Dict

import jsonschema
import yaml

import windows_channels as wc

from .schema import RULE_SCHEMA, SILVER_TABLE_FOR_CHANNEL, SILVER_TABLE_FOR_EVENT

DEFAULT_DIR = Path(__file__).parent / "rules"


class RuleError(ValueError):
    pass


def validate_rule(rule: dict, source: str = "") -> dict:
    try:
        jsonschema.validate(rule, RULE_SCHEMA)
    except jsonschema.ValidationError as exc:
        loc = "/".join(str(p) for p in exc.absolute_path)
        raise RuleError(f"{source}: rule không hợp lệ tại '{loc}': {exc.message}") from exc
    r = dict(rule)
    if r.get("source_events"):
        r["source_events"] = [dict(se) for se in r["source_events"]]      # không sửa dict của người gọi khi chuẩn hóa kênh
    r.setdefault("response_policy", "alert_only")
    if r.get("sysmon_event_ids") and r.get("source_events"):
        raise RuleError(f"{source}: chỉ khai một trong sysmon_event_ids hoặc source_events")
    if r["type"] == "single" and not (r.get("sysmon_event_ids") or r.get("source_events")):
        raise RuleError(f"{source}: rule 'single' cần sysmon_event_ids hoặc source_events")
    if r.get("source_events") and r["type"] not in ("single", "scriptblock"):
        raise RuleError(f"{source}: source_events chỉ dùng cho rule 'single' hoặc 'scriptblock'")
    channels = []
    for se in r.get("source_events") or []:
        ch = wc.canonical_channel(se["channel"])
        if ch not in SILVER_TABLE_FOR_CHANNEL:
            raise RuleError(f"{source}: source_events kênh {se['channel']!r} không có bảng Silver")
        bad = sorted(set(se["event_ids"]) - set(wc.SUPPORTED_EVENT_IDS[ch]))
        if bad:
            raise RuleError(f"{source}: source_events {ch} không hỗ trợ Event ID {bad}")
        se["channel"] = ch
        channels.append(ch)
    if r["type"] == "scriptblock":
        ses = r.get("source_events") or []
        if channels != [wc.POWERSHELL_CHANNEL] or ses[0]["event_ids"] != [4104] or not r.get("patterns"):
            raise RuleError(f"{source}: rule 'scriptblock' cần source_events đúng một mục PowerShell/Operational [4104] và patterns")
    elif wc.POWERSHELL_CHANNEL in channels:
        # evaluator 'single' chép nguyên giá trị trường vào matched_fields -> lộ văn bản script (có thể chứa bí mật, w8 mục 2.7)
        raise RuleError(f"{source}: kênh PowerShell chỉ dùng rule 'scriptblock' (không chép văn bản script vào alert)")
    if (r.get("patterns") or r.get("base64")) and r["type"] != "scriptblock":
        raise RuleError(f"{source}: patterns/base64 chỉ dùng cho rule 'scriptblock'")
    if r.get("detection_source") == "EXTERNAL_DEFENDER" and set(channels) != {wc.DEFENDER_CHANNEL}:
        raise RuleError(f"{source}: detection_source EXTERNAL_DEFENDER chỉ dùng cho rule đọc riêng kênh Defender")
    if r["type"] == "sigma":
        if not r.get("sigma") or r.get("detection_source") != "SIGMA" or not r["rule_id"].startswith("DACN-SIG-"):
            raise RuleError(f"{source}: rule 'sigma' cần khóa sigma, detection_source SIGMA và rule_id DACN-SIG-<8 hex>")
        bad = [k for k in ("match", "exclude", "sysmon_event_ids", "source_events", "patterns", "base64", "severity_by",
                           "registry_change_filter", "correlation_keys") if r.get(k)]
        if bad:
            raise RuleError(f"{source}: rule 'sigma' không dùng {bad} (điều kiện nằm trong sigma.detection)")
    elif r.get("sigma") or r.get("detection_source") == "SIGMA" or r["rule_id"].startswith("DACN-SIG-"):
        raise RuleError(f"{source}: khóa sigma / detection_source SIGMA / rule_id DACN-SIG- chỉ dùng cho rule 'sigma'")
    if r["type"] == "correlation" and not (r.get("time_window_seconds") and r.get("window_status")):
        raise RuleError(f"{source}: rule 'correlation' cần time_window_seconds và window_status")
    unknown = sorted(set(r.get("sysmon_event_ids") or []) - set(SILVER_TABLE_FOR_EVENT))
    if r["status"] == "enabled" and unknown:
        raise RuleError(f"{source}: sysmon_event_ids {unknown} không có bảng Silver; rule đang bật sẽ không chạy được")
    if r["status"] == "blocked" and not r.get("blocked_reason"):
        raise RuleError(f"{source}: rule 'blocked' cần blocked_reason")
    if r.get("mitre_technique_ids") and not r.get("mitre_basis"):
        raise RuleError(f"{source}: gán MITRE cần mitre_basis (căn cứ)")
    conds = (r.get("match") or {}).get("all", []) + (r.get("match") or {}).get("any", []) + (r.get("exclude") or [])
    for c in conds:
        if c["op"] == "regex":
            for pat in ([c["value"]] if isinstance(c["value"], str) else c["value"]):
                try:
                    re.compile(pat)
                except re.error as exc:
                    raise RuleError(f"{source}: regex lỗi: {exc}") from exc
    return r


def load_rules(directory: Path = DEFAULT_DIR) -> Dict[str, dict]:
    rules: Dict[str, dict] = {}
    for p in sorted(Path(directory).glob("*.yaml")):
        try:
            data = yaml.safe_load(p.read_text(encoding="utf-8"))
        except yaml.YAMLError as exc:
            raise RuleError(f"{p.name}: YAML lỗi") from exc
        if not isinstance(data, dict):
            raise RuleError(f"{p.name}: phải là mapping")
        r = validate_rule(data, p.name)
        if r["rule_id"] in rules:
            raise RuleError(f"{p.name}: trùng rule_id {r['rule_id']}")
        rules[r["rule_id"]] = r
    return rules
