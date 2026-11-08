"""Nạp và kiểm hợp lệ rule YAML (PH4-T01). Rule sai → RuleError nêu rõ, không nạp một phần âm thầm."""
from __future__ import annotations

import re
from pathlib import Path
from typing import Dict, List

import jsonschema
import yaml

from .schema import RULE_SCHEMA

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
    r.setdefault("response_policy", "alert_only")
    if r["type"] == "single" and not r.get("sysmon_event_ids"):
        raise RuleError(f"{source}: rule 'single' cần sysmon_event_ids")
    if r["type"] == "correlation" and not (r.get("time_window_seconds") and r.get("window_status")):
        raise RuleError(f"{source}: rule 'correlation' cần time_window_seconds và window_status")
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
