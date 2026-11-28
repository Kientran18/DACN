"""An toàn: rule Sigma chỉ tạo alert. Kiểm tra tĩnh (AST) rằng module Sigma không import response/subprocess/mạng,
và mọi rule Sigma nạp được đều có response_policy alert_only."""
import ast
from pathlib import Path

from detection.loader import validate_rule, RuleError
from detection.sigma.loader import load_sigma

import pytest

SIGMA_DIR = Path(__file__).resolve().parents[2] / "src" / "detection" / "sigma"
FORBIDDEN = ("response", "subprocess", "socket", "urllib", "requests", "http", "ctypes", "win32api", "os.system")


def test_sigma_package_never_imports_response_or_exec():
    for py in SIGMA_DIR.glob("*.py"):
        tree = ast.parse(py.read_text(encoding="utf-8"))
        for node in ast.walk(tree):
            names = []
            if isinstance(node, ast.Import):
                names = [a.name for a in node.names]
            elif isinstance(node, ast.ImportFrom):
                names = [node.module or ""]
            for n in names:
                assert not any(n == f or n.startswith(f + ".") for f in FORBIDDEN), (py.name, n)
            if isinstance(node, ast.Call) and isinstance(node.func, ast.Name):
                assert node.func.id not in ("eval", "exec", "compile", "__import__"), (py.name, node.func.id)


def test_all_sigma_rules_alert_only():
    rules = load_sigma({"enabled": True}).rules
    assert rules and all(r["response_policy"] == "alert_only" for r in rules.values())


def test_validator_rejects_sigma_misuse():
    base = next(iter(load_sigma({"enabled": True}).rules.values()))
    bad = dict(base, match={"all": [{"field": "image_path", "op": "equals", "value": "x"}]})
    with pytest.raises(RuleError):
        validate_rule(bad, "x")
    with pytest.raises(RuleError):
        validate_rule(dict(base, detection_source="EXTERNAL_DEFENDER"), "x")
    with pytest.raises(RuleError):
        validate_rule(dict(base, response_policy="auto"), "x")
