"""Kiểm tra chính trình nghiệm thu: không được tự điền PASS khi thiếu bằng chứng."""
import importlib.util
import subprocess
import sys
from pathlib import Path

import yaml

ROOT = Path(__file__).resolve().parents[2]
spec = importlib.util.spec_from_file_location("run_acceptance", ROOT / "scripts/acceptance/run_acceptance.py")
ra = importlib.util.module_from_spec(spec)
spec.loader.exec_module(ra)
CAT = yaml.safe_load((ROOT / "tests/acceptance/at_catalog.yaml").read_text(encoding="utf-8"))


def test_catalog_has_43_unique_ats_with_required_fields():
    assert sorted(CAT) == [f"AT-{i:02d}" for i in range(1, 44)]
    for at, a in CAT.items():
        for k in ("req", "level", "goal", "pre", "steps", "expected", "tests"):
            assert k in a, (at, k)
        assert a["level"] in ("L", "W", "D")


def test_windows_level_tests_have_no_linux_evidence_attached():
    for at, a in CAT.items():
        if a["level"] == "W":
            assert a["tests"] == [], at


def test_every_listed_test_exists():
    files = sorted({w.split("::")[0] for a in CAT.values() for w in a["tests"]})
    out = subprocess.run([sys.executable, "-m", "pytest", "--collect-only", "-q", *files],
                         cwd=ROOT, capture_output=True, text=True).stdout.splitlines()
    ids = [x for x in out if "::" in x]
    for at, a in CAT.items():
        for w in a["tests"]:
            assert any(ra.match(i, w) for i in ids), (at, w)


def test_match_is_exact_or_prefix_by_param_not_substring():
    assert ra.match("tests/a.py::test_x[1]", "tests/a.py::test_x")
    assert ra.match("tests/a.py::test_x", "tests/a.py")
    assert not ra.match("tests/a.py::test_xy", "tests/a.py::test_x")
