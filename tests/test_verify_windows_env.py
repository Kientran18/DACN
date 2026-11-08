"""Test cho scripts/windows/verify_windows_env.py (PH2-T05).

Chạy được trên Linux: các kiểm tra phụ thuộc Windows phải trả SKIP, các kiểm tra
tệp phải dọn sạch thư mục tạm, báo cáo không được chứa nội dung sự kiện.
"""
import importlib.util
import json
import sys
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[1]
SCRIPT = ROOT / "scripts" / "windows" / "verify_windows_env.py"


@pytest.fixture(scope="module")
def vwe():
    spec = importlib.util.spec_from_file_location("verify_windows_env", SCRIPT)
    mod = importlib.util.module_from_spec(spec)
    sys.modules["verify_windows_env"] = mod
    spec.loader.exec_module(mod)
    return mod


def test_result_has_fixed_shape(vwe):
    r = vwe.result("X-01", "PASS", "ok", {"k": 1})
    assert set(r) == {"id", "status", "message", "details"}
    assert r["status"] == "PASS"


def test_invalid_status_is_rejected(vwe):
    with pytest.raises(ValueError):
        vwe.result("X-01", "MAYBE", "m")


def test_file_semantics_writes_lf_only_and_cleans_up(vwe, tmp_path):
    results = vwe.check_file_semantics(tmp_path)
    by_id = {r["id"]: r for r in results}
    assert by_id["F-01"]["status"] == "PASS", by_id["F-01"]
    assert by_id["F-01"]["details"]["crlf_count"] == 0
    assert list(tmp_path.iterdir()) == []


def test_windows_only_checks_skip_on_non_windows(vwe):
    if sys.platform == "win32":
        pytest.skip("kiểm tra này dành cho môi trường không phải Windows")
    for fn in (vwe.check_admin, vwe.check_pywin32, vwe.check_sysmon_service,
               vwe.check_channel_readable, vwe.check_bookmark_api,
               vwe.check_channel_size):
        res = fn()
        assert all(r["status"] == "SKIP" for r in res), (fn.__name__, res)


def test_report_never_contains_event_payload(vwe, tmp_path):
    out = tmp_path / "report.json"
    code = vwe.main(["--out", str(out)])
    assert code in (0, 1)
    text = out.read_text(encoding="utf-8")
    data = json.loads(text)
    assert data["tool"] == "verify_windows_env"
    for banned in ("CommandLine", "TargetFilename", "<Event", "UserName", "hostname"):
        assert banned not in text
