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


class _FakeEvtLog:
    """win32evtlog giả: ghi lại các lời gọi EvtSubscribe/EvtNext, không chạm Event Log thật."""
    EvtQueryChannelPath, EvtQueryReverseDirection, EvtRenderEventXml, EvtRenderBookmark = 1, 2, 3, 4
    EvtSubscribeToFutureEvents, EvtSubscribeStartAfterBookmark = 5, 6

    def __init__(self, block_on_default_timeout=False):
        self.subscribe_calls, self.block = [], block_on_default_timeout
        import threading
        self.release = threading.Event()

    def EvtQuery(self, *a, **k): return "query-handle"
    def EvtNext(self, handle, count, timeout=None, flags=0):
        if handle == "sub-handle" and self.block:
            self.release.wait(10)                      # mô phỏng EvtNext chặn vô hạn trên subscription không có sự kiện
            return ()
        return ("ev",) if handle == "query-handle" else ()
    def EvtRender(self, obj, flag): return "<BookmarkList/>" if flag == self.EvtRenderBookmark else "<Event/>"
    def EvtCreateBookmark(self, xml=None): return ("bookmark", xml)
    def EvtUpdateBookmark(self, bm, ev): pass
    def EvtSubscribe(self, channel, flags, **kw):
        self.subscribe_calls.append((flags, kw))
        return "sub-handle" if flags == self.EvtSubscribeStartAfterBookmark else "future-handle"


def _run_bookmark_checks(vwe, monkeypatch, fake, *, win32event=None):
    monkeypatch.setattr(vwe, "IS_WINDOWS", True)
    monkeypatch.setitem(sys.modules, "win32evtlog", fake)
    monkeypatch.setitem(sys.modules, "win32event", win32event)      # None = import win32event -> ImportError
    try:
        return {r["id"]: r for r in vwe.check_bookmark_api(probe_timeout_s=0.3)}
    finally:
        fake.release.set()


def test_b03_mimics_agent_call_and_missing_win32event_is_not_a_nameerror(vwe, monkeypatch):
    """B-03 phải gọi EvtSubscribe ĐÚNG như agent (EventLogSource: StartAfterBookmark + SignalEvent + Query + Bookmark dựng lại từ XML).
    VM Windows 2026-11-23: bản cũ (không SignalEvent) báo lỗi 87. Thiếu win32event: B-02 SKIP, B-03 FAIL rõ lý do, không NameError."""
    fake = _FakeEvtLog()
    res = _run_bookmark_checks(vwe, monkeypatch, fake, win32event=_FakeWin32Event())
    assert res["B-03"]["status"] == "PASS"
    start_after = [kw for flags, kw in fake.subscribe_calls if flags == fake.EvtSubscribeStartAfterBookmark]
    assert start_after and set(start_after[0]) == {"SignalEvent", "Query", "Bookmark"}, fake.subscribe_calls
    assert start_after[0]["Bookmark"] == ("bookmark", "<BookmarkList/>")                              # dựng lại từ XML bookmark
    res2 = _run_bookmark_checks(vwe, monkeypatch, _FakeEvtLog(), win32event=None)
    assert "NameError" not in json.dumps(res2, ensure_ascii=False)
    assert res2["B-02"]["status"] == "SKIP" and res2["B-03"]["status"] == "FAIL" and "win32event" in res2["B-03"]["message"]


class _FakeWin32Event:
    @staticmethod
    def CreateEvent(*a): return "signal"


@pytest.mark.parametrize("blocks,expect", [(False, "không chặn"), (True, "CHẶN")])
def test_b04_reports_whether_evtnext_with_timeout_zero_blocks_on_subscription(vwe, monkeypatch, blocks, expect):
    """Agent gọi EvtNext(handle, n, 0) trên handle EvtSubscribe; nếu lời gọi đó vẫn chặn thì --follow không quay lại kiểm tệp STOP.
    Script chỉ ĐO (thread có giới hạn thời gian), không đổi gì."""
    res = _run_bookmark_checks(vwe, monkeypatch, _FakeEvtLog(block_on_default_timeout=blocks), win32event=_FakeWin32Event())
    assert res["B-04"]["status"] == "INFO" and expect in res["B-04"]["message"]
