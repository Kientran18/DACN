"""Lỗi lộ ra khi chạy agent --live lần đầu trên Windows 10 VM (2026-11-23): health ghi A-002 347 lần, 0 sự kiện.
verify_windows_env B-03 trên cùng máy: EvtSubscribe(StartAfterBookmark, Bookmark=...) KHÔNG có SignalEvent -> (87, 'The parameter
is incorrect'); B-02 (CÓ SignalEvent) khởi tạo được và EvtNext(timeout=0) không chặn. Theo tài liệu Win32, mô hình kéo (Callback NULL)
bắt buộc SignalEvent. Test dùng module win32evtlog/win32event giả, không chứng minh hành vi trên Windows thật."""
import sys
import types

import pytest

from agent.sources import eventlog


class _FakeW:
    EvtQueryChannelPath, EvtQueryForwardDirection, EvtSubscribeStartAfterBookmark = 1, 2, 6
    EvtRenderEventXml, EvtRenderBookmark = 3, 4

    def __init__(self):
        self.calls = []

    def EvtCreateBookmark(self, xml=None): return ("bm", xml)
    def EvtQuery(self, *a, **k): self.calls.append(("EvtQuery", a, k)); return "q"
    def EvtSubscribe(self, ch, flags, **kw): self.calls.append(("EvtSubscribe", (ch, flags), kw)); return "s"
    def EvtNext(self, h, n, *a, **k): self.calls.append(("EvtNext", (h, n) + a, k)); return ()


@pytest.fixture
def fake(monkeypatch):
    w = _FakeW()
    monkeypatch.setitem(sys.modules, "win32evtlog", w)
    ev = types.SimpleNamespace(CreateEvent=lambda *a: "signal")
    monkeypatch.setitem(sys.modules, "win32event", ev)
    return w


def test_pull_subscription_passes_signal_event_and_query(fake):
    api = eventlog._Api()
    h, _ = api.query(eventlog.CHANNEL, "<BookmarkList/>")
    sub = [c for c in fake.calls if c[0] == "EvtSubscribe"]
    assert sub and sub[0][1][1] == fake.EvtSubscribeStartAfterBookmark
    assert sub[0][2].get("SignalEvent") == "signal" and sub[0][2].get("Query") == "*", sub


def test_next_on_subscription_does_not_block(fake):
    api = eventlog._Api()
    h, _ = api.query(eventlog.CHANNEL, "<BookmarkList/>")
    api.next(h, 10)
    nxt = [c for c in fake.calls if c[0] == "EvtNext"][-1]
    assert 0 in nxt[1][2:] or nxt[2].get("Timeout") == 0, nxt      # timeout 0 như B-02 đã đo trên VM

