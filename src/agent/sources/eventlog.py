"""Nguồn Windows Event Log (PH2-T06). TRẠNG THÁI: UNKNOWN trên Windows thật tới khi PH2-T09.

Mọi gọi win32evtlog nằm sau `_Api` để test bằng đối tượng giả trên Linux.
Bookmark = XML bookmark do EvtRender(EvtRenderBookmark) trả về; có thể không dùng được
nếu spike PH2-T05 cho thấy khác — khi đó cần điều chỉnh sau khi có verify_report.json.
"""
from __future__ import annotations

from typing import Iterator, Optional

from .base import RawItem, SourceError

CHANNEL = "Microsoft-Windows-Sysmon/Operational"


class _Api:
    """Lớp mỏng quanh pywin32; chỉ import khi thực sự dùng trên Windows."""

    def __init__(self):
        import win32evtlog  # type: ignore
        self.w = win32evtlog
        self._subs = {}      # handle subscription -> event báo hiệu (giữ tham chiếu cho tới khi handle hết dùng)

    def query(self, channel, bookmark_xml, xpath="*"):
        w = self.w
        if bookmark_xml:
            # Mô hình kéo (không Callback) BẮT BUỘC SignalEvent; thiếu nó EvtSubscribe báo lỗi 87 (đo trên VM Windows 10,
            # verify_windows_env B-03). Cùng cách gọi với B-02 đã khởi tạo được trên VM.
            import win32event  # type: ignore
            signal = win32event.CreateEvent(None, 0, 0, None)
            bm = w.EvtCreateBookmark(bookmark_xml)
            h = w.EvtSubscribe(channel, w.EvtSubscribeStartAfterBookmark, SignalEvent=signal, Query=xpath, Bookmark=bm)
            self._subs = {h: signal}
            return h, bm
        h = w.EvtQuery(channel, w.EvtQueryChannelPath | w.EvtQueryForwardDirection, xpath)
        return h, w.EvtCreateBookmark(None)

    def next(self, handle, n):
        if handle in self._subs:
            return self.w.EvtNext(handle, n, 0)      # timeout 0: không chặn khi chưa có sự kiện mới (B-02 trên VM)
        return self.w.EvtNext(handle, n)

    def render_xml(self, ev):
        return self.w.EvtRender(ev, self.w.EvtRenderEventXml)

    def update_bookmark(self, bm, ev):
        self.w.EvtUpdateBookmark(bm, ev)

    def render_bookmark(self, bm):
        return self.w.EvtRender(bm, self.w.EvtRenderBookmark)


class EventLogSource:
    def __init__(self, channel: str = CHANNEL, api=None, batch: int = 64, xpath: str = "*"):
        """xpath: bộ lọc XPath truyền cho EvtQuery/EvtSubscribe (mặc định "*" = mọi sự kiện như trước)."""
        self.channel, self._api, self.batch, self.xpath = channel, api, batch, xpath

    def iter_events(self, from_bookmark: Optional[str]) -> Iterator[RawItem]:
        try:
            api = self._api or _Api()
            handle, bm = api.query(self.channel, from_bookmark, self.xpath)
        except ImportError as exc:
            raise SourceError("A-001", "pywin32 không khả dụng") from exc
        except Exception as exc:  # pywintypes.error: mã 5 = ACCESS_DENIED
            code = "C-006" if getattr(exc, "winerror", None) == 5 or "denied" in str(exc).lower() else "A-002"
            raise SourceError(code, f"{type(exc).__name__}: {exc}") from exc     # giữ mã winerror và tên hàm
        while True:
            events = api.next(handle, self.batch)
            if not events:
                return
            for ev in events:
                xml = api.render_xml(ev)
                api.update_bookmark(bm, ev)
                yield RawItem(xml, api.render_bookmark(bm))
