"""Backend Windows cho kết thúc tiến trình (PH7-T04). TRẠNG THÁI: UNKNOWN - CHƯA CHẠY TRÊN WINDOWS THẬT.

Chỉ lớp gọi API hệ điều hành (ctypes/kernel32) nằm ở đây; logic xác minh danh tính nằm trong LocalBackend
và được test bằng FakeProcessApi. Không được tạo trên hệ khác Windows. Không tự chạy: Executor chỉ dùng backend
này khi policy mở CẢ HAI khóa (mode=execute và execute_unlocked=true) và hành động đã được duyệt.
"""
from __future__ import annotations

import sys
from datetime import datetime, timedelta, timezone
from typing import Optional

PROCESS_TERMINATE = 0x0001
PROCESS_QUERY_LIMITED_INFORMATION = 0x1000
_EPOCH = datetime(1601, 1, 1, tzinfo=timezone.utc)


def filetime_to_iso(ft: int) -> str:
    return (_EPOCH + timedelta(microseconds=ft // 10)).isoformat(timespec="milliseconds")


class WinProcessApi:
    def __init__(self):
        if sys.platform != "win32":
            raise RuntimeError("WinProcessApi chỉ dùng được trên Windows")
        import ctypes
        from ctypes import wintypes
        self.ct, self.wt = ctypes, wintypes
        k = ctypes.WinDLL("kernel32", use_last_error=True)
        k.OpenProcess.argtypes = [wintypes.DWORD, wintypes.BOOL, wintypes.DWORD]
        k.OpenProcess.restype = wintypes.HANDLE
        k.GetProcessTimes.argtypes = [wintypes.HANDLE] + [ctypes.POINTER(wintypes.FILETIME)] * 4
        k.GetProcessTimes.restype = wintypes.BOOL
        k.QueryFullProcessImageNameW.argtypes = [wintypes.HANDLE, wintypes.DWORD, wintypes.LPWSTR, ctypes.POINTER(wintypes.DWORD)]
        k.QueryFullProcessImageNameW.restype = wintypes.BOOL
        k.TerminateProcess.argtypes = [wintypes.HANDLE, wintypes.UINT]
        k.TerminateProcess.restype = wintypes.BOOL
        k.CloseHandle.argtypes = [wintypes.HANDLE]
        self.k = k

    def _creation_filetime(self, h) -> int:
        c, e, kt, ut = (self.wt.FILETIME() for _ in range(4))
        if not self.k.GetProcessTimes(h, self.ct.byref(c), self.ct.byref(e), self.ct.byref(kt), self.ct.byref(ut)):
            raise OSError("GetProcessTimes thất bại")
        return (c.dwHighDateTime << 32) | c.dwLowDateTime

    def inspect(self, pid: int) -> Optional[dict]:
        h = self.k.OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, False, pid)
        if not h:
            return None
        try:
            buf = self.ct.create_unicode_buffer(32768)
            size = self.wt.DWORD(len(buf))
            if not self.k.QueryFullProcessImageNameW(h, 0, buf, self.ct.byref(size)):
                return None
            return {"creation_time": filetime_to_iso(self._creation_filetime(h)), "image_path": buf.value}
        finally:
            self.k.CloseHandle(h)

    def terminate(self, pid: int, expected_creation_time=None) -> None:
        """Mở một handle, kiểm lại thời điểm tạo trên CHÍNH handle đó rồi mới kết thúc (giảm TOCTOU)."""
        from .local import same_time
        h = self.k.OpenProcess(PROCESS_TERMINATE | PROCESS_QUERY_LIMITED_INFORMATION, False, pid)
        if not h:
            raise OSError("không mở được tiến trình")
        try:
            if expected_creation_time is not None and not same_time(
                    filetime_to_iso(self._creation_filetime(h)), expected_creation_time, 1.0):
                raise OSError("thời điểm tạo đã đổi: từ chối kết thúc")
            if not self.k.TerminateProcess(h, 1):
                raise OSError("TerminateProcess thất bại")
        finally:
            self.k.CloseHandle(h)
