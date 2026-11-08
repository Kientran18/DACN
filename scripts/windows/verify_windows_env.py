#!/usr/bin/env python3
"""Kiểm tra môi trường Windows cho DACN EDR (PH2-T05). CHỈ ĐỌC, không đổi cấu hình.

Script này:
  - KHÔNG cài đặt, KHÔNG sửa Sysmon/Defender/registry/audit/quyền/dịch vụ.
  - KHÔNG in nội dung sự kiện (command line, đường dẫn, tên người dùng, tên máy).
    Chỉ ghi EventID, EventRecordID và kết quả đạt/không đạt của từng kiểm tra.
  - Chỉ tạo rồi xóa một thư mục tạm của riêng nó để thử hành vi ghi/đổi tên tệp.
  - Chạy được trên Linux (các kiểm tra Windows trả SKIP) nên có test tự động.

Cách chạy trên VM Windows (từ thư mục gốc repository):
    python scripts\\windows\\verify_windows_env.py --out verify_report.json
Chạy thêm một lần với PowerShell "Run as Administrator" để so sánh quyền.
"""
from __future__ import annotations

import argparse
import json
import os
import platform
import shutil
import subprocess
import sys
import tempfile
import uuid
import xml.etree.ElementTree as ET
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, List, Optional

SYSMON_CHANNEL = "Microsoft-Windows-Sysmon/Operational"
VALID_STATUS = {"PASS", "FAIL", "SKIP", "INFO"}
IS_WINDOWS = sys.platform == "win32"
NS = {"e": "http://schemas.microsoft.com/win/2004/08/events/event"}


def result(check_id: str, status: str, message: str, details: Optional[Dict[str, Any]] = None) -> Dict[str, Any]:
    if status not in VALID_STATUS:
        raise ValueError(f"status không hợp lệ: {status!r}")
    return {"id": check_id, "status": status, "message": message, "details": details or {}}


def _skip(check_id: str, why: str = "Không phải Windows") -> List[Dict[str, Any]]:
    return [result(check_id, "SKIP", why)]


# ----------------------------------------------------------------------------- E: môi trường
def check_environment() -> List[Dict[str, Any]]:
    return [result("E-01", "INFO", "Thông tin nền tảng", {
        "system": platform.system(),
        "release": platform.release(),
        "version": platform.version(),
        "machine": platform.machine(),
        "python": platform.python_version(),
        "python_bits": 64 if sys.maxsize > 2**32 else 32,
    })]


def check_admin() -> List[Dict[str, Any]]:
    if not IS_WINDOWS:
        return _skip("A-01")
    try:
        import ctypes
        admin = bool(ctypes.windll.shell32.IsUserAnAdmin())
    except Exception as exc:  # noqa: BLE001 - báo cáo nguyên văn lỗi
        return [result("A-01", "FAIL", f"Không xác định được quyền: {exc}")]
    return [result("A-01", "INFO", "Đang chạy với quyền Administrator" if admin else "Đang chạy KHÔNG có quyền Administrator",
                   {"is_admin": admin})]


# ----------------------------------------------------------------------------- P: pywin32
BOOKMARK_API = ["EvtQuery", "EvtNext", "EvtRender", "EvtSubscribe", "EvtCreateBookmark",
                "EvtUpdateBookmark", "EvtSeek", "EvtClose", "EvtGetChannelConfigProperty"]
BOOKMARK_FLAGS = ["EvtQueryChannelPath", "EvtQueryReverseDirection", "EvtRenderEventXml", "EvtRenderBookmark",
                  "EvtSubscribeToFutureEvents", "EvtSubscribeStartAfterBookmark", "EvtSubscribeStrict"]


def check_pywin32() -> List[Dict[str, Any]]:
    if not IS_WINDOWS:
        return _skip("P-01")
    try:
        import win32evtlog  # type: ignore
    except ImportError as exc:
        return [result("P-01", "FAIL", f"Không import được win32evtlog: {exc}")]
    funcs = {n: hasattr(win32evtlog, n) for n in BOOKMARK_API}
    flags = {n: hasattr(win32evtlog, n) for n in BOOKMARK_FLAGS}
    ok = all(funcs[n] for n in ("EvtQuery", "EvtNext", "EvtRender"))
    status = "PASS" if ok else "FAIL"
    return [result("P-01", status, "pywin32 win32evtlog import được; liệt kê hàm/cờ có hoặc không có",
                   {"functions": funcs, "flags": flags})]


# ----------------------------------------------------------------------------- S: Sysmon
def _run(cmd: List[str], timeout: int = 20) -> Dict[str, Any]:
    try:
        p = subprocess.run(cmd, capture_output=True, text=True, timeout=timeout)
        return {"returncode": p.returncode, "stdout": p.stdout, "stderr": p.stderr}
    except Exception as exc:  # noqa: BLE001
        return {"returncode": None, "stdout": "", "stderr": str(exc)}


def check_sysmon_service() -> List[Dict[str, Any]]:
    if not IS_WINDOWS:
        return _skip("S-01")
    found = {}
    for name in ("Sysmon64", "Sysmon"):
        out = _run(["sc", "query", name])
        state = None
        for line in out["stdout"].splitlines():
            if "STATE" in line:
                state = line.split(":", 1)[1].strip()
        found[name] = {"returncode": out["returncode"], "state": state}
    running = any(v["state"] and "RUNNING" in v["state"] for v in found.values())
    return [result("S-01", "PASS" if running else "FAIL",
                   "Dịch vụ Sysmon đang chạy" if running else "Không thấy dịch vụ Sysmon đang chạy", {"services": found})]


def _read_one_event():
    import win32evtlog  # type: ignore
    flags = win32evtlog.EvtQueryChannelPath | win32evtlog.EvtQueryReverseDirection
    handle = win32evtlog.EvtQuery(SYSMON_CHANNEL, flags, "*", None)
    events = win32evtlog.EvtNext(handle, 1)
    return win32evtlog, handle, events


def check_channel_readable() -> List[Dict[str, Any]]:
    if not IS_WINDOWS:
        return _skip("R-01")
    try:
        win32evtlog, _h, events = _read_one_event()
    except ImportError as exc:
        return [result("R-01", "FAIL", f"Thiếu pywin32: {exc}")]
    except Exception as exc:  # noqa: BLE001
        code = exc.args[0] if getattr(exc, "args", None) else None
        msg = "Từ chối truy cập (cần Administrator hoặc quyền đọc log)" if code == 5 else f"Lỗi khi truy vấn kênh: {exc}"
        return [result("R-01", "FAIL", msg, {"winerror": code})]
    if not events:
        return [result("R-01", "FAIL", "Truy vấn được nhưng kênh Sysmon chưa có sự kiện nào", {})]
    xml = win32evtlog.EvtRender(events[0], win32evtlog.EvtRenderEventXml)
    root = ET.fromstring(xml)
    sysn = root.find("e:System", NS)
    event_id = sysn.findtext("e:EventID", default=None, namespaces=NS)
    record_id = sysn.findtext("e:EventRecordID", default=None, namespaces=NS)
    return [result("R-01", "PASS", "Đọc được 1 sự kiện từ kênh Sysmon (không ghi nội dung)",
                   {"event_id": event_id, "event_record_id": record_id})]


def check_bookmark_api() -> List[Dict[str, Any]]:
    """Thử bookmark và đăng ký sự kiện tương lai theo kiểu kéo. Ghi nguyên văn lỗi nếu API khác dự kiến."""
    if not IS_WINDOWS:
        return _skip("B-01")
    out: List[Dict[str, Any]] = []
    try:
        win32evtlog, _h, events = _read_one_event()
    except Exception as exc:  # noqa: BLE001
        return [result("B-01", "FAIL", f"Không đọc được sự kiện để tạo bookmark: {exc}")]
    if not events:
        return [result("B-01", "FAIL", "Không có sự kiện để tạo bookmark")]
    bm = None
    try:
        bm = win32evtlog.EvtCreateBookmark(None)
        win32evtlog.EvtUpdateBookmark(bm, events[0])
        bm_xml = win32evtlog.EvtRender(bm, win32evtlog.EvtRenderBookmark)
        out.append(result("B-01", "PASS", "Tạo, cập nhật và kết xuất bookmark thành công",
                          {"bookmark_xml_length": len(bm_xml)}))
    except Exception as exc:  # noqa: BLE001
        out.append(result("B-01", "FAIL", f"Bookmark lỗi: {type(exc).__name__}: {exc}"))
        return out
    try:
        import win32event  # type: ignore
        signal = win32event.CreateEvent(None, 0, 0, None)
        sub = win32evtlog.EvtSubscribe(SYSMON_CHANNEL, win32evtlog.EvtSubscribeToFutureEvents,
                                       SignalEvent=signal, Query="*")
        got = win32evtlog.EvtNext(sub, 1, 0)
        out.append(result("B-02", "PASS", "EvtSubscribe kiểu kéo (ToFutureEvents) khởi tạo được; EvtNext không chặn",
                          {"events_immediately_available": len(got)}))
    except Exception as exc:  # noqa: BLE001
        out.append(result("B-02", "FAIL", f"EvtSubscribe lỗi: {type(exc).__name__}: {exc}"))
    try:
        sub2 = win32evtlog.EvtSubscribe(SYSMON_CHANNEL, win32evtlog.EvtSubscribeStartAfterBookmark,
                                        SignalEvent=win32event.CreateEvent(None, 0, 0, None), Bookmark=bm, Query="*")
        out.append(result("B-03", "PASS", "EvtSubscribe bắt đầu sau bookmark khởi tạo được",
                          {"handle_created": sub2 is not None}))
    except Exception as exc:  # noqa: BLE001
        out.append(result("B-03", "FAIL", f"EvtSubscribe sau bookmark lỗi: {type(exc).__name__}: {exc}"))
    return out


def check_channel_size() -> List[Dict[str, Any]]:
    """Đọc cấu hình kích thước/retention của kênh Sysmon (chỉ đọc) để đánh giá nguy cơ bị ghi đè."""
    if not IS_WINDOWS:
        return _skip("L-01")
    out = _run(["wevtutil", "gl", SYSMON_CHANNEL])
    if out["returncode"] != 0:
        return [result("L-01", "FAIL", "Không đọc được cấu hình kênh", {"stderr": out["stderr"].strip()[:300]})]
    keep = {}
    for line in out["stdout"].splitlines():
        if ":" in line:
            k, v = line.split(":", 1)
            if k.strip() in ("enabled", "retention", "autoBackup", "maxSize"):
                keep[k.strip()] = v.strip()
    return [result("L-01", "INFO", "Cấu hình kênh Sysmon (maxSize tính bằng byte)", keep)]


# ----------------------------------------------------------------------------- F: hành vi tệp
def check_file_semantics(base: Path) -> List[Dict[str, Any]]:
    """Thử ghi LF, đổi tên sau khi đóng, đổi tên khi còn mở, os.replace ghi đè, fsync. Dọn sạch sau khi xong."""
    work = Path(tempfile.mkdtemp(prefix="dacn_verify_", dir=str(base)))
    out: List[Dict[str, Any]] = []
    try:
        part = work / "seg.jsonl.part"
        sealed = work / "seg.jsonl"
        with open(part, "w", encoding="utf-8", newline="\n") as fh:
            fh.write('{"a":1}\n{"b":2}\n')
            fh.flush()
            os.fsync(fh.fileno())
        raw = part.read_bytes()
        crlf = raw.count(b"\r\n")
        out.append(result("F-01", "PASS" if crlf == 0 else "FAIL", "Ghi JSONL với newline='\\n' không sinh CRLF",
                          {"crlf_count": crlf, "bytes": len(raw)}))
        os.replace(part, sealed)
        out.append(result("F-02", "PASS" if sealed.exists() and not part.exists() else "FAIL",
                          "Đổi tên .part → .jsonl sau khi đóng tệp"))
        # đổi tên khi còn mở (Windows thường từ chối)
        busy = work / "busy.part"
        fh2 = open(busy, "w", encoding="utf-8", newline="\n")
        try:
            fh2.write("x\n")
            fh2.flush()
            try:
                os.replace(busy, work / "busy.jsonl")
                out.append(result("F-03", "INFO", "Đổi tên khi tệp còn mở: ĐƯỢC phép trên nền tảng này"))
            except PermissionError as exc:
                out.append(result("F-03", "INFO", "Đổi tên khi tệp còn mở: BỊ CHẶN (đúng giả định cần đóng handle trước)",
                                  {"error": type(exc).__name__}))
        finally:
            fh2.close()
        # os.replace ghi đè đích đã có
        a, b = work / "a.tmp", work / "b.tmp"
        a.write_text("A", encoding="utf-8")
        b.write_text("B", encoding="utf-8")
        try:
            os.replace(a, b)
            out.append(result("F-04", "PASS" if b.read_text(encoding="utf-8") == "A" else "FAIL",
                              "os.replace ghi đè tệp đích đã tồn tại"))
        except Exception as exc:  # noqa: BLE001
            out.append(result("F-04", "FAIL", f"os.replace ghi đè lỗi: {type(exc).__name__}: {exc}"))
        out.append(result("F-05", "INFO", "Độ dài đường dẫn tạm đã dùng",
                          {"path_length": len(str(sealed)), "windows_default_limit": 260}))
    finally:
        shutil.rmtree(work, ignore_errors=True)
    return out


# ----------------------------------------------------------------------------- chạy
def run_all() -> List[Dict[str, Any]]:
    results: List[Dict[str, Any]] = []
    for fn in (check_environment, check_admin, check_pywin32, check_sysmon_service,
               check_channel_readable, check_bookmark_api, check_channel_size):
        results.extend(fn())
    results.extend(check_file_semantics(Path(tempfile.gettempdir())))
    return results


def main(argv: Optional[List[str]] = None) -> int:
    ap = argparse.ArgumentParser(description="Kiểm tra môi trường Windows cho DACN EDR (chỉ đọc)")
    ap.add_argument("--out", type=Path, default=Path("verify_report.json"), help="Tệp JSON báo cáo")
    args = ap.parse_args(argv)
    results = run_all()
    report = {
        "tool": "verify_windows_env",
        "version": "0.1",
        "generated_utc": datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ"),
        "run_id": uuid.uuid4().hex[:8],
        "results": results,
    }
    args.out.parent.mkdir(parents=True, exist_ok=True)
    args.out.write_text(json.dumps(report, ensure_ascii=False, indent=2), encoding="utf-8", newline="\n")
    width = max(len(r["id"]) for r in results)
    for r in results:
        print(f"[{r['status']:<4}] {r['id']:<{width}}  {r['message']}")
    fails = [r for r in results if r["status"] == "FAIL"]
    print(f"\nBáo cáo: {args.out}  ({len(fails)} FAIL)")
    return 1 if fails else 0


if __name__ == "__main__":
    sys.exit(main())
