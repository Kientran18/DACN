"""Quan sát bytes HIỆN TẠI; không suy ra bytes lịch sử từ Sysmon. Không chạy file hay mạng."""
from __future__ import annotations

import hashlib
import math
import os
import stat
import struct
import time
import uuid
from collections import Counter
from datetime import datetime, timezone
from pathlib import Path


def utc_now():
    return datetime.now(timezone.utc).isoformat()


class FileAccessError(ValueError):
    pass


def identity(s):
    # Python/Windows stat và fstat có thể trả st_ctime khác nghĩa (creation/change).
    # Dùng dev+file ID+size+mtime; không dùng timestamp mâu thuẫn để báo FILE_CHANGED giả.
    return (s.st_dev, s.st_ino, s.st_size, s.st_mtime_ns, s.st_ctime_ns if os.name != "nt" else 0)


def checked_path(path, roots):
    """Từ chối symlink/reparse trên mọi thành phần, UNC/device/ADS và đường dẫn ngoài root."""
    p = Path(path)
    if "\x00" in str(p) or not p.is_absolute() or (os.name == "nt" and (str(p).startswith("\\\\") or ":" in str(p)[2:])):
        raise FileAccessError("INVALID_PATH")
    for item in (p, *p.parents):
        try:
            s = item.lstat()
        except FileNotFoundError:
            continue
        if stat.S_ISLNK(s.st_mode) or getattr(s, "st_file_attributes", 0) & 0x400:
            raise FileAccessError("REPARSE_POINT")
    resolved = p.resolve()
    if not any(resolved.is_relative_to(Path(root).resolve()) for root in roots):
        raise FileAccessError("OUTSIDE_ROOTS")
    return resolved


def pe_metadata(header: bytes):
    """COFF header tối thiểu, kiểm biên; không nạp PE vào bộ nhớ thực thi."""
    if not header.startswith(b"MZ"):
        return {"status": "NOT_PE", "value": None}
    if len(header) < 64:
        return {"status": "MALFORMED", "value": None}
    off = struct.unpack_from("<I", header, 60)[0]
    if off + 26 > len(header):
        return {"status": "UNAVAILABLE_HEADER", "value": None}
    if header[off:off + 4] != b"PE\x00\x00":
        return {"status": "MALFORMED", "value": None}
    machine, sections, timestamp = struct.unpack_from("<HHI", header, off + 4)
    magic = struct.unpack_from("<H", header, off + 24)[0]
    return {"status": "OK", "value": {"machine": machine, "section_count": sections,
                                      "coff_timestamp": timestamp, "optional_header_magic": magic}}


class StaticExtractor:
    def __init__(self, roots, *, max_bytes=16 * 1024 * 1024, timeout_s=5.0, chunk_size=65536):
        if max_bytes < 1 or timeout_s <= 0 or chunk_size < 1:
            raise ValueError("giới hạn phải dương")
        self.roots, self.max_bytes, self.timeout_s, self.chunk_size = tuple(roots), max_bytes, timeout_s, chunk_size

    def extract(self, path, *, source_event_ids=(), patterns=(), expected_sha256=None):
        result = {"schema_version": "dacn-static/1.0", "analysis_id": str(uuid.uuid4()),
                  "observed_at": utc_now(), "extractor_version": "1.0", "path": str(path),
                  "source_event_ids": list(source_event_ids), "status": "ERROR", "error_code": None,
                  "sha256": None, "size_bytes": None, "entropy": None, "file_identity": None,
                  "pe": {"status": "UNAVAILABLE", "value": None},
                  "signature": {"status": "UNAVAILABLE", "reason": "NO_OFFLINE_TRUST_PROVIDER"},
                  "pattern_ids": [], "historical_identity": "UNVERIFIED"}
        start = time.monotonic()
        try:
            p = checked_path(path, self.roots)
            before_path = p.stat()
            if not stat.S_ISREG(before_path.st_mode):
                raise FileAccessError("NOT_REGULAR_FILE")
            if before_path.st_size > self.max_bytes:
                raise FileAccessError("TOO_LARGE")
            # O_NONBLOCK tránh block nếu đối tượng bị thay bằng FIFO trên POSIX; Windows bỏ qua.
            flags = os.O_RDONLY | getattr(os, "O_BINARY", 0) | getattr(os, "O_NOFOLLOW", 0) | getattr(os, "O_NONBLOCK", 0)
            with os.fdopen(os.open(p, flags), "rb") as stream:
                before = os.fstat(stream.fileno())
                if not stat.S_ISREG(before.st_mode) or identity(before) != identity(before_path):
                    raise FileAccessError("FILE_CHANGED")
                digest, counts, size, prefix, tail, hits = hashlib.sha256(), Counter(), 0, b"", b"", set()
                literals = [(x["id"], bytes.fromhex(x["hex"])) for x in patterns]
                if any(not b or len(b) > 256 for _, b in literals):
                    raise ValueError("pattern không hợp lệ")
                overlap = max((len(b) - 1 for _, b in literals), default=0)
                while True:
                    if time.monotonic() - start > self.timeout_s:
                        raise FileAccessError("TIMEOUT")
                    chunk = stream.read(min(self.chunk_size, self.max_bytes - size + 1))
                    if not chunk:
                        break
                    size += len(chunk)
                    if size > self.max_bytes:
                        raise FileAccessError("TOO_LARGE")
                    digest.update(chunk)
                    counts.update(chunk)
                    prefix = (prefix + chunk)[:65536]
                    block = tail + chunk
                    hits.update(pid for pid, literal in literals if literal in block)
                    tail = block[-overlap:] if overlap else b""
                after = os.fstat(stream.fileno())
                checked_path(path, self.roots)
                if identity(before) != identity(after) or identity(after) != identity(p.stat()) or size != after.st_size:
                    raise FileAccessError("FILE_CHANGED")
            sha = digest.hexdigest()
            if expected_sha256 and sha.lower() != expected_sha256.lower():
                raise FileAccessError("HASH_MISMATCH")
            result.update(status="OK", sha256=sha, size_bytes=size,
                          entropy=-sum((n / size) * math.log2(n / size) for n in counts.values()) if size else 0.0,
                          file_identity=list(identity(after)), pe=pe_metadata(prefix), pattern_ids=sorted(hits),
                          historical_identity="HASH_VERIFIED" if expected_sha256 else "UNVERIFIED")
        except FileNotFoundError:
            result["error_code"] = "NOT_FOUND"
        except PermissionError:
            result["error_code"] = "ACCESS_DENIED_OR_LOCKED"
        except FileAccessError as exc:
            result["error_code"] = str(exc)
        except OSError:
            result["error_code"] = "IO_ERROR"
        return result
