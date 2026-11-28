"""Bronze segment writer (PH2-T02) + phục hồi (PH2-T04).

`.jsonl.part` (UTF-8, LF) → seal bằng os.replace sang `.jsonl` + `.manifest.json`.
Không đổi schema Bronze; bản ghi do bronze_contract.build_bronze_record tạo (1.0 cho Sysmon, 1.1 cho Defender/PowerShell).
"""
from __future__ import annotations

import hashlib
import json
import os
import time
from datetime import datetime, timezone
from pathlib import Path
from typing import List, Optional

import bronze_contract as bc


def _sha256(path: Path) -> str:
    h = hashlib.sha256()
    with path.open("rb") as f:
        for chunk in iter(lambda: f.read(1 << 20), b""):
            h.update(chunk)
    return h.hexdigest()


class BronzeWriter:
    def __init__(self, directory: Path, *, max_records: int = 5000,
                 max_bytes: int = 8 << 20, max_age_s: float = 300.0, name_prefix: str = ""):
        """name_prefix: chèn sau `seg-` để mỗi kênh có segment riêng (ví dụ `microsoft_windows_powershell_operational-`).
        Rỗng (mặc định, kênh Sysmon) giữ nguyên tên segment như trước; `list_sealed` vẫn dùng glob `seg-*.jsonl`."""
        self.dir = Path(directory)
        self.name_prefix = name_prefix
        self.dir.mkdir(parents=True, exist_ok=True)
        self.max_records, self.max_bytes, self.max_age_s = max_records, max_bytes, max_age_s
        self._fh = None
        self._part: Optional[Path] = None
        self._n = 0
        self._bytes = 0
        self._opened = 0.0
        self._first = self._last = None
        self._counter = 0
        self.last_sealed: Optional[Path] = None
        self.last_sealed_at: Optional[str] = None   # = sealed_at trong manifest của segment seal gần nhất

    def _open(self) -> None:
        stamp = datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%S%fZ")
        self._counter += 1
        self._part = self.dir / f"seg-{self.name_prefix}{stamp}-{self._counter:04d}.jsonl.part"
        self._fh = self._part.open("wb")
        self._n = self._bytes = 0
        self._first = self._last = None
        self._opened = time.monotonic()

    def append(self, record: dict) -> None:
        if self._fh is None:
            self._open()
        line = (json.dumps(record, ensure_ascii=False, separators=(",", ":")) + "\n").encode("utf-8")
        self._fh.write(line)
        self._n += 1
        self._bytes += len(line)
        self._first = self._first or record["record_id"]
        self._last = record["record_id"]
        if (self._n >= self.max_records or self._bytes >= self.max_bytes
                or time.monotonic() - self._opened >= self.max_age_s):
            self.seal()

    def flush(self) -> None:
        if self._fh is not None:
            self._fh.flush()
            os.fsync(self._fh.fileno())

    def abort(self) -> None:
        """Bỏ segment đang mở sau lỗi ghi (đĩa đầy, từ chối quyền): đóng handle, bỏ qua lỗi đóng, KHÔNG seal.
        Tệp `.part` được giữ nguyên để recover_dir cắt dòng dở và seal phần hợp lệ ở lượt sau."""
        fh, self._fh = self._fh, None
        if fh is not None:
            try:
                fh.close()
            except OSError:
                pass

    def seal(self) -> Optional[Path]:
        if self._fh is None:
            return None
        self.flush()
        self._fh.close()
        part, n, first, last = self._part, self._n, self._first, self._last
        self._fh = None
        sealed_at = datetime.now(timezone.utc).isoformat()
        seg = _finalize(part, n, first, last, sealed_at)
        self.last_sealed, self.last_sealed_at = seg, sealed_at
        return seg


def _finalize(part: Path, n: int, first, last, sealed_at: Optional[str] = None) -> Path:
    """Manifest TRƯỚC (tệp tạm -> fsync -> os.replace), đổi tên `.part` -> `.jsonl` SAU CÙNG.
    Nhờ đó reader không bao giờ thấy segment thiếu manifest hoặc manifest ghi dở; crash giữa chừng
    chỉ để lại `.part` mà recover_dir xử lý được."""
    seg = part.with_suffix("")  # bỏ '.part' → .jsonl
    versions = _schema_versions(part)
    manifest = {"segment": seg.name, "sha256": _sha256(part), "record_count": n,
                "first_record_id": first, "last_record_id": last,
                # Một phiên bản duy nhất (thường gặp: mỗi kênh một writer). Segment trộn phiên bản (file mode đọc export
                # nhiều kênh) ghi "mixed" kèm danh sách; segment rỗng giữ phiên bản mặc định như trước.
                "schema_version": versions[0] if len(versions) == 1 else ("mixed" if versions else bc.SCHEMA_VERSION),
                "collector_version": bc.COLLECTOR_VERSION,
                "sealed_at": sealed_at or datetime.now(timezone.utc).isoformat()}
    if len(versions) > 1:
        manifest["schema_versions"] = versions
    mp = seg.with_suffix(".manifest.json")
    tmp = mp.with_name(mp.name + ".tmp")
    with tmp.open("w", encoding="utf-8", newline="\n") as f:
        json.dump(manifest, f, indent=2)
        f.flush()
        os.fsync(f.fileno())
    os.replace(tmp, mp)
    os.replace(part, seg)
    return seg


def _schema_versions(part: Path) -> List[str]:
    """Các `schema_version` có trong tệp (sắp xếp). Dòng không đọc được bỏ qua: recover_dir đã lọc dòng hỏng."""
    found = set()
    with part.open("rb") as f:
        for line in f:
            try:
                v = json.loads(line).get("schema_version")
            except (ValueError, AttributeError):
                continue
            if isinstance(v, str):
                found.add(v)
    return sorted(found)


def verify_segment(seg: Path) -> List[str]:
    """Danh sách lỗi (rỗng = hợp lệ). Manifest hỏng/ghi dở là lỗi V-MANIFEST_UNREADABLE, không ném ngoại lệ."""
    seg = Path(seg)
    mp = seg.with_suffix(".manifest.json")
    if not mp.exists():
        return ["V-MANIFEST_MISSING"]
    try:
        m = json.loads(mp.read_text(encoding="utf-8"))
        want_sha, want_n = m["sha256"], m["record_count"]
    except (OSError, ValueError, KeyError, TypeError):
        return ["V-MANIFEST_UNREADABLE"]
    errs = []
    if _sha256(seg) != want_sha:
        errs.append("V-HASH_MISMATCH")
    with seg.open("rb") as f:
        if sum(1 for _ in f) != want_n:
            errs.append("V-COUNT_MISMATCH")
    return errs


def recover_dir(directory: Path) -> List[dict]:
    """Xử lý `.part` mồ côi sau crash: seal mọi dòng JSON hợp lệ; dòng hỏng (dòng dở ở cuối, hoặc hỏng giữa tệp)
    được chuyển nguyên byte vào quarantine/<tên>.invalid, không xóa. Không còn dòng hợp lệ -> cả tệp vào quarantine/."""
    d = Path(directory)
    report = []
    for part in sorted(d.glob("*.jsonl.part")):
        good, bad, first, last, bad_not_tail = [], [], None, None, False
        lines = part.read_bytes().splitlines(keepends=True)
        for i, raw in enumerate(lines):
            try:
                if not raw.endswith(b"\n"):
                    raise ValueError("no newline")
                rec = json.loads(raw)
                rid = rec["record_id"]
            except (ValueError, KeyError, TypeError):
                bad.append(raw)
                bad_not_tail = bad_not_tail or i < len(lines) - 1
                continue
            good.append(raw)
            first = first or rid
            last = rid
        q = d / "quarantine"
        if not good:
            q.mkdir(exist_ok=True)
            os.replace(part, q / part.name)
            report.append({"file": part.name, "reason": "R-EMPTY_PART", "records": 0, "invalid_lines": len(bad)})
            continue
        if bad:
            q.mkdir(exist_ok=True)
            with (q / (part.name + ".invalid")).open("ab") as f:
                f.write(b"".join(bad))
                f.flush()
                os.fsync(f.fileno())
        part.write_bytes(b"".join(good))
        _finalize(part, len(good), first, last)
        reason = "R-INVALID_LINES" if bad_not_tail else ("R-TRUNCATED_TAIL" if bad else "R-SEALED_ORPHAN")
        report.append({"file": part.name, "records": len(good), "invalid_lines": len(bad), "reason": reason})
    return report
