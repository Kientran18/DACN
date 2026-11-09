"""Bronze segment writer (PH2-T02) + phục hồi (PH2-T04).

`.jsonl.part` (UTF-8, LF) → seal bằng os.replace sang `.jsonl` + `.manifest.json`.
Không đổi schema bronze-event/1.0; bản ghi do bronze_contract.build_bronze_record tạo.
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
                 max_bytes: int = 8 << 20, max_age_s: float = 300.0):
        self.dir = Path(directory)
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

    def _open(self) -> None:
        stamp = datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%S%fZ")
        self._counter += 1
        self._part = self.dir / f"seg-{stamp}-{self._counter:04d}.jsonl.part"
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

    def seal(self) -> Optional[Path]:
        if self._fh is None:
            return None
        self.flush()
        self._fh.close()
        part, n, first, last = self._part, self._n, self._first, self._last
        self._fh = None
        seg = _finalize(part, n, first, last)
        self.last_sealed = seg
        return seg


def _finalize(part: Path, n: int, first, last) -> Path:
    """Manifest TRƯỚC (tệp tạm -> fsync -> os.replace), đổi tên `.part` -> `.jsonl` SAU CÙNG.
    Nhờ đó reader không bao giờ thấy segment thiếu manifest hoặc manifest ghi dở; crash giữa chừng
    chỉ để lại `.part` mà recover_dir xử lý được."""
    seg = part.with_suffix("")  # bỏ '.part' → .jsonl
    manifest = {"segment": seg.name, "sha256": _sha256(part), "record_count": n,
                "first_record_id": first, "last_record_id": last,
                "schema_version": bc.SCHEMA_VERSION, "collector_version": bc.COLLECTOR_VERSION,
                "sealed_at": datetime.now(timezone.utc).isoformat()}
    mp = seg.with_suffix(".manifest.json")
    tmp = mp.with_name(mp.name + ".tmp")
    with tmp.open("w", encoding="utf-8", newline="\n") as f:
        json.dump(manifest, f, indent=2)
        f.flush()
        os.fsync(f.fileno())
    os.replace(tmp, mp)
    os.replace(part, seg)
    return seg


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
    """Xử lý `.part` mồ côi sau crash: cắt dòng dở, seal phần hợp lệ; rỗng → quarantine/."""
    d = Path(directory)
    report = []
    for part in sorted(d.glob("*.jsonl.part")):
        good, first, last, truncated = [], None, None, False
        for raw in part.read_bytes().splitlines(keepends=True):
            try:
                if not raw.endswith(b"\n"):
                    raise ValueError("no newline")
                rec = json.loads(raw)
                good.append(raw)
                first = first or rec["record_id"]
                last = rec["record_id"]
            except (ValueError, KeyError):
                truncated = True
                break
        if not good:
            q = d / "quarantine"
            q.mkdir(exist_ok=True)
            os.replace(part, q / part.name)
            report.append({"file": part.name, "reason": "R-EMPTY_PART", "records": 0})
            continue
        part.write_bytes(b"".join(good))
        _finalize(part, len(good), first, last)
        report.append({"file": part.name, "records": len(good),
                       "reason": "R-TRUNCATED_TAIL" if truncated else "R-SEALED_ORPHAN"})
    return report
