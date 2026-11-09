"""Backend thao tác thật trên tiến trình/tệp qua một lớp API tiến trình có thể thay (giả khi test).
File ops chạy trên hệ thống tệp thật nhưng bị khóa trong allowed_roots (thư mục lab)."""
from __future__ import annotations

import hashlib
import json
import os
import shutil
from datetime import datetime, timezone
from pathlib import Path
from typing import Dict, List, Optional

from ..policy import is_within


class FakeProcessApi:
    """Mô phỏng tiến trình cho test. Không chạm tiến trình thật."""

    def __init__(self, procs: Dict[int, dict]):
        self.procs = dict(procs)
        self.terminated: List[int] = []

    def inspect(self, pid: int) -> Optional[dict]:
        p = self.procs.get(pid)
        return dict(p) if p else None

    def terminate(self, pid: int, expected_creation_time=None) -> None:
        self.terminated.append(pid)
        self.procs.pop(pid, None)


def _sha256(path) -> str:
    h = hashlib.sha256()
    with open(path, "rb") as f:
        for c in iter(lambda: f.read(1 << 20), b""):
            h.update(c)
    return h.hexdigest()


def _parse_time(v):
    if isinstance(v, (int, float)):
        return float(v)
    return datetime.fromisoformat(str(v).replace("Z", "+00:00").replace(" ", "T")).astimezone(timezone.utc).timestamp()


def same_time(a, b, tolerance_s: float = 0.0) -> bool:
    """Thời điểm tạo tiến trình. Số nguyên: so sánh đúng; chuỗi ISO: cho phép sai số (Sysmon UtcTime chỉ chính xác ms)."""
    try:
        return abs(_parse_time(a) - _parse_time(b)) <= tolerance_s
    except (ValueError, TypeError):
        return False


def _same_path(a, b) -> bool:
    return os.path.normcase(os.path.normpath(str(a))) == os.path.normcase(os.path.normpath(str(b)))


class LocalBackend:
    def __init__(self, process_api, allowed_roots, creation_tolerance_s: float = 0.0):
        self.api, self.roots = process_api, [Path(r) for r in allowed_roots]
        self.tol = creation_tolerance_s

    def _inside(self, p) -> bool:
        return any(is_within(p, r) for r in self.roots)

    def execute(self, action_type: str, target: dict, ctx: dict) -> dict:
        fn = {"TERMINATE_PROCESS": self._terminate, "QUARANTINE_FILE": self._quarantine, "RESTORE_FILE": self._restore,
              "ADD_WHITELIST": self._add_whitelist, "REMOVE_WHITELIST": self._remove_whitelist}[action_type]
        return fn(target, ctx)

    # -- tiến trình: xác minh lại danh tính NGAY TRƯỚC khi hành động ------------------------
    def _terminate(self, t: dict, ctx: dict) -> dict:
        cur = self.api.inspect(t["pid"])
        if cur is None:
            return {"ok": False, "code": "X-TARGET_GONE", "message": "tiến trình không còn"}
        if not same_time(cur["creation_time"], t["creation_time"], self.tol) or not _same_path(cur["image_path"], t["image_path"]):
            return {"ok": False, "code": "X-IDENTITY_MISMATCH", "message": "PID đã bị tái sử dụng hoặc ảnh khác"}
        self.api.terminate(t["pid"], t["creation_time"])
        return {"ok": True, "terminated_pid": t["pid"], "identity_verified": True}

    def _quarantine(self, t: dict, ctx: dict) -> dict:
        src = Path(t["path"])
        if not self._inside(src):
            return {"ok": False, "code": "X-OUTSIDE_ROOTS"}
        if not src.exists():
            return {"ok": False, "code": "X-NOT_FOUND"}
        if src.is_symlink() or not src.is_file():
            return {"ok": False, "code": "X-NOT_REGULAR_FILE"}
        sha = _sha256(src)
        if t.get("expected_sha256") and t["expected_sha256"].lower() != sha:
            return {"ok": False, "code": "X-HASH_MISMATCH", "message": "hash tệp khác kỳ vọng"}
        qdir = Path(ctx["quarantine_dir"]); qdir.mkdir(parents=True, exist_ok=True)
        dest = qdir / (ctx["action_id"] + ".quar")
        if dest.exists():
            return {"ok": False, "code": "X-DEST_EXISTS"}
        meta = {"original_path": str(src), "sha256": sha, "size": src.stat().st_size, "action_id": ctx["action_id"],
                "quarantined_at_utc": datetime.now(timezone.utc).isoformat()}
        Path(str(dest) + ".json").write_text(json.dumps(meta), encoding="utf-8")
        shutil.move(str(src), str(dest))
        return {"ok": True, "quarantined_to": str(dest), "original_path": str(src), "sha256": sha}

    def _restore(self, t: dict, ctx: dict) -> dict:
        q, orig = Path(t["quarantined_to"]), Path(t["original_path"])
        if not self._inside(q) or not self._inside(orig):
            return {"ok": False, "code": "X-OUTSIDE_ROOTS"}
        meta_p = Path(str(q) + ".json")
        if not q.exists() or not meta_p.exists():
            return {"ok": False, "code": "X-NOT_FOUND"}
        meta = json.loads(meta_p.read_text(encoding="utf-8"))
        if orig.exists():
            return {"ok": False, "code": "X-DEST_EXISTS", "message": "không ghi đè tệp đang có"}
        if _sha256(q) != meta["sha256"] or (t.get("expected_sha256") and t["expected_sha256"] != meta["sha256"]):
            return {"ok": False, "code": "X-HASH_MISMATCH", "message": "tệp cách ly đã bị đổi"}
        shutil.move(str(q), str(orig))
        meta_p.unlink()
        return {"ok": True, "restored_to": str(orig), "sha256": meta["sha256"]}

    # -- allowlist hash (ADD/REMOVE_WHITELIST): sửa tệp ioc.yaml nguyên tử; detection tự quét lại khi allowlist đổi -----------
    @staticmethod
    def _load_ioc(path: Path) -> dict:
        import yaml
        if not path.exists():
            return {}
        d = yaml.safe_load(path.read_text(encoding="utf-8")) or {}
        if not isinstance(d, dict):
            raise ValueError("ioc.yaml phải là mapping")
        return d

    @staticmethod
    def _store_ioc(path: Path, d: dict) -> None:
        import yaml
        path.parent.mkdir(parents=True, exist_ok=True)
        tmp = path.with_name(path.name + ".tmp")
        tmp.write_text(yaml.safe_dump(d, allow_unicode=True, sort_keys=False), encoding="utf-8")
        os.replace(tmp, path)

    def _add_whitelist(self, t: dict, ctx: dict) -> dict:
        if not ctx.get("ioc_path"):
            return {"ok": False, "code": "X-NO_IOC_PATH"}
        path, sha = Path(ctx["ioc_path"]), t["sha256"].lower()
        try:
            d = self._load_ioc(path)
        except Exception:
            return {"ok": False, "code": "X-IOC_FILE_INVALID", "message": "ioc.yaml không đọc được; không ghi đè"}
        if sha in {str(h.get("sha256", "")).lower() for h in d.get("ioc_hashes", []) if isinstance(h, dict)}:
            return {"ok": False, "code": "X-IOC_CONFLICT", "message": "hash đang là IOC; gỡ IOC trước, không whitelist ngầm"}
        allow = [str(a).lower() for a in d.get("allowlist_hashes", [])]
        if sha in allow:
            return {"ok": False, "code": "X-ALREADY_ALLOWLISTED"}
        d["allowlist_hashes"] = allow + [sha]
        meta = d.get("allowlist_meta") or {}
        meta[sha] = {"reason": str(t.get("reason", ""))[:500], "action_id": ctx["action_id"],
                     "added_at_utc": datetime.now(timezone.utc).isoformat()}
        d["allowlist_meta"] = meta
        self._store_ioc(path, d)
        return {"ok": True, "sha256": sha, "ioc_path": str(path)}

    def _remove_whitelist(self, t: dict, ctx: dict) -> dict:
        if not ctx.get("ioc_path"):
            return {"ok": False, "code": "X-NO_IOC_PATH"}
        path, sha = Path(ctx["ioc_path"]), t["sha256"].lower()
        try:
            d = self._load_ioc(path)
        except Exception:
            return {"ok": False, "code": "X-IOC_FILE_INVALID", "message": "ioc.yaml không đọc được; không ghi đè"}
        allow = [str(a).lower() for a in d.get("allowlist_hashes", [])]
        if sha not in allow:
            return {"ok": False, "code": "X-NOT_ALLOWLISTED"}
        d["allowlist_hashes"] = [a for a in allow if a != sha]
        (d.get("allowlist_meta") or {}).pop(sha, None)
        self._store_ioc(path, d)
        return {"ok": True, "sha256": sha, "ioc_path": str(path)}
