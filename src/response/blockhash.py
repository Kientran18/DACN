"""Block hash MỨC ỨNG DỤNG (PH7-T09): thêm hash vào kho IOC cục bộ để lần phát hiện sau gắn cờ.
Đây là detection, KHÔNG phải prevention: không ngăn thực thi ở mức hệ điều hành."""
from __future__ import annotations

import os
import re
from pathlib import Path

import yaml


def block_hash(ioc_path, sha256: str, *, actor: str, reason: str, audit=None) -> str:
    if not re.fullmatch(r"[0-9a-fA-F]{64}", sha256 or ""):
        raise ValueError("sha256 không hợp lệ")
    if not actor or not reason:
        raise ValueError("cần actor và reason")
    p = Path(ioc_path)
    data = (yaml.safe_load(p.read_text(encoding="utf-8")) if p.exists() else None) or {}
    data.setdefault("version", "analyst-block")
    items = data.setdefault("ioc_hashes", [])
    if not any(i.get("sha256", "").lower() == sha256.lower() for i in items):
        items.append({"sha256": sha256.lower(), "source": "analyst-block", "note": reason})
    tmp = p.with_suffix(".tmp")
    tmp.write_text(yaml.safe_dump(data, allow_unicode=True), encoding="utf-8")
    os.replace(tmp, p)
    if audit is not None:
        audit.record(actor, "BLOCK_HASH", "hash", sha256.lower(), reason)
    return "Hash được gắn cờ ở các lần phát hiện sau (detection). Việc này không ngăn thực thi ở mức hệ điều hành."
