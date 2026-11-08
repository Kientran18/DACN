"""Kho IOC và allowlist cục bộ (PH4-T07). Không tự tải feed; không wildcard."""
from __future__ import annotations

from datetime import datetime, timezone
from pathlib import Path
from typing import Optional

import yaml


class IocStore:
    def __init__(self, path: Optional[Path] = None, now: Optional[datetime] = None):
        self.hashes: dict = {}
        self.allow: set = set()
        self.version = None
        now = now or datetime.now(timezone.utc)
        if path and Path(path).exists():
            d = yaml.safe_load(Path(path).read_text(encoding="utf-8")) or {}
            self.version = d.get("version")
            for h in d.get("ioc_hashes", []):
                exp = h.get("expires")
                if exp and datetime.fromisoformat(str(exp).replace("Z", "+00:00")).astimezone(timezone.utc) < now:
                    continue
                self.hashes[h["sha256"].lower()] = {"source": h.get("source"), "note": h.get("note")}
            self.allow = {a.lower() for a in d.get("allowlist_hashes", [])}

    def check(self, sha256: Optional[str]):
        """(status, info). status ∈ ALLOWLISTED | IOC_MATCH | None. Allowlist ưu tiên."""
        if not sha256:
            return None, None
        h = sha256.lower()
        if h in self.allow:
            return "ALLOWLISTED", None
        if h in self.hashes:
            return "IOC_MATCH", self.hashes[h]
        return None, None
