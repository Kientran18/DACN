"""Xác thực Bearer token và phân quyền theo vai trò (PH8-T01). Token lưu dạng sha256, không lưu bản rõ."""
from __future__ import annotations

import hashlib
import hmac
import json
import os
import secrets
from pathlib import Path
from typing import Dict, Optional

ROLES = {
    "viewer": {"read"},
    "analyst": {"read", "alert_write", "request_action", "raw"},
    "approver": {"read", "alert_write", "request_action", "raw", "approve"},
    "responder": {"responder"},      # tiến trình responder: không đọc dữ liệu, chỉ nhận/ báo hành động
}


def hash_token(token: str) -> str:
    return hashlib.sha256(token.encode("utf-8")).hexdigest()


class TokenStore:
    def __init__(self, entries: Dict[str, dict]):
        for h, e in entries.items():
            if e.get("role") not in ROLES or not e.get("actor"):
                raise ValueError("token entry không hợp lệ")
        self.entries = entries

    @classmethod
    def load(cls, path: Path) -> "TokenStore":
        p = Path(path)
        if not p.exists():
            return cls({})
        return cls(json.loads(p.read_text(encoding="utf-8")))

    def lookup(self, token: Optional[str]) -> Optional[dict]:
        if not token:
            return None
        h, found = hash_token(token), None
        for known, entry in self.entries.items():      # duyệt hết, so sánh thời gian hằng
            if hmac.compare_digest(known, h):
                found = entry
        return found


def create_token(path: Path, role: str, actor: str) -> str:
    """Tạo token ngẫu nhiên, ghi băm vào tệp, trả bản rõ MỘT LẦN."""
    if role not in ROLES or not actor.strip():
        raise ValueError("role/actor không hợp lệ")
    p = Path(path)
    data = json.loads(p.read_text(encoding="utf-8")) if p.exists() else {}
    token = secrets.token_urlsafe(32)
    data[hash_token(token)] = {"role": role, "actor": actor.strip()}
    p.parent.mkdir(parents=True, exist_ok=True)
    tmp = p.with_suffix(".tmp")
    tmp.write_text(json.dumps(data, indent=2), encoding="utf-8")
    os.replace(tmp, p)
    return token


def main(argv=None) -> int:
    import argparse
    from common.config import load_config
    ap = argparse.ArgumentParser(prog="api.auth")
    ap.add_argument("--config", type=Path)
    ap.add_argument("--role", required=True, choices=sorted(ROLES))
    ap.add_argument("--actor", required=True)
    a = ap.parse_args(argv)
    cfg = load_config(a.config)
    print("Token (chỉ hiện một lần, hãy lưu lại):", create_token(cfg.tokens_path, a.role, a.actor))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
