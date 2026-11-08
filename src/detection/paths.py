"""Chuẩn hóa đường dẫn tệp Windows để tương quan (PH4-T06). Không đoán ánh xạ \\Device\\."""
from __future__ import annotations

from typing import Optional


def normalize_path(p: Optional[str]) -> Optional[str]:
    """None nếu không chuẩn hóa được một cách chắc chắn (ví dụ \\Device\\HarddiskVolumeN)."""
    if not p:
        return None
    s = p.strip().strip('"').replace("/", "\\")
    for prefix in ("\\\\?\\", "\\??\\"):
        if s.startswith(prefix):
            s = s[len(prefix):]
    if s.lower().startswith("\\device\\"):
        return None
    return s.lower()
