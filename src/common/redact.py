"""Che chuỗi giống bí mật trong văn bản script trước khi API trả về (docs/architecture/w8 mục 2.7, phương án P1, hạng mục 8).

HEURISTIC: chỉ giảm rủi ro lộ tình cờ khi xem trên dashboard, KHÔNG bảo đảm che hết bí mật. Bản gốc vẫn nằm ở Bronze/Silver
(ADR 0003); xem bản gốc qua API cần quyền `raw` và được ghi audit. Không dùng ở pipeline hay detection.
"""
from __future__ import annotations

import re
from typing import List, Tuple

MASK = "«ĐÃ CHE»"

# (tên, regex, nhóm cần che). Thứ tự quan trọng: mẫu cụ thể trước, chuỗi dài chung chung sau cùng.
_RULES: List[Tuple[str, "re.Pattern", int]] = [
    ("private_key", re.compile(r"-----BEGIN [A-Z ]*PRIVATE KEY-----.*?-----END [A-Z ]*PRIVATE KEY-----", re.S), 0),
    ("securestring_plaintext", re.compile(r"(?i)ConvertTo-SecureString\s+(?:-String\s+)?(['\"])(.+?)\1"), 2),
    ("password_param", re.compile(r"(?i)-(?:Password|Pass|Pwd|Secret|Token|ApiKey|AccessKey)\s+(['\"]?)([^\s'\";]+)\1"), 2),
    ("password_assign", re.compile(
        r"(?i)\b(?:password|passwd|pwd|secret|token|api[_-]?key|access[_-]?key|client[_-]?secret)\b\s*[:=]\s*(['\"]?)([^\s'\";]+)\1"), 2),
    ("bearer", re.compile(r"(?i)\bBearer\s+([A-Za-z0-9._~+/=-]{8,})"), 1),
    ("aws_access_key", re.compile(r"\b(AKIA[0-9A-Z]{16})\b"), 1),
    ("long_token", re.compile(r"[A-Za-z0-9+/=_-]{40,}"), 0),
]


def _long_token_like(s: str) -> bool:
    """Chuỗi dài có cả chữ hoa, chữ thường và chữ số (giống khóa/base64), không phải từ hay đường kẻ lặp lại."""
    return any(c.isupper() for c in s) and any(c.islower() for c in s) and any(c.isdigit() for c in s)


def redact(text: str) -> Tuple[str, List[str]]:
    """Trả (văn bản đã che, danh sách tên luật đã áp dụng, có lặp theo số lần). Không thay đổi độ dài ý nghĩa ngoài phần che."""
    if not text:
        return text, []
    hits: List[str] = []
    out = text
    for name, rx, group in _RULES:
        def sub(m, name=name, group=group):
            val = m.group(group)
            if name == "long_token" and not _long_token_like(val):
                return m.group(0)
            if MASK in val:
                return m.group(0)
            hits.append(name)
            start, end = m.start(group) - m.start(0), m.end(group) - m.start(0)
            whole = m.group(0)
            return whole[:start] + MASK + whole[end:]
        out = rx.sub(sub, out)
    return out, hits
