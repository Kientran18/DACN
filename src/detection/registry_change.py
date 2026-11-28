"""Phân loại một thay đổi giá trị registry dạng `<khóa>\\<tên giá trị> = <giá trị>` (Defender Event 5007 'Old Value'/'New Value').

Dùng cho khóa rule `registry_change_filter` (DACN-DET-202 v3, cách C ở docs/architecture/w8 mục 12.14). Chỉ suy luận hướng ở chỗ
ý nghĩa tự rõ từ tên, không đoán ngữ nghĩa giá trị của từng chính sách:
- NOOP: cùng khóa, cùng giá trị (không phân biệt hoa/thường).
- Tên giá trị bắt đầu bằng `Disable` và giá trị là số: 0/không có -> khác 0 = WEAKEN; khác 0 -> 0/xóa = STRENGTHEN; còn lại CHANGE.
- Khóa thuộc nhánh `\\Exclusions\\`: thêm (hoặc đổi sang khóa khác) = WEAKEN; xóa = STRENGTHEN.
- Mọi trường hợp khác (ví dụ TamperProtection, Spynet: ý nghĩa giá trị chưa được kiểm chứng) = CHANGE.
- Cả hai phía trống/thiếu: None (không có gì để phân loại; rule không lọc).
"""
from __future__ import annotations

from typing import Optional, Tuple

CLASSES = ("NOOP", "WEAKEN", "STRENGTHEN", "CHANGE")


def _split(v) -> Tuple[Optional[str], Optional[str]]:
    s = (v or "").strip()
    if not s:
        return None, None
    key, sep, val = s.partition(" = ")
    return key.strip(), (val.strip() if sep else None)


def _num(v: Optional[str]) -> Optional[int]:
    if v is None:
        return None
    try:
        return int(v, 0)
    except ValueError:
        return None


def classify_registry_change(old, new) -> Optional[str]:
    ko, vo = _split(old)
    kn, vn = _split(new)
    if ko is None and kn is None:
        return None
    if ko is not None and kn is not None and ko.lower() == kn.lower() and (vo or "").lower() == (vn or "").lower():
        return "NOOP"
    key = (kn or ko)
    name = key.rsplit("\\", 1)[-1].lower()
    if "\\exclusions\\" in key.lower():
        if kn is None:
            return "STRENGTHEN"
        if ko is None or ko.lower() != kn.lower():
            return "WEAKEN"
        return "CHANGE"
    if name.startswith("disable"):
        o = 0 if ko is None else _num(vo)
        n = 0 if kn is None else _num(vn)
        if o is None or n is None:
            return "CHANGE"
        if o == 0 and n != 0:
            return "WEAKEN"
        if o != 0 and n == 0:
            return "STRENGTHEN"
        return "CHANGE"
    return "CHANGE"
