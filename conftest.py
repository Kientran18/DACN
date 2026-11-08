"""Cấu hình pytest gốc (PH1-T08/T11).

- Đưa các thư mục mã nguồn vào sys.path để import module bằng tên trần
  mà không đổi vị trí tệp (D-03 phương án a).
- Marker `windows`: test chỉ chạy trên Windows, tự skip trên hệ khác.
"""
import sys
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parent
for _p in (ROOT, ROOT / "src", ROOT / "src" / "pipeline", ROOT / "poc" / "sysmon-collector"):
    if str(_p) not in sys.path:
        sys.path.insert(0, str(_p))


def pytest_collection_modifyitems(config, items):
    if sys.platform == "win32":
        return
    skip = pytest.mark.skip(reason="cần Windows host thật (marker 'windows')")
    for item in items:
        if "windows" in item.keywords:
            item.add_marker(skip)
