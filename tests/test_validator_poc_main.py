"""B4 (audit): `python src/pipeline/validator_poc.py` chạy từ thư mục gốc phải nạp 4 tệp mẫu W03 trong
references/samples/json/, như docs/architecture/w5/validation_quality_lineage_and_governance_v1.md mục kiểm thử mô tả
(8 bản ghi thật + 2 bản phát lại trùng + 5 mẫu DNS/lỗi = 15)."""
import os
import re
import subprocess
import sys
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[1]


def test_main_from_repo_root_loads_w03_samples():
    pytest.importorskip("duckdb")
    out = subprocess.run([sys.executable, "src/pipeline/validator_poc.py"], cwd=ROOT, capture_output=True,
                         text=True, encoding="utf-8", timeout=120, check=True,
                         env={**os.environ, "PYTHONIOENCODING": "cp1252"}).stdout   # mô phỏng ống dẫn (pipe) trên Windows
    nums = {k: int(v) for k, v in re.findall(r"(Tổng số bản ghi đầu vào đã đọc|trùng lặp đã loại bỏ)\s*:\s*(\d+)", out)}
    assert nums == {"Tổng số bản ghi đầu vào đã đọc": 15, "trùng lặp đã loại bỏ": 2}
