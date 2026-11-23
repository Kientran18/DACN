"""Windows không có cơ sở dữ liệu múi giờ IANA của hệ điều hành: DuckDB cần gói `tzdata` để đọc TIMESTAMPTZ khi múi giờ máy
không phải UTC (đo trên VM Windows: 'Time zone ... is not available to Python's zoneinfo'). Khóa vào requirements."""
from pathlib import Path

REQ = Path(__file__).resolve().parents[1] / "requirements.txt"


def test_tzdata_is_required_on_windows():
    lines = [l.split("#")[0].strip() for l in REQ.read_text(encoding="utf-8").splitlines()]
    assert any(l.startswith("tzdata") and "win32" in l for l in lines)
