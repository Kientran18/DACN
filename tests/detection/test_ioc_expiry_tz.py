"""U4 (audit): `expires` không có múi giờ (YAML date hoặc datetime thiếu offset) phải hiểu là UTC, không theo giờ máy.
Trước đây .astimezone() coi giá trị thiếu múi giờ là giờ địa phương: trên VM UTC+7 IOC hết hạn sớm 7 giờ."""
import time
from datetime import datetime, timezone

import pytest
import yaml

from detection.ioc import IocStore

SHA = "a" * 64


@pytest.fixture
def vn_tz(monkeypatch):
    if not hasattr(time, "tzset"):
        pytest.skip("cần time.tzset (POSIX)")
    monkeypatch.setenv("TZ", "Asia/Ho_Chi_Minh")
    time.tzset()
    yield
    monkeypatch.undo()
    time.tzset()


@pytest.mark.parametrize("expires", ["2026-12-01", "2026-12-01T00:00:00"])
def test_naive_expiry_is_utc_not_local_time(tmp_path, vn_tz, expires):
    p = tmp_path / "ioc.yaml"
    p.write_text(f"ioc_hashes:\n  - {{sha256: {SHA}, source: t, expires: {expires}}}\n", encoding="utf-8")
    assert not isinstance(yaml.safe_load(p.read_text())["ioc_hashes"][0]["expires"], str)   # YAML trả date/datetime
    before = IocStore(p, now=datetime(2026, 11, 30, 20, 0, tzinfo=timezone.utc))            # 4 giờ trước 00:00 UTC
    after = IocStore(p, now=datetime(2026, 12, 1, 0, 0, 1, tzinfo=timezone.utc))
    assert before.check(SHA)[0] == "IOC_MATCH" and after.check(SHA)[0] is None


def test_explicit_offset_is_respected(tmp_path):
    p = tmp_path / "ioc.yaml"
    p.write_text(f"ioc_hashes:\n  - {{sha256: {SHA}, source: t, expires: '2026-12-01T07:00:00+07:00'}}\n", encoding="utf-8")
    assert IocStore(p, now=datetime(2026, 11, 30, 23, 59, tzinfo=timezone.utc)).check(SHA)[0] == "IOC_MATCH"
    assert IocStore(p, now=datetime(2026, 12, 1, 0, 1, tzinfo=timezone.utc)).check(SHA)[0] is None
