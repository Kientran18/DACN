import hashlib
import struct

import pytest

from static_analysis import extractor as module
from static_analysis.extractor import StaticExtractor, pe_metadata


@pytest.mark.parametrize("data,entropy", [(b"", 0), (b"a" * 1000, 0), (bytes(range(256)) * 4, 8)])
def test_known_hash_size_byte_entropy_and_unavailable_signature(tmp_path, data, entropy):
    p = tmp_path / "benign.bin"; p.write_bytes(data)
    result = StaticExtractor([tmp_path]).extract(p)
    assert result["status"] == "OK"
    assert result["sha256"] == hashlib.sha256(data).hexdigest()
    assert result["size_bytes"] == len(data) and result["entropy"] == pytest.approx(entropy)
    assert result["signature"]["status"] == "UNAVAILABLE"
    assert result["historical_identity"] == "UNVERIFIED"


def test_literal_pattern_crosses_read_chunk_boundary(tmp_path):
    p = tmp_path / "benign.txt"; p.write_bytes(b"abcDEFGxyz")
    result = StaticExtractor([tmp_path], chunk_size=4).extract(p, patterns=[{"id": "marker", "hex": b"cDEFG".hex()}])
    assert result["pattern_ids"] == ["marker"]


@pytest.mark.parametrize("kind,code", [("missing", "NOT_FOUND"), ("large", "TOO_LARGE"),
                                       ("outside", "OUTSIDE_ROOTS"), ("directory", "NOT_REGULAR_FILE")])
def test_file_access_errors_do_not_publish_partial_hash(tmp_path, kind, code):
    root = tmp_path / "root"; root.mkdir()
    p = root / "file"
    if kind == "large": p.write_bytes(b"1234")
    if kind == "outside": p = tmp_path / "other"; p.write_bytes(b"x")
    if kind == "directory": p = root
    r = StaticExtractor([root], max_bytes=3).extract(p)
    assert r["status"] == "ERROR" and r["error_code"] == code and r["sha256"] is None


def test_denied_or_locked_file_is_structured_error(tmp_path, monkeypatch):
    p = tmp_path / "file"; p.write_bytes(b"safe")
    def deny(*a, **kw): raise PermissionError()
    monkeypatch.setattr(module.os, "open", deny)
    assert StaticExtractor([tmp_path]).extract(p)["error_code"] == "ACCESS_DENIED_OR_LOCKED"


@pytest.mark.parametrize("path", ["relative.txt", "C:/EDR/lab/bad\x00name"])
def test_invalid_paths_are_rejected_before_open(tmp_path, path):
    assert StaticExtractor([tmp_path]).extract(path)["error_code"] == "INVALID_PATH"


def test_time_budget_is_bounded(tmp_path, monkeypatch):
    p = tmp_path / "file"; p.write_bytes(b"safe")
    ticks = iter([0.0, 6.0])
    monkeypatch.setattr(module.time, "monotonic", lambda: next(ticks))
    assert StaticExtractor([tmp_path]).extract(p)["error_code"] == "TIMEOUT"


def test_changed_file_during_read_discards_features(tmp_path, monkeypatch):
    p = tmp_path / "file"; p.write_bytes(b"safe")
    real, calls = module.os.fstat, []
    def changing(fd):
        calls.append(1)
        if len(calls) == 2:
            with p.open("ab") as f: f.write(b"changed")
        return real(fd)
    monkeypatch.setattr(module.os, "fstat", changing)
    r = StaticExtractor([tmp_path]).extract(p)
    assert r["error_code"] == "FILE_CHANGED" and r["sha256"] is None


def test_expected_historical_hash_must_match(tmp_path):
    p = tmp_path / "file"; p.write_bytes(b"safe")
    ex = StaticExtractor([tmp_path])
    assert ex.extract(p, expected_sha256="0" * 64)["error_code"] == "HASH_MISMATCH"
    assert ex.extract(p, expected_sha256=hashlib.sha256(b"safe").hexdigest())["historical_identity"] == "HASH_VERIFIED"


def test_reparse_link_refused(tmp_path):
    p = tmp_path / "file"; p.write_bytes(b"safe")
    link = tmp_path / "link"
    try: link.symlink_to(p)
    except OSError: pytest.skip("Windows cần quyền tạo symlink; không bỏ qua kiểm tra reparse trong code")
    assert StaticExtractor([tmp_path]).extract(link)["error_code"] == "REPARSE_POINT"


def test_minimal_pe_header_without_executing(tmp_path):
    b = bytearray(256); b[:2] = b"MZ"; struct.pack_into("<I", b, 60, 128)
    b[128:132] = b"PE\x00\x00"; struct.pack_into("<HHI", b, 132, 0x8664, 3, 0)
    struct.pack_into("<H", b, 152, 0x20b)
    p = tmp_path / "synthetic.pe"; p.write_bytes(b)
    pe = StaticExtractor([tmp_path]).extract(p)["pe"]
    assert pe["status"] == "OK" and pe["value"]["machine"] == 0x8664
    assert pe_metadata(b"MZ")["status"] == "MALFORMED"
    assert pe_metadata(b"plain text")["status"] == "NOT_PE"


@pytest.mark.windows
def test_real_windows_exclusive_file_lock_is_reported(tmp_path):
    import win32con
    import win32file
    p = tmp_path / "locked-lab.txt"; p.write_bytes(b"safe lab file")
    handle = win32file.CreateFile(str(p), win32con.GENERIC_READ, 0, None, win32con.OPEN_EXISTING, 0, None)
    try:
        result = StaticExtractor([tmp_path]).extract(p)
        assert result["status"] == "ERROR" and result["error_code"] == "ACCESS_DENIED_OR_LOCKED"
    finally:
        handle.Close()
