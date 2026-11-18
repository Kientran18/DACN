"""Bộ chấm điểm PE tĩnh: dùng PE synthetic (header tối thiểu, KHÔNG phải mã độc), bộ trích đặc trưng và predictor giả.
Không kiểm tra chất lượng phát hiện; không cần lightgbm/thrember."""
import hashlib
import json
import struct
from pathlib import Path

import pytest

from detection.ml.static_scorer import (INSUFFICIENT, NDIM, SCHEMA, SCORED, StaticScorer, StaticScorerConfig,
                                        classify_pe)


def make_pe(magic=0x20B, clr=False, padding=0) -> bytes:
    """PE synthetic tối thiểu: DOS header + PE signature + optional header với 16 data directory."""
    size_opt = (96 if magic == 0x10B else 112) + 16 * 8
    dos = bytearray(64)
    dos[:2] = b"MZ"
    struct.pack_into("<I", dos, 0x3C, 64)
    coff = struct.pack("<HHIIIHH", 0x8664 if magic == 0x20B else 0x14C, 0, 0, 0, 0, size_opt, 0)
    opt = bytearray(size_opt)
    struct.pack_into("<H", opt, 0, magic)
    dirs = 96 if magic == 0x10B else 112
    struct.pack_into("<I", opt, dirs, 16)
    if clr:
        struct.pack_into("<II", opt, dirs + 4 + 14 * 8, 0x2000, 0x48)
    return bytes(dos) + b"PE\0\0" + coff + bytes(opt) + b"\0" * padding


def write_model(root: Path, name: str, version="test-v0"):
    d = root / name
    d.mkdir(parents=True)
    art = d / "m.txt"
    art.write_text("model-gia", encoding="utf-8")
    (d / "model_card.json").write_text(json.dumps({
        "model_version": f"{version}-{name}", "feature_schema_version": SCHEMA, "artifact_file": "m.txt",
        "artifact_sha256": hashlib.sha256(art.read_bytes()).hexdigest()}), encoding="utf-8")


@pytest.fixture
def env(tmp_path):
    models = tmp_path / "models"
    write_model(models, "dotnet")
    write_model(models, "win64")
    allowed = tmp_path / "allowed"
    allowed.mkdir()
    return tmp_path, models, allowed


def scorer(models, allowed, score=0.25, dim=NDIM, threshold=None, max_bytes=1 << 20):
    cfg = StaticScorerConfig(allowed_dirs=[allowed], models_root=models, max_bytes=max_bytes, threshold=threshold)
    return StaticScorer(cfg, extractor=lambda b: [0.0] * dim, predictor_factory=lambda p: (lambda f: score))


def test_classify_pe():
    assert classify_pe(make_pe(0x20B)) == "win64"
    assert classify_pe(make_pe(0x10B)) == "win32"
    assert classify_pe(make_pe(0x10B, clr=True)) == "dotnet"
    assert classify_pe(make_pe(0x20B, clr=True)) == "dotnet"
    assert classify_pe(b"not a pe") is None
    assert classify_pe(b"MZ" + b"\0" * 10) is None
    assert classify_pe(make_pe()[:70]) is None


def test_cham_diem_win64_va_dotnet(env):
    _, models, allowed = env
    (allowed / "a.exe").write_bytes(make_pe(0x20B))
    (allowed / "b.dll").write_bytes(make_pe(0x10B, clr=True))
    s = scorer(models, allowed)
    r = s.score_file(allowed / "a.exe")
    assert r.status == SCORED and r.file_kind == "win64" and r.score == 0.25
    assert r.model_version == "test-v0-win64" and r.over_threshold is None and r.triggers_response is False
    assert r.sha256 == hashlib.sha256(make_pe(0x20B)).hexdigest()
    assert s.score_file(allowed / "b.dll").file_kind == "dotnet"


def test_nguong_chi_ap_dung_khi_duoc_cau_hinh(env):
    _, models, allowed = env
    (allowed / "a.exe").write_bytes(make_pe())
    assert scorer(models, allowed, score=0.9, threshold=0.5).score_file(allowed / "a.exe").over_threshold is True
    assert scorer(models, allowed, score=0.1, threshold=0.5).score_file(allowed / "a.exe").over_threshold is False


@pytest.mark.parametrize("ten,noi_dung,ly_do", [
    ("x.txt", b"khong phai pe", "NOT_PE"),
    ("w32.exe", make_pe(0x10B), "NO_MODEL_FOR_KIND"),
])
def test_insufficient_telemetry(env, ten, noi_dung, ly_do):
    _, models, allowed = env
    (allowed / ten).write_bytes(noi_dung)
    r = scorer(models, allowed).score_file(allowed / ten)
    assert r.status == INSUFFICIENT and r.reason == ly_do and r.score is None


def test_thu_muc_khong_duoc_phep_va_mac_dinh_tu_choi(env):
    tmp, models, allowed = env
    out = tmp / "outside.exe"
    out.write_bytes(make_pe())
    assert scorer(models, allowed).score_file(out).reason == "DIR_NOT_ALLOWED"
    assert scorer(models, allowed).score_file(allowed / ".." / "outside.exe").reason == "DIR_NOT_ALLOWED"
    cfg = StaticScorerConfig(models_root=models)    # allowed_dirs rỗng
    assert StaticScorer(cfg).score_file(out).reason == "DIR_NOT_ALLOWED"


def test_symlink_thoat_thu_muc_bi_chan(env):
    tmp, models, allowed = env
    out = tmp / "outside.exe"
    out.write_bytes(make_pe())
    (allowed / "link.exe").symlink_to(out)
    assert scorer(models, allowed).score_file(allowed / "link.exe").reason == "DIR_NOT_ALLOWED"


def test_khong_doc_duoc_va_qua_lon(env):
    _, models, allowed = env
    assert scorer(models, allowed).score_file(allowed / "khong-ton-tai.exe").reason == "FILE_UNREADABLE"
    assert scorer(models, allowed).score_file(allowed).reason == "FILE_UNREADABLE"   # thư mục
    (allowed / "big.exe").write_bytes(make_pe(padding=5000))
    assert scorer(models, allowed, max_bytes=1000).score_file(allowed / "big.exe").reason == "FILE_TOO_LARGE"


def test_mo_hinh_bi_tu_choi_khong_diem_gia(env):
    _, models, allowed = env
    (allowed / "a.exe").write_bytes(make_pe())
    (models / "win64" / "m.txt").write_text("bi sua", encoding="utf-8")
    r = scorer(models, allowed).score_file(allowed / "a.exe")
    assert r.status == INSUFFICIENT and r.reason == "MODEL_REJECTED" and r.score is None


def test_so_dac_trung_sai_va_diem_ngoai_khoang(env):
    _, models, allowed = env
    (allowed / "a.exe").write_bytes(make_pe())
    assert scorer(models, allowed, dim=10).score_file(allowed / "a.exe").reason == "FEATURE_DIM_MISMATCH"
    assert scorer(models, allowed, score=1.5).score_file(allowed / "a.exe").reason == "SCORING_FAILED"


def test_trich_dac_trung_loi_va_thieu_thu_vien(env):
    _, models, allowed = env
    (allowed / "a.exe").write_bytes(make_pe())
    cfg = StaticScorerConfig(allowed_dirs=[allowed], models_root=models)

    def boom(b):
        raise ValueError("pe hỏng")

    def missing(b):
        raise ImportError("thrember")

    f = lambda p: (lambda x: 0.1)
    assert StaticScorer(cfg, extractor=boom, predictor_factory=f).score_file(allowed / "a.exe").reason == "FEATURE_EXTRACTION_FAILED"
    assert StaticScorer(cfg, extractor=missing, predictor_factory=f).score_file(allowed / "a.exe").reason == "DEPENDENCY_MISSING"


def test_thieu_lightgbm_la_dependency_missing(env):
    _, models, allowed = env
    (allowed / "a.exe").write_bytes(make_pe())
    def no_lgb(p):
        raise ImportError("lightgbm")
    cfg = StaticScorerConfig(allowed_dirs=[allowed], models_root=models)
    r = StaticScorer(cfg, extractor=lambda b: [0.0] * NDIM, predictor_factory=no_lgb).score_file(allowed / "a.exe")
    assert r.reason == "DEPENDENCY_MISSING"
