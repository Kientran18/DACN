"""Mô hình PE tĩnh EMBER2024 (Dot_Net, Win64): nạp qua loader, kiểm tra hash, số đặc trưng và điểm trong [0,1].

Phạm vi: chỉ xác nhận file mô hình nguyên vẹn và nạp được. KHÔNG đánh giá chất lượng phát hiện của DACN.
Cần `lightgbm` (không nằm trong requirements.txt); thiếu thì test được bỏ qua."""
import hashlib
import json
from pathlib import Path

import pytest

from detection.ml.loader import ModelError, load_model

lgb = pytest.importorskip("lightgbm")
np = pytest.importorskip("numpy")

ROOT = Path(__file__).resolve().parents[2] / "models" / "ember2024"
SCHEMA = "thrember-v3-2568"
NDIM = 2568
LOAI = ["dotnet", "win64"]


def _factory(path):
    booster = lgb.Booster(model_file=str(path))
    return lambda f: float(booster.predict(np.asarray(f["x"], dtype=np.float32).reshape(1, -1))[0])


@pytest.mark.parametrize("ten", LOAI)
def test_card_report_va_artifact_khop_nhau(ten):
    d = ROOT / ten
    card = json.loads((d / "model_card.json").read_text(encoding="utf-8"))
    rep = json.loads((d / f"report_{ten}.json").read_text(encoding="utf-8"))
    sha = hashlib.sha256((d / card["artifact_file"]).read_bytes()).hexdigest()
    assert sha == card["artifact_sha256"] == rep["sha256_model"]
    assert card["status"] == "DRAFT_CHUA_DUYET"          # chưa được Cyber/Data duyệt
    assert card["feature_schema_version"] == SCHEMA
    assert "Không phải chất lượng phát hiện của DACN" in card["luu_y"]


@pytest.mark.parametrize("ten", LOAI)
def test_nap_qua_loader_va_diem_trong_0_1(ten):
    m = load_model(ROOT / ten, expected_feature_schema_version=SCHEMA, predictor_factory=_factory)
    assert lgb.Booster(model_file=str(ROOT / ten / m.card["artifact_file"])).num_feature() == NDIM
    rng = np.random.default_rng(0)
    for x in (np.zeros(NDIM), rng.random(NDIM)):        # vector tổng hợp, chỉ để kiểm tra điểm hợp lệ
        r = m.score({"x": x})
        assert 0.0 <= r.score <= 1.0 and r.triggers_response is False
        assert r.model_version == m.card["model_version"]


@pytest.mark.parametrize("ten", LOAI)
def test_tu_choi_sai_schema_va_file_bi_sua(ten, tmp_path):
    with pytest.raises(ModelError, match="feature_schema_version"):
        load_model(ROOT / ten, expected_feature_schema_version="thrember-v3-9999", predictor_factory=_factory)
    d = tmp_path / ten
    d.mkdir()
    card = json.loads((ROOT / ten / "model_card.json").read_text(encoding="utf-8"))
    (d / "model_card.json").write_text(json.dumps(card), encoding="utf-8")
    (d / card["artifact_file"]).write_bytes((ROOT / ten / card["artifact_file"]).read_bytes() + b"\n#")
    with pytest.raises(ModelError, match="hash artifact"):
        load_model(d, expected_feature_schema_version=SCHEMA, predictor_factory=_factory)
