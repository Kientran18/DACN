"""Runner tín hiệu ML (tắt mặc định) + nối static_scorer (EMBER2024 nháp) thành nguồn tín hiệu tùy chọn.
PE synthetic, extractor/predictor giả; KHÔNG đo chất lượng phát hiện."""
import hashlib
import sys
from datetime import datetime, timezone
from pathlib import Path

import pytest
import yaml

HERE = Path(__file__).resolve().parent
sys.path.insert(0, str(HERE))
import harness  # noqa: E402
from test_static_scorer import make_pe, write_model  # noqa: E402

from detection.ml.runner import MLConfigError, MLRunner, load_ml_config  # noqa: E402
from detection.ml.signals import MLSignalStore  # noqa: E402
from detection.ml.static_scorer import NDIM, StaticScorer, StaticScorerConfig  # noqa: E402
from detection.ml.static_signal import score_static_signals  # noqa: E402
from pipeline.silver_store import SilverStore  # noqa: E402

ROOT = Path(__file__).resolve().parents[2]
T0 = datetime(2026, 1, 1, 10, tzinfo=timezone.utc)


@pytest.fixture
def env(tmp_path):
    lab = tmp_path / "lab"
    lab.mkdir()
    good = lab / "tool.exe"
    good.write_bytes(make_pe(0x20B))
    changed = lab / "changed.exe"
    changed.write_bytes(make_pe(0x20B, padding=7))
    models = tmp_path / "models"
    write_model(models, "dotnet")
    write_model(models, "win64")
    st = SilverStore(tmp_path / "m.duckdb")
    ids = {}
    for t, rid, row in harness.build_rows({"name": "mlrun", "rows": [
            {"id": "good", "table": "process", "process_guid": "g-good", "image_path": str(good),
             "file_sha256": hashlib.sha256(good.read_bytes()).hexdigest(), "timestamp": T0.isoformat()},
            {"id": "nohash", "table": "process", "process_guid": "g-nohash", "image_path": str(good),
             "timestamp": T0.isoformat()},
            {"id": "changed", "table": "process", "process_guid": "g-changed", "image_path": str(changed),
             "file_sha256": "b" * 64, "timestamp": T0.isoformat()},
            {"id": "outside", "table": "process", "process_guid": "g-out", "image_path": "C:\\Windows\\x.exe",
             "timestamp": T0.isoformat()}]}):
        st._insert(t, row)
        ids[rid] = row["event_id"]
    return {"st": st, "lab": lab, "models": models, "ids": ids, "tmp": tmp_path}


def fake_scorer(env, score=0.8):
    return StaticScorer(StaticScorerConfig(allowed_dirs=[env["lab"]], models_root=env["models"]),
                        extractor=lambda b: [0.0] * NDIM, predictor_factory=lambda p: (lambda f: score))


def test_default_config_disables_everything():
    cfg = load_ml_config()
    assert cfg["static_pe"]["enabled"] is False and cfg["behavior"]["enabled"] is False
    assert MLRunner.from_config(cfg).enabled() == {"ML_STATIC": False, "ML_BEHAVIOR": False}


def test_config_rejects_unknown_keys(tmp_path):
    raw = yaml.safe_load((ROOT / "config/ml-detectors.yaml").read_text(encoding="utf-8"))
    raw["static_pe"]["auto_response"] = True
    p = tmp_path / "ml.yaml"
    p.write_text(yaml.safe_dump(raw), encoding="utf-8")
    with pytest.raises(MLConfigError):
        load_ml_config(p)


def test_disabled_runner_records_nothing(env):
    out = MLRunner.from_config(load_ml_config()).run(env["st"].con)
    assert out == {"ML_STATIC": "DISABLED", "ML_BEHAVIOR": "DISABLED"}
    assert MLSignalStore(env["st"].con).list() == []


def test_static_signal_scores_only_allowed_dirs_and_checks_hash(env):
    store = MLSignalStore(env["st"].con)
    out = score_static_signals(env["st"].con, fake_scorer(env), store)
    rows = {r["process_guid"]: r for r in store.list()}
    assert set(rows) == {"g-good", "g-nohash", "g-changed"}           # ngoài allowed_dirs: không chấm
    assert rows["g-good"]["status"] == "SCORED" and rows["g-good"]["score"] == 0.8
    assert rows["g-good"]["explanation"]["identity"] == "HASH_VERIFIED"
    assert rows["g-nohash"]["explanation"]["identity"] == "CURRENT_BYTES_ONLY"
    assert rows["g-changed"]["status"] == "INSUFFICIENT_TELEMETRY"
    assert rows["g-changed"]["reason"] == "HASH_MISMATCH_CURRENT_BYTES" and rows["g-changed"]["score"] is None
    assert rows["g-good"]["source_event_ids"] == [env["ids"]["good"]]
    assert out == {"scored": 2, "insufficient": 1, "skipped_existing": 0}
    assert score_static_signals(env["st"].con, fake_scorer(env), store)["skipped_existing"] == 3


def test_static_signal_dependency_missing_is_insufficient(env, monkeypatch):
    import builtins
    real = builtins.__import__

    def no_thrember(name, *a, **k):
        if name == "thrember":
            raise ImportError("thrember chưa cài")
        return real(name, *a, **k)
    monkeypatch.setattr(builtins, "__import__", no_thrember)
    sc = StaticScorer(StaticScorerConfig(allowed_dirs=[env["lab"]], models_root=env["models"]),
                      predictor_factory=lambda p: (lambda f: 0.5))
    store = MLSignalStore(env["st"].con)
    score_static_signals(env["st"].con, sc, store)
    assert {r["reason"] for r in store.list()} == {"DEPENDENCY_MISSING"}
    assert all(r["score"] is None for r in store.list())


def test_runner_static_enabled_uses_injected_scorer(env):
    cfg = load_ml_config()
    cfg["static_pe"].update(enabled=True, allowed_dirs=[str(env["lab"])], models_root=str(env["models"]))
    r = MLRunner.from_config(cfg, static_scorer=fake_scorer(env))
    out = r.run(env["st"].con)
    assert out["ML_STATIC"]["scored"] == 2 and out["ML_BEHAVIOR"] == "DISABLED"


def test_runner_behavior_bad_model_reports_error_without_raising(env):
    cfg = load_ml_config()
    cfg["behavior"].update(enabled=True, model_dir=str(env["tmp"] / "khong-co"))
    out = MLRunner.from_config(cfg).run(env["st"].con)
    assert out["ML_BEHAVIOR"].startswith("ERROR:")
    assert MLSignalStore(env["st"].con).list() == []


def test_core_cycle_runs_ml_runner_and_survives_its_failure(env, tmp_path):
    from core.service import CoreService

    class Boom:
        def enabled(self):
            return {"ML_STATIC": True, "ML_BEHAVIOR": False}

        def run(self, con):
            raise RuntimeError("ml hỏng")

    svc = CoreService(env["st"], tmp_path / "bronze", tmp_path / "metrics.jsonl", ml_runner=Boom())
    out = svc.cycle()
    assert "alerts_created" in out and out["ml"].startswith("ERROR")
    assert svc.status()["ml"]["last_error"]["type"] == "RuntimeError"

    class Ok(Boom):
        def run(self, con):
            return {"ML_STATIC": {"scored": 0}, "ML_BEHAVIOR": "DISABLED"}
    svc2 = CoreService(env["st"], tmp_path / "bronze", tmp_path / "metrics.jsonl", ml_runner=Ok())
    assert svc2.cycle()["ml"] == {"ML_STATIC": {"scored": 0}, "ML_BEHAVIOR": "DISABLED"}
    assert svc2.status()["ml"]["enabled"] == {"ML_STATIC": True, "ML_BEHAVIOR": False}


def test_core_without_runner_has_ml_disabled(env, tmp_path):
    from core.service import CoreService
    svc = CoreService(env["st"], tmp_path / "bronze", tmp_path / "metrics.jsonl")
    assert "ml" not in svc.cycle()
    assert svc.status()["ml"]["enabled"] == {"ML_STATIC": False, "ML_BEHAVIOR": False}
