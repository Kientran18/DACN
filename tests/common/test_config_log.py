import json
import pytest
from common.config import load_config, ConfigError
from common.log import get_logger


def test_defaults_use_edr_home(tmp_path, monkeypatch):
    monkeypatch.setenv("EDR_HOME", str(tmp_path))
    cfg = load_config(None)
    assert cfg.home == tmp_path
    assert cfg.silver_db == tmp_path / "silver" / "endpoint_silver.duckdb"
    assert cfg.api_host == "127.0.0.1"
    assert cfg.response_mode == "dry-run"


def test_yaml_overrides(tmp_path):
    f = tmp_path / "edr.yaml"
    f.write_text("home: %s\napi:\n  port: 9000\n" % (tmp_path / "d"), encoding="utf-8")
    cfg = load_config(f)
    assert cfg.api_port == 9000 and cfg.home == tmp_path / "d"


@pytest.mark.parametrize("text", ["api:\n  port: 99999\n", "response:\n  mode: live\n",
                                  "api:\n  host: 0.0.0.0\n", ": : bad", "unknown_key: 1\n"])
def test_invalid_config_is_rejected(tmp_path, text):
    f = tmp_path / "edr.yaml"
    f.write_text(text, encoding="utf-8")
    with pytest.raises(ConfigError):
        load_config(f)


def test_missing_file_is_error(tmp_path):
    with pytest.raises(ConfigError):
        load_config(tmp_path / "none.yaml")


def test_log_is_jsonl_and_drops_raw_command_line(tmp_path):
    p = tmp_path / "x.jsonl"
    lg = get_logger("agent", path=p, run_id="r1")
    lg.info("started", reason_code="OK", CommandLine="powershell -enc AAA", count=2)
    row = json.loads(p.read_text(encoding="utf-8").splitlines()[0])
    assert {"ts", "level", "component", "run_id", "event", "reason_code"} <= set(row)
    assert row["count"] == 2 and "CommandLine" not in row
    assert "powershell" not in p.read_text(encoding="utf-8")
