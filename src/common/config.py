"""Tải cấu hình EDR (PH1-T09). Mặc định an toàn: bind 127.0.0.1, response dry-run."""
from __future__ import annotations

import os
from dataclasses import dataclass
from pathlib import Path
from typing import Optional

import yaml


class ConfigError(ValueError):
    pass


_ALLOWED = {"home", "api", "response"}
_ALLOWED_API = {"host", "port"}
_ALLOWED_RESP = {"mode"}


@dataclass(frozen=True)
class Config:
    home: Path
    api_host: str = "127.0.0.1"
    api_port: int = 8765
    response_mode: str = "dry-run"

    @property
    def silver_db(self) -> Path:
        return self.home / "silver" / "endpoint_silver.duckdb"

    @property
    def bronze_dir(self) -> Path:
        return self.home / "bronze"

    @property
    def log_dir(self) -> Path:
        return self.home / "logs"


def _default_home() -> Path:
    return Path(os.environ.get("EDR_HOME") or (Path.home() / ".edr"))


def load_config(path: Optional[Path]) -> Config:
    data: dict = {}
    if path is not None:
        path = Path(path)
        if not path.is_file():
            raise ConfigError(f"CFG-001 không tìm thấy tệp cấu hình: {path.name}")
        try:
            data = yaml.safe_load(path.read_text(encoding="utf-8")) or {}
        except yaml.YAMLError as exc:
            raise ConfigError("CFG-002 YAML không hợp lệ") from exc
    if not isinstance(data, dict):
        raise ConfigError("CFG-002 cấu hình phải là mapping")
    for key, allowed in ((None, _ALLOWED), ("api", _ALLOWED_API), ("response", _ALLOWED_RESP)):
        section = data if key is None else (data.get(key) or {})
        if not isinstance(section, dict):
            raise ConfigError(f"CFG-003 mục '{key}' phải là mapping")
        extra = set(section) - allowed
        if extra:
            raise ConfigError(f"CFG-003 khóa không hỗ trợ: {sorted(extra)}")
    api = data.get("api") or {}
    host = api.get("host", "127.0.0.1")
    port = api.get("port", 8765)
    mode = (data.get("response") or {}).get("mode", "dry-run")
    if host not in ("127.0.0.1", "localhost", "::1"):
        raise ConfigError("CFG-004 api.host chỉ được là loopback (local-first)")
    if not isinstance(port, int) or isinstance(port, bool) or not 1 <= port <= 65535:
        raise ConfigError("CFG-005 api.port phải nằm trong 1..65535")
    if mode != "dry-run":
        raise ConfigError("CFG-006 response.mode hiện chỉ hỗ trợ 'dry-run' (thực thi thật cần phê duyệt riêng)")
    home = Path(data["home"]) if data.get("home") else _default_home()
    return Config(home=home, api_host=host, api_port=port, response_mode=mode)
