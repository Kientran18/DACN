"""Tải cấu hình EDR (PH1-T09). Mặc định an toàn: bind 127.0.0.1.
Chế độ response KHÔNG nằm ở đây: chỉ config/response-policy.yaml (mode + execute_unlocked) quyết định."""
from __future__ import annotations

import os
from dataclasses import dataclass
from pathlib import Path
from typing import Optional, Tuple

import yaml


class ConfigError(ValueError):
    pass


_ALLOWED = {"home", "api", "agent"}
_ALLOWED_API = {"host", "port", "tokens_file"}
_ALLOWED_AGENT = {"channels"}
_ALLOWED_CHANNEL = {"name", "enabled", "xpath"}
# Kênh mặc định khi không cấu hình agent.channels: chỉ Sysmon (giữ hành vi trước 2026-11-28). Tên kênh được agent
# kiểm tra với poc/sysmon-collector/windows_channels.py lúc khởi động (common.config không import module trần đó
# vì api.auth chạy chỉ với PYTHONPATH=src).
DEFAULT_CHANNEL = "Microsoft-Windows-Sysmon/Operational"


@dataclass(frozen=True)
class ChannelConfig:
    name: str
    enabled: bool = True
    xpath: Optional[str] = None      # None = bộ lọc mặc định của kênh (windows_channels.DEFAULT_XPATH)


@dataclass(frozen=True)
class Config:
    home: Path
    api_host: str = "127.0.0.1"
    api_port: int = 8765
    api_tokens_file: Optional[Path] = None
    agent_channels: Tuple[ChannelConfig, ...] = (ChannelConfig(DEFAULT_CHANNEL),)

    @property
    def silver_db(self) -> Path:
        return self.home / "silver" / "endpoint_silver.duckdb"

    @property
    def bronze_dir(self) -> Path:
        return self.home / "bronze"

    @property
    def tokens_path(self) -> Path:
        return self.api_tokens_file or (self.home / "api_tokens.json")

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
    for key, allowed in ((None, _ALLOWED), ("api", _ALLOWED_API)):
        section = data if key is None else (data.get(key) or {})
        if not isinstance(section, dict):
            raise ConfigError(f"CFG-003 mục '{key}' phải là mapping")
        extra = set(section) - allowed
        if extra:
            raise ConfigError(f"CFG-003 khóa không hỗ trợ: {sorted(extra)}")
    api = data.get("api") or {}
    host = api.get("host", "127.0.0.1")
    port = api.get("port", 8765)
    if host not in ("127.0.0.1", "localhost", "::1"):
        raise ConfigError("CFG-004 api.host chỉ được là loopback (local-first)")
    if not isinstance(port, int) or isinstance(port, bool) or not 1 <= port <= 65535:
        raise ConfigError("CFG-005 api.port phải nằm trong 1..65535")
    home = Path(data["home"]) if data.get("home") else _default_home()
    tf = api.get("tokens_file")
    return Config(home=home, api_host=host, api_port=port,
                  api_tokens_file=Path(tf) if tf else None,
                  agent_channels=_parse_channels(data.get("agent") or {}))


def _parse_channels(agent: dict) -> Tuple[ChannelConfig, ...]:
    """agent.channels: danh sách {name, enabled (mặc định true), xpath (tùy chọn)}. Kênh mới mặc định tắt là do
    tệp cấu hình mẫu ghi enabled: false (D10); thiếu cả mục thì chỉ đọc Sysmon."""
    extra = set(agent) - _ALLOWED_AGENT
    if extra:
        raise ConfigError(f"CFG-003 khóa không hỗ trợ trong agent: {sorted(extra)}")
    if "channels" not in agent:
        return (ChannelConfig(DEFAULT_CHANNEL),)
    items = agent["channels"]
    if not isinstance(items, list) or not items:
        raise ConfigError("CFG-006 agent.channels phải là danh sách khác rỗng")
    out, seen = [], set()
    for it in items:
        if not isinstance(it, dict):
            raise ConfigError("CFG-006 mỗi phần tử agent.channels phải là mapping")
        extra = set(it) - _ALLOWED_CHANNEL
        if extra:
            raise ConfigError(f"CFG-003 khóa không hỗ trợ trong agent.channels: {sorted(extra)}")
        name, enabled, xpath = it.get("name"), it.get("enabled", True), it.get("xpath")
        if not isinstance(name, str) or not name.strip():
            raise ConfigError("CFG-006 agent.channels[].name phải là chuỗi khác rỗng")
        if not isinstance(enabled, bool):
            raise ConfigError("CFG-006 agent.channels[].enabled phải là true/false")
        if xpath is not None and (not isinstance(xpath, str) or not xpath.strip()):
            raise ConfigError("CFG-006 agent.channels[].xpath phải là chuỗi khác rỗng")
        key = name.strip().casefold()
        if key in seen:
            raise ConfigError(f"CFG-006 kênh lặp lại trong agent.channels: {name}")
        seen.add(key)
        out.append(ChannelConfig(name.strip(), enabled, xpath))
    if not any(c.enabled for c in out):
        raise ConfigError("CFG-006 agent.channels cần ít nhất một kênh enabled: true")
    return tuple(out)
