"""Bảng kênh Windows Event Log mà DACN hỗ trợ (dùng chung collector, adapter, pipeline).

Căn cứ: docs/architecture/w8/telemetry-defender-powershell-proposal.md, người dùng duyệt D1/D4/D9 ngày 2026-11-26
(thay cho Data/Cyber; chưa có review độc lập). Module trần (import bằng tên), giống bronze_contract.

- `source` và `schema_version` của bản ghi Bronze suy ra từ `channel` (D1): Sysmon giữ bronze-event/1.0,
  Windows Defender và PowerShell dùng bronze-event/1.1.
- Tên event type của kênh mới tra theo (channel, event_id) (D4), KHÔNG thêm vào bảng Sysmon của collector/validator
  (tránh trùng số và tránh tạo thêm "bộ tên" thứ ba; Q-X3 vẫn mở cho Sysmon).
"""
from __future__ import annotations

from typing import Optional, Tuple

SYSMON_CHANNEL = "Microsoft-Windows-Sysmon/Operational"
DEFENDER_CHANNEL = "Microsoft-Windows-Windows Defender/Operational"
POWERSHELL_CHANNEL = "Microsoft-Windows-PowerShell/Operational"

SCHEMA_V10 = "bronze-event/1.0"
SCHEMA_V11 = "bronze-event/1.1"

# channel -> (source, schema_version)
CHANNEL_SOURCES = {
    SYSMON_CHANNEL: ("SYSMON", SCHEMA_V10),
    DEFENDER_CHANNEL: ("WINDOWS_DEFENDER", SCHEMA_V11),
    POWERSHELL_CHANNEL: ("POWERSHELL", SCHEMA_V11),
}

# Event ID được hỗ trợ của từng kênh mới (D9: thu 1116/1117 và 5001/5007/5013; PowerShell chỉ 4104).
SUPPORTED_EVENT_IDS = {
    DEFENDER_CHANNEL: (1116, 1117, 5001, 5007, 5013),
    POWERSHELL_CHANNEL: (4104,),
}

# (channel, event_id) -> event_type (D4)
EVENT_TYPES = {
    (DEFENDER_CHANNEL, 1116): "DEFENDER_MALWARE_DETECTED",
    (DEFENDER_CHANNEL, 1117): "DEFENDER_MALWARE_ACTION",
    (DEFENDER_CHANNEL, 5001): "DEFENDER_RTP_DISABLED",
    (DEFENDER_CHANNEL, 5007): "DEFENDER_CONFIG_CHANGED",
    (DEFENDER_CHANNEL, 5013): "DEFENDER_TAMPER_BLOCKED",
    (POWERSHELL_CHANNEL, 4104): "POWERSHELL_SCRIPT_BLOCK",
}

# Bộ lọc XPath mặc định cho agent live: giảm tải kênh ồn (PowerShell/Operational còn 4100, 40961...; Defender có
# nhiều sự kiện cập nhật chữ ký). Sysmon đọc toàn bộ như trước.
DEFAULT_XPATH = {
    SYSMON_CHANNEL: "*",
    DEFENDER_CHANNEL: "*[System[(EventID=1116 or EventID=1117 or EventID=5001 or EventID=5007 or EventID=5013)]]",
    POWERSHELL_CHANNEL: "*[System[(EventID=4104)]]",
}

_BY_FOLD = {c.casefold(): c for c in CHANNEL_SOURCES}


def canonical_channel(channel: Optional[str]) -> Optional[str]:
    """Tên kênh chuẩn nếu được hỗ trợ (so sánh không phân biệt hoa thường như Windows), ngược lại None."""
    return _BY_FOLD.get((channel or "").strip().casefold())


def source_for_channel(channel: Optional[str]) -> Optional[Tuple[str, str]]:
    """(source, schema_version) của kênh, hoặc None nếu kênh không được hỗ trợ."""
    c = canonical_channel(channel)
    return CHANNEL_SOURCES[c] if c else None


def is_sysmon(channel: Optional[str]) -> bool:
    return canonical_channel(channel) == SYSMON_CHANNEL


def event_type_for(channel: Optional[str], event_id: int) -> Optional[str]:
    """Event type của kênh mới; None nếu (kênh, ID) chưa được hỗ trợ. Không dùng cho Sysmon."""
    c = canonical_channel(channel)
    return EVENT_TYPES.get((c, event_id)) if c else None


def channel_slug(channel: str) -> str:
    """Tên an toàn cho tệp: chữ thường, ký tự không phải chữ/số thành '_' (dùng cho checkpoint/segment)."""
    out = "".join(ch if ch.isalnum() else "_" for ch in channel.strip().lower())
    return "_".join(p for p in out.split("_") if p)
