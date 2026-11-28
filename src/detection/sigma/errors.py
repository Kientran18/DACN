"""Mã từ chối rule Sigma (SIG-E*). Đề xuất của Software, người dùng duyệt 2026-11-28; chưa review độc lập."""
from __future__ import annotations

CODES = {
    "SIG-E001": "YAML hoặc cấu trúc rule lỗi (thiếu khóa, nhiều document, id lệch manifest, tệp không tồn tại)",
    "SIG-E002": "logsource không được hỗ trợ / không có telemetry tương ứng trong Silver",
    "SIG-E003": "field không có trong telemetry của logsource (không bịa giá trị)",
    "SIG-E004": "modifier không được hỗ trợ hoặc kết hợp modifier không hợp lệ",
    "SIG-E005": "điều kiện không được hỗ trợ (aggregation, near, timeframe, correlation, 'N of' với N != 1) hoặc tham chiếu sai",
    "SIG-E006": "keyword search (selection không có tên field) chưa được hỗ trợ",
    "SIG-E007": "status/level của rule không được phép theo cấu hình",
    "SIG-E008": "trùng id Sigma hoặc trùng rule_id DACN-SIG-<8 hex>",
    "SIG-E009": "sha256 của tệp lệch manifest (tệp đã đổi so với bản đã ghim)",
    "SIG-E010": "regex lỗi hoặc dài quá giới hạn cấu hình",
    "SIG-E011": "vượt giới hạn max_rules của cấu hình",
}


class SigmaRuleError(ValueError):
    def __init__(self, code: str, message: str):
        assert code in CODES, code
        self.code, self.message = code, message
        super().__init__(f"{code}: {message}")


class SigmaConfigError(ValueError):
    """Cấu hình config/sigma-rules.yaml sai: dừng hẳn (không nạp một phần âm thầm)."""
