"""Kiểm tra tĩnh script lab (PH5-T02): không có hành động bị cấm; có cơ chế an toàn bắt buộc.
Đây KHÔNG thay cho việc đọc script và chạy -WhatIf trên VM (chưa chạy PowerShell thật)."""
import re
from pathlib import Path

SCRIPT = (Path(__file__).resolve().parents[1] / "scripts" / "lab" / "dacn_lab_scenarios.ps1").read_text(encoding="utf-8")
CODE = "\n".join(l for l in SCRIPT.splitlines() if not l.strip().startswith("#"))

BANNED = [r"Invoke-WebRequest", r"Invoke-RestMethod", r"WebClient", r"Start-BitsTransfer", r"curl\b", r"wget\b",
          r"Set-MpPreference", r"Add-MpPreference", r"Disable-", r"Stop-Service", r"Set-Service", r"(?<![A-Za-z])sc\.exe",
          r"Restart-Computer", r"Stop-Computer", r"shutdown", r"Format-Volume", r"Remove-Item\s+[^\n]*\*",
          r"-Recurse", r"New-Service", r"schtasks", r"reg\s+add", r"netsh", r"Sysmon(64)?\.exe"]


def test_no_banned_actions():
    hits = [p for p in BANNED if re.search(p, CODE, re.I)]
    assert not hits, hits


def test_required_safety_mechanisms_present():
    assert "SupportsShouldProcess = $true" in SCRIPT
    assert "ShouldProcess(" in SCRIPT
    assert "function Assert-InLab" in SCRIPT
    assert "DACN_LAB_" in SCRIPT
    assert "-LiteralPath" in SCRIPT


def test_all_removals_go_through_lab_guard():
    for line in CODE.splitlines():
        if "Remove-Item " in line and "Remove-ItemProperty" not in line:
            assert "-LiteralPath $full" in line, line


def test_registry_writes_limited_to_run_prefix_and_test_key():
    assert "HKCU:\\Software\\Microsoft\\Windows\\CurrentVersion\\Run" in SCRIPT
    assert "HKCU:\\Software\\EDR_PoC" in SCRIPT
    assert "HKLM" not in CODE
