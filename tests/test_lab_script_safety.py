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


def _function_body(name):
    m = re.search(rf"function {re.escape(name)}\b.*?\n}}", CODE, re.S)
    assert m, name
    return m.group(0)


def test_lab_guard_compares_with_trailing_separator():
    """L2 (audit): so tiền tố KHÔNG kèm dấu phân cách thì ...\\Temp\\dacn_labX\\a vẫn qua guard của ...\\Temp\\dacn_lab."""
    body = _function_body("Assert-InLab")
    assert "StartsWith($LabDir" not in body and "StartsWith($PubDir" not in body, body
    assert "DirectorySeparatorChar" in body and "TrimEnd(" in body, body


def test_ioc_candidate_is_kept_for_the_comparison_step():
    """L1 (audit): README bảo dùng ioc_candidate_<runid>.yaml cho compare_expected.py --ioc, nên finally KHÔNG được xóa nó."""
    sc04 = CODE[CODE.index("Invoke-Scenario 'SC04'"):CODE.index("Invoke-Scenario 'SC05'")]
    assert "ioc_candidate_" in sc04
    assert "$Created.Add($cand)" not in CODE, "ioc_candidate bị đưa vào danh sách dọn"


def test_powershell_scripts_with_non_ascii_have_utf8_bom():
    """Windows PowerShell 5.1 đọc .ps1 KHÔNG có BOM theo codepage ANSI (cp1252): chữ tiếng Việt UTF-8 bị đọc sai, một số byte
    thành dấu nháy và script vỡ cú pháp (đo trên VM Windows 10, bước 10: 'Missing closing }'). Tệp có ký tự ngoài ASCII phải có BOM."""
    import subprocess
    root = Path(__file__).resolve().parents[1]
    files = subprocess.run(["git", "ls-files", "*.ps1", "*.psm1", "*.psd1"], cwd=root, capture_output=True, text=True,
                           check=True).stdout.split()
    bad = [f for f in files if any(c > 127 for c in (root / f).read_bytes()) and not (root / f).read_bytes().startswith(b"\xef\xbb\xbf")]
    assert files and not bad, bad
