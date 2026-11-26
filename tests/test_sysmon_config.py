"""Kiểm tra tĩnh cấu hình Sysmon của repo (không chạy Sysmon). Khóa các mục registry mà rule và bộ đánh giá Atomic cần."""
import xml.etree.ElementTree as ET
from pathlib import Path

CONFIG = Path(__file__).resolve().parents[1] / "poc" / "sysmon-collector" / "configs" / "sysmon-config.xml"


def _registry_includes():
    root = ET.parse(CONFIG).getroot()
    out = []
    for ev in root.iter("RegistryEvent"):
        if ev.get("onmatch") == "include":
            out += [(t.get("condition"), t.text) for t in ev.findall("TargetObject")]
    return out


def test_config_is_well_formed_and_keeps_schema():
    root = ET.parse(CONFIG).getroot()
    assert root.tag == "Sysmon" and root.get("schemaversion") == "4.90"
    assert "SHA256" in root.findtext("HashAlgorithms")


def test_registry_include_covers_run_keys_used_by_det003():
    inc = _registry_includes()
    assert ("contains", "\\CurrentVersion\\Run") in inc          # Run, RunOnce, RunOnceEx


def test_registry_include_covers_policies_explorer_run():
    """A07 (Atomic T1547.001 #12, đo 2026-11-26): không có Event 13 vì cấu hình không include khóa này."""
    assert ("contains", "\\Policies\\Explorer\\Run") in _registry_includes()
