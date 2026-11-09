import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "scripts"))
sys.path.insert(0, str(ROOT / "poc" / "sysmon-collector"))

import sanitize_samples as ss  # noqa: E402
import sysmon_collector_poc as poc  # noqa: E402

FAKE = ('<Event><System><EventID>1</EventID><EventRecordID>7</EventRecordID><Channel>Microsoft-Windows-Sysmon/Operational</Channel>'
        '<Computer>DESKTOP-ZZ9TEST</Computer></System><EventData><Data Name="User">DESKTOP-ZZ9TEST\\alicefake</Data>'
        '<Data Name="CurrentDirectory">C:\\Users\\alicefake\\Desktop\\</Data><Data Name="ProcessGuid">{AAAAAAAA-0000-0000-0000-000000000001}</Data>'
        '<Data Name="X">S-1-5-21-111-222-333-1001</Data></EventData></Event>')


def test_sanitize_replaces_and_keeps_structure(tmp_path):
    src, out = tmp_path / "src", tmp_path / "out"
    src.mkdir(); (src / "a.xml").write_text(FAKE, encoding="utf-8")
    rep = ss.sanitize_dir(src, out)
    s = (out / "a.xml").read_text(encoding="utf-8")
    assert rep["leaks_remaining"] == 0
    for secret in ("ZZ9TEST", "alicefake", "111-222-333"):
        assert secret.lower() not in s.lower()
    assert "{AAAAAAAA-0000-0000-0000-000000000001}" in s and "<EventRecordID>7</EventRecordID>" in s
    assert (src / "a.xml").read_text(encoding="utf-8") == FAKE          # không ghi đè nguồn


def test_shipped_sanitized_samples_are_clean_and_parse():
    d = ROOT / "tests" / "fixtures" / "sanitized"
    raw = ROOT / "references" / "samples" / "raw"
    files = sorted(d.glob("*.xml"))
    assert files, "thiếu bộ mẫu đã khử định danh"
    mapping = ss.discover([f.read_text(encoding="utf-8") for f in sorted(raw.glob("*.xml"))])
    for f in files:
        t = f.read_text(encoding="utf-8")
        assert ss.leaks(t, mapping) == 0, f.name           # không in giá trị gốc
        list(map(poc.normalize, poc.iter_events_from_file(f)))   # vẫn parse được


def test_refuses_to_overwrite_source(tmp_path):
    import pytest
    with pytest.raises(SystemExit):
        ss.main(["--src", str(tmp_path), "--out", str(tmp_path)])
