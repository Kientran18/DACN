"""CLI `python -m detection.sigma check|list` (chỉ đọc)."""
import json

from detection.sigma.__main__ import check, main
from detection.sigma.loader import DEFAULT_MANIFEST

RULE = DEFAULT_MANIFEST.parent / "rules/sigmahq/rules/windows/process_creation/proc_creation_win_schtasks_creation.yml"


def test_check_supported_prints_manifest_entry(capsys):
    assert main(["check", str(RULE), "--origin", "sigmahq"]) == 0
    out = capsys.readouterr().out
    res = json.loads(out.split("\n# Dòng manifest")[0])
    assert res["supported"] and res["rule_id"] == "DACN-SIG-92626ddd" and res["dacn_table"] == "silver_process_events"
    assert res["manifest_entry"]["path"].startswith("sigmahq/rules/windows/process_creation/")
    assert "sha256:" in out


def test_check_rejected_has_code(tmp_path):
    p = tmp_path / "x.yml"
    p.write_text("title: x\nid: 12345678-0000-4000-8000-000000000000\nstatus: test\nlevel: high\n"
                 "logsource: {product: windows, category: image_load}\ndetection: {sel: {ImageLoaded: a}, condition: sel}\n",
                 encoding="utf-8")
    res = check(p)
    assert res["supported"] is False and res["code"] == "SIG-E002"
    assert main(["check", str(p)]) == 1


def test_list_default_config(capsys):
    assert main(["list"]) == 0
    out = json.loads(capsys.readouterr().out)
    assert out["enabled"] is False and len(out["loaded"]) == 28 and out["rejected"] == []
