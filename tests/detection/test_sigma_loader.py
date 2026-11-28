"""Nạp rule Sigma theo manifest + cấu hình (detection.sigma.loader). Không tải mạng; dùng tệp đã ghim trong repo."""
import hashlib
from pathlib import Path

import pytest
import yaml

from detection.loader import validate_rule, load_rules
from detection.sigma.errors import SigmaConfigError
from detection.sigma.loader import DEFAULT_MANIFEST, content_sha256, load_sigma, load_sigma_config

ON = {"enabled": True, "allow_experimental": False, "max_rules": 50, "regex_max_length": 1000}


def test_packaged_manifest_loads_all_selected_rules():
    res = load_sigma(ON)
    assert res.report["rejected"] == []
    assert len(res.rules) == 28
    for rid, r in res.rules.items():
        assert rid.startswith("DACN-SIG-") and len(rid) == 17 and len(rid) <= 32
        validate_rule(r, rid)                          # cùng schema rule của DACN (type sigma)
        assert r["type"] == "sigma" and r["detection_source"] == "SIGMA"
        assert r["response_policy"] == "alert_only" and r["validation_status"] == "synthetic_only"
        assert r["sigma"]["license"] == "DRL-1.1" and r["sigma"]["author"]
        assert r["sigma"]["source_commit"] in r["sigma"]["source_url"]
        assert rid[9:] == r["sigma"]["id"][:8]


def test_level_status_and_mitre_mapping():
    r = load_sigma(ON).rules["DACN-SIG-92626ddd"]          # Scheduled Task Creation Via Schtasks.EXE
    assert r["severity"] == "low" and r["sigma"]["level"] == "low" and r["sigma"]["status"] == "test"
    assert r["mitre_technique_ids"] == ["T1053.005"] and "SigmaHQ" in r["mitre_basis"]
    assert r["name"].startswith("[Sigma] ")


def test_disabled_config_loads_nothing_but_reports():
    res = load_sigma({**ON, "enabled": False})
    assert res.rules == {}
    assert res.report["enabled"] is False and len(res.report["loaded"]) == 28
    assert all(x["active"] is False for x in res.report["loaded"])


def test_default_config_is_disabled():
    assert load_sigma_config()["enabled"] is False


def test_missing_default_config_means_disabled_but_explicit_missing_is_error(tmp_path, monkeypatch):
    import detection.sigma.loader as L
    monkeypatch.setattr(L, "DEFAULT_CONFIG", tmp_path / "none.yaml")
    assert L.load_sigma_config()["enabled"] is False
    with pytest.raises(SigmaConfigError):
        L.load_sigma_config(tmp_path / "also-none.yaml")


def test_config_rejects_unknown_key(tmp_path):
    p = tmp_path / "s.yaml"
    p.write_text(yaml.safe_dump({**ON, "version": 1, "manifest": None, "bogus": 1}), encoding="utf-8")
    with pytest.raises(SigmaConfigError):
        load_sigma_config(p)


def test_rules_dir_merge_has_no_collision():
    base = load_rules()
    sig = load_sigma(ON).rules
    assert not set(base) & set(sig)


# -- manifest tạm để kiểm tra từ chối ------------------------------------------------------------------------------
GOOD = """title: Test {n}
id: {id}
status: {status}
description: synthetic
author: Test Author
level: {level}
tags: [attack.execution, attack.t1059.001]
logsource: {{product: windows, category: process_creation}}
detection:
    sel:
        Image|endswith: '\\\\x{n}.exe'
    condition: sel
falsepositives: [Unknown]
"""


def mk(tmp_path: Path, rules, extra_entries=None):
    base = tmp_path / "rules"
    entries = []
    for i, r in enumerate(rules):
        body = r.get("body") or GOOD.format(n=i, id=r["id"], status=r.get("status", "test"), level=r.get("level", "medium"))
        f = base / "local" / f"r{i}.yml"
        f.parent.mkdir(parents=True, exist_ok=True)
        f.write_text(body, encoding="utf-8")
        sha = content_sha256(f.read_bytes())
        entries.append({"path": f"local/r{i}.yml", "origin": "local", "sigma_id": r.get("manifest_id", r["id"]),
                        "sha256": r.get("sha256", sha), "version": 1, "license": "DRL-1.1", "enabled": True})
    m = tmp_path / "manifest.yaml"
    m.write_text(yaml.safe_dump({"source": {"repository": None, "commit": None, "license": "DRL-1.1",
                                            "license_url": "https://github.com/SigmaHQ/Detection-Rule-License"},
                                 "base_dir": "rules", "rules": entries + (extra_entries or [])}), encoding="utf-8")
    return m


def codes(res):
    return sorted(x["code"] for x in res.report["rejected"])


ID1 = "aaaaaaaa-1111-4111-8111-111111111111"
ID2 = "aaaaaaaa-2222-4222-8222-222222222222"     # cùng 8 hex đầu với ID1
ID3 = "bbbbbbbb-3333-4333-8333-333333333333"


def test_local_rule_loads(tmp_path):
    res = load_sigma(ON, manifest_path=mk(tmp_path, [{"id": ID3}]))
    assert list(res.rules) == ["DACN-SIG-bbbbbbbb"]
    assert res.rules["DACN-SIG-bbbbbbbb"]["sigma"]["origin"] == "local"
    assert res.rules["DACN-SIG-bbbbbbbb"]["sigma"]["source_url"] is None


def test_sha256_mismatch_rejected(tmp_path):
    res = load_sigma(ON, manifest_path=mk(tmp_path, [{"id": ID3, "sha256": "0" * 64}]))
    assert res.rules == {} and codes(res) == ["SIG-E009"]


def test_id_mismatch_rejected(tmp_path):
    res = load_sigma(ON, manifest_path=mk(tmp_path, [{"id": ID3, "manifest_id": ID1}]))
    assert codes(res) == ["SIG-E001"]


def test_prefix_collision_rejects_both(tmp_path):
    res = load_sigma(ON, manifest_path=mk(tmp_path, [{"id": ID1}, {"id": ID2}, {"id": ID3}]))
    assert list(res.rules) == ["DACN-SIG-bbbbbbbb"] and codes(res) == ["SIG-E008", "SIG-E008"]


def test_experimental_needs_flag_and_informational_or_deprecated_rejected(tmp_path):
    m = mk(tmp_path, [{"id": ID1, "status": "experimental"}, {"id": ID3, "level": "informational"},
                      {"id": "cccccccc-4444-4444-8444-444444444444", "status": "deprecated"}])
    assert codes(load_sigma(ON, manifest_path=m)) == ["SIG-E007", "SIG-E007", "SIG-E007"]
    res = load_sigma({**ON, "allow_experimental": True}, manifest_path=m)
    assert "DACN-SIG-aaaaaaaa" in res.rules


def test_max_rules(tmp_path):
    res = load_sigma({**ON, "max_rules": 1}, manifest_path=mk(tmp_path, [{"id": ID1}, {"id": ID3}]))
    assert len(res.rules) == 1 and codes(res) == ["SIG-E011"]


def test_unsupported_logsource_and_missing_file(tmp_path):
    body = GOOD.format(n=0, id=ID1, status="test", level="high").replace("category: process_creation", "category: image_load") \
        .replace("Image|endswith", "ImageLoaded|endswith")
    m = mk(tmp_path, [{"id": ID1, "body": body}],
           extra_entries=[{"path": "local/none.yml", "origin": "local", "sigma_id": ID3, "sha256": "0" * 64, "version": 1,
                           "license": "DRL-1.1"}])
    res = load_sigma(ON, manifest_path=m)
    assert res.rules == {} and codes(res) == ["SIG-E001", "SIG-E002"]
    rej = {x["code"]: x for x in res.report["rejected"]}
    assert rej["SIG-E002"]["title"] == "Test 0" and "image_load" in rej["SIG-E002"]["reason"]


def test_multi_document_rejected(tmp_path):
    body = GOOD.format(n=0, id=ID1, status="test", level="high") + "\n---\naction: global\n"
    assert codes(load_sigma(ON, manifest_path=mk(tmp_path, [{"id": ID1, "body": body}]))) == ["SIG-E001"]


def test_sha256_ignores_crlf_line_endings():
    assert content_sha256(b"a\r\nb\n") == content_sha256(b"a\nb\n") == hashlib.sha256(b"a\nb\n").hexdigest()


def test_manifest_sha_matches_files_in_repo():
    m = yaml.safe_load(DEFAULT_MANIFEST.read_text(encoding="utf-8"))
    base = DEFAULT_MANIFEST.parent / m["base_dir"]
    for e in m["rules"]:
        assert content_sha256((base / e["path"]).read_bytes()) == e["sha256"], e["path"]
    assert (base / "sigmahq" / "LICENSE.Detection.Rules.md").exists()
