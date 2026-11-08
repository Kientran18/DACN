"""Kiểm thử compare_expected trên dữ liệu SYNTHETIC mô phỏng một lần chạy lab (không phải telemetry thật)."""
import base64
import sys
from pathlib import Path

import pytest
import yaml

HERE = Path(__file__).parent
sys.path.insert(0, str(HERE))
sys.path.insert(0, str(HERE.parent / "detection"))
import compare_expected as ce  # noqa: E402
import harness  # noqa: E402
from pipeline.silver_store import SilverStore  # noqa: E402

RUN = "20260101120000"
P = f"DACN_LAB_{RUN}"
PS = "C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe"
TMP = "C:\\Users\\lab\\AppData\\Local\\Temp\\dacn_lab"
PUB = "C:\\Users\\Public\\dacn_lab"
IOC_SHA = "d" * 64


def rows(skip=()):
    b64 = base64.b64encode(f"Write-Output {P}_SC01".encode("utf-16-le")).decode()
    t = lambda s: f"2026-01-01T12:{s}+00:00"
    r = [
        {"id": "s1", "table": "process", "image_path": PS, "timestamp": t("00:01"),
         "command_line": f"powershell.exe -NoProfile -ExecutionPolicy Bypass -EncodedCommand {b64}"},
        {"id": "s2", "table": "registry", "timestamp": t("01:00"),
         "target_object": f"HKU\\S-1-5-21-1\\Software\\Microsoft\\Windows\\CurrentVersion\\Run\\{P}_SC02"},
        {"id": "s3c", "table": "file", "sysmon_event_id": 11, "timestamp": t("02:00"), "file_path": f"{TMP}\\{P}_SC03_whoami.exe"},
        {"id": "s3e", "table": "process", "timestamp": t("02:05"), "image_path": f"{TMP}\\{P}_SC03_whoami.exe"},
        {"id": "s3d", "table": "file", "sysmon_event_id": 26, "timestamp": t("02:10"), "file_path": f"{TMP}\\{P}_SC03_whoami.exe"},
        {"id": "s4", "table": "process", "timestamp": t("03:00"), "image_path": f"{TMP}\\{P}_SC04.exe", "file_sha256": IOC_SHA},
        {"id": "s6", "table": "process", "timestamp": t("04:00"), "image_path": PS,
         "command_line": f"powershell.exe -NoProfile -Command Get-Date # {P}_SC06"},
        {"id": "s7c", "table": "file", "sysmon_event_id": 11, "timestamp": t("05:00"), "file_path": f"{PUB}\\{P}_SC07_whoami.exe"},
        {"id": "s7e", "table": "process", "timestamp": t("05:05"), "image_path": f"{PUB}\\{P}_SC07_whoami.exe"},
        {"id": "late", "table": "network", "timestamp": t("30:00")},
    ]
    return [x for x in r if x["id"] not in skip]


def manifest(skip=()):
    ids = ["SC01", "SC02", "SC03", "SC04", "SC06", "SC07"]
    return {"run_id": RUN, "scenarios": [{"id": i, "marker": f"{P}_{i}", "status": "ok"} for i in ids if i not in skip]}


def build(tmp_path, skip=()):
    st = SilverStore(tmp_path / "s.duckdb")
    for t, _, row in harness.build_rows({"name": "lab", "rows": rows(skip)}):
        st._insert(t, row)
    st.close()
    ioc = tmp_path / "ioc.yaml"
    ioc.write_text(yaml.safe_dump({"version": "t", "ioc_hashes": [{"sha256": IOC_SHA, "source": "lab-test"}]}))
    return tmp_path / "s.duckdb", ioc


def by(rows_):
    return {r["scenario"]: r for r in rows_}


def test_synthetic_lab_run_all_pass_and_not_run_for_missing(tmp_path):
    db, ioc = build(tmp_path)
    res = by(ce.compare(manifest(), db, ioc=ioc))
    for sid in ("SC01", "SC02", "SC03", "SC04", "SC06", "SC07"):
        assert res[sid]["status"] == "PASS", res[sid]
    assert res["SC05"]["status"] == "NOT RUN"


def test_missing_delete_telemetry_makes_sc03_fail(tmp_path):
    db, ioc = build(tmp_path, skip=("s3d",))
    r = by(ce.compare(manifest(), db, ioc=ioc))["SC03"]
    assert r["status"] == "FAIL" and "thiếu telemetry Event 26" in r["note"]


def test_scenario_not_in_manifest_is_not_run_not_pass(tmp_path):
    db, ioc = build(tmp_path)
    assert by(ce.compare(manifest(skip=("SC02",)), db, ioc=ioc))["SC02"]["status"] == "NOT RUN"


def test_sc04_without_ioc_is_not_run(tmp_path):
    db, _ = build(tmp_path)
    assert by(ce.compare(manifest(), db))["SC04"]["status"] == "NOT RUN"


def test_sc07_invalid_if_delete_event_present(tmp_path):
    db, ioc = build(tmp_path)
    st = SilverStore(db)
    extra = {"name": "x", "rows": [{"id": "d", "table": "file", "sysmon_event_id": 26,
                                    "file_path": f"{PUB}\\{P}_SC07_whoami.exe", "timestamp": "2026-01-01T12:05:10+00:00"}]}
    for t, _, row in harness.build_rows(extra):
        row["record_id"] = 500; st._insert(t, row)
    st.close()
    assert by(ce.compare(manifest(), db, ioc=ioc))["SC07"]["status"] == "FAIL"


def test_markdown_report_has_totals(tmp_path):
    db, ioc = build(tmp_path)
    md = ce.to_markdown(ce.compare(manifest(), db, ioc=ioc), RUN)
    assert "**PASS**" in md and "không suy rộng" in md
