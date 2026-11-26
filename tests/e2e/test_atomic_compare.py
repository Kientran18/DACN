"""Kiểm thử atomic_compare trên dữ liệu SYNTHETIC (Silver giả + log Invoke-AtomicRedTeam giả).

Không phải telemetry thật và không phải kết quả chạy Atomic Red Team. Mục tiêu: công cụ gán đúng
cây tiến trình của từng lần chạy, phân loại TP/FN/FP/TN đúng theo kỳ vọng, và KHÔNG làm lộ định danh.
"""
import json
import sys
from pathlib import Path

import pytest
import yaml

HERE = Path(__file__).parent
sys.path.insert(0, str(HERE))
sys.path.insert(0, str(HERE.parent / "detection"))
import atomic_compare as ac  # noqa: E402
import harness  # noqa: E402
from pipeline.silver_store import SilverStore  # noqa: E402

PS = "C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe"
CMD = "C:\\Windows\\System32\\cmd.exe"
REG = "C:\\Windows\\System32\\reg.exe"
SCHT = "C:\\Windows\\System32\\schtasks.exe"
G_RUNNER = "aaaaaaaa-0000-0000-0000-000000000000"     # powershell.exe của người vận hành (gọi Invoke-AtomicTest)
SECRET_HOST = "LABHOST"                               # hostname trong harness: không được xuất hiện trong báo cáo
SECRET_USER = "secretoperator"


def g(n):
    return f"bbbbbbbb-0000-0000-0000-{n:012d}"


def t(mmss):
    return f"2026-01-01T10:{mmss}+00:00"


# Bảng kỳ vọng nhỏ, độc lập với tệp thật (tệp thật được kiểm ở test riêng)
EXPECTED = {
    "version": 1,
    "tests": [
        {"id": "A01", "technique": "T1059.001", "guid": "guid-a01", "name": "enc", "category": "TP_EXPECTED",
         "target_rules": ["DACN-DET-001"], "expect_telemetry": [1]},
        {"id": "A04", "technique": "T1547.001", "guid": "guid-a04", "name": "run key", "category": "TP_EXPECTED",
         "target_rules": ["DACN-DET-003"], "expect_telemetry": [1, 13]},
        {"id": "A06", "technique": "T1547.001", "guid": "guid-a06", "name": "winlogon userinit", "category": "FN_NO_RULE",
         "target_rules": ["DACN-DET-003"], "expect_telemetry": [1, 13]},
        {"id": "A08", "technique": "T1053.005", "guid": "guid-a08", "name": "schtasks", "category": "TP_EXPECTED",
         "target_rules": ["DACN-DET-004"], "expect_telemetry": [1]},
        {"id": "C01", "technique": "T1082", "guid": "guid-c01", "name": "systeminfo", "category": "CONTROL",
         "target_rules": [], "expect_telemetry": [1]},
        {"id": "C02", "technique": "T1059.003", "guid": "guid-c02", "name": "echo", "category": "CONTROL",
         "target_rules": [], "expect_telemetry": [1]},
        {"id": "A11", "technique": "T1070.004", "guid": "guid-a11", "name": "del", "category": "FN_NO_RULE",
         "target_rules": [], "expect_telemetry": [1, 26]},
    ],
}


def silver_rows():
    """Mỗi lần chạy: tiến trình gốc (pid do Invoke-AtomicTest ghi) + con cháu. Thêm nhiễu cùng pid ngoài cửa sổ."""
    r = [
        # A01 lúc 10:00:10, pid 1001: cmd.exe -> powershell.exe -e ... (DET-001 phải MATCH trên tiến trình con)
        {"id": "a01s", "table": "process", "timestamp": t("00:10"), "pid": 1001, "process_guid": g(1),
         "parent_guid": G_RUNNER, "image_path": CMD, "command_line": "cmd.exe /c powershell.exe -e  JgAgAA=="},
        {"id": "a01c", "table": "process", "timestamp": t("00:11"), "pid": 1002, "process_guid": g(2),
         "parent_guid": g(1), "image_path": PS, "command_line": "powershell.exe -e  JgAgAA=="},
        # A04 lúc 10:01:00, pid 2001: cmd.exe -> reg.exe ghi Run key (Event 13 thuộc reg.exe)
        {"id": "a04s", "table": "process", "timestamp": t("01:00"), "pid": 2001, "process_guid": g(3),
         "parent_guid": G_RUNNER, "image_path": CMD, "command_line": "cmd.exe /c REG ADD HKCU\\...\\Run"},
        {"id": "a04c", "table": "process", "timestamp": t("01:01"), "pid": 2002, "process_guid": g(4),
         "parent_guid": g(3), "image_path": REG, "command_line": "REG ADD ..."},
        {"id": "a04r", "table": "registry", "timestamp": t("01:01"), "pid": 2002, "process_guid": g(4),
         "image_path": REG,
         "target_object": "HKU\\S-1-5-21-1\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Run\\Atomic Red Team"},
        # A06 lúc 10:02:00: Winlogon\Userinit - Event 13 có nhưng DET-003 (v3) không khớp
        {"id": "a06s", "table": "process", "timestamp": t("02:00"), "pid": 3001, "process_guid": g(5),
         "parent_guid": G_RUNNER, "image_path": CMD, "command_line": "cmd.exe /c REG ADD HKLM\\...\\Winlogon"},
        {"id": "a06r", "table": "registry", "timestamp": t("02:01"), "pid": 3001, "process_guid": g(5),
         "image_path": CMD,
         "target_object": "HKLM\\SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\Winlogon\\Userinit"},
        # A08 lúc 10:03:00: schtasks /Create -> DET-004
        {"id": "a08s", "table": "process", "timestamp": t("03:00"), "pid": 4001, "process_guid": g(6),
         "parent_guid": G_RUNNER, "image_path": CMD, "command_line": "cmd.exe /c SCHTASKS /Create /SC ONCE /TN spawn"},
        # schtasks là CHÁU của tiến trình gốc (cmd -> cmd -> schtasks): kiểm duyệt cây nhiều tầng
        {"id": "a08m", "table": "process", "timestamp": t("03:01"), "pid": 4003, "process_guid": g(11),
         "parent_guid": g(6), "image_path": CMD, "command_line": "cmd /c SCHTASKS /Create /SC ONCE /TN spawn"},
        {"id": "a08c", "table": "process", "timestamp": t("03:01"), "pid": 4002, "process_guid": g(7),
         "parent_guid": g(11), "image_path": SCHT, "command_line": "SCHTASKS /Create /SC ONCE /TN spawn"},
        # C01 lúc 10:04:00: lành tính
        {"id": "c01s", "table": "process", "timestamp": t("04:00"), "pid": 5001, "process_guid": g(8),
         "parent_guid": G_RUNNER, "image_path": CMD, "command_line": "cmd.exe /c systeminfo"},
        # C02 lúc 10:05:00 nhưng có thêm một powershell -enc con (giả lập FP để kiểm phân loại)
        {"id": "c02s", "table": "process", "timestamp": t("05:00"), "pid": 6001, "process_guid": g(9),
         "parent_guid": G_RUNNER, "image_path": CMD, "command_line": "cmd.exe /c echo hi"},
        {"id": "c02c", "table": "process", "timestamp": t("05:01"), "pid": 6002, "process_guid": g(10),
         "parent_guid": g(9), "image_path": PS, "command_line": "powershell.exe -enc AAAA"},
        # Nhiễu: một tiến trình KHÁC dùng lại pid 1001 lúc 10:30 với lệnh khớp DET-001 - không được gán cho A01
        {"id": "noise", "table": "process", "timestamp": t("30:00"), "pid": 1001, "process_guid": g(99),
         "parent_guid": G_RUNNER, "image_path": PS, "command_line": "powershell.exe -encodedcommand ZZZZ"},
        # Nhiễu: tiến trình -enc cùng thời điểm A04 nhưng KHÔNG thuộc cây tiến trình A04
        {"id": "noise2", "table": "process", "timestamp": t("01:00"), "pid": 7777, "process_guid": g(98),
         "parent_guid": G_RUNNER, "image_path": PS, "command_line": "powershell.exe -enc YYYY"},
    ]
    return r


def build_silver(tmp_path, rows=None):
    st = SilverStore(tmp_path / "s.duckdb")
    for table, _, row in harness.build_rows({"name": "art", "rows": rows or silver_rows()}):
        st._insert(table, row)
    st.close()
    return tmp_path / "s.duckdb"


def proc(technique, guid, order, start, stop, pid, exit_code=0, stdout="", stderr=""):
    out = [{"content": stdout, "level": "STDOUT", "type": "console"}]
    if stderr:
        out.append({"content": stderr, "level": "STDERR", "type": "console"})
    return {"mitre-technique-id": technique, "procedure-name": "x", "procedure-id": {"type": "guid", "id": guid},
            "procedure-description": "d", "order": order,
            "steps": [{"order": 1, "time-start": start, "time-stop": stop, "executor": "command_prompt",
                       "command": f"echo {SECRET_USER}", "process-id": pid, "exit-code": exit_code,
                       "is-timeout": False, "output": out}]}


def attire(procedures):
    return {"attire-version": "1.1",
            "execution-data": {"execution-source": "Invoke-Atomicredteam", "execution-id": "eA==",
                               "execution-category": {"name": "Atomic Red Team", "abbreviation": "ART"},
                               "execution-command": "Invoke-AtomicTest ...",
                               "target": {"user": f"{SECRET_HOST}\\{SECRET_USER}", "host": SECRET_HOST,
                                          "ip": "10.9.8.7", "path": f"C:\\Users\\{SECRET_USER}\\bin"},
                               "time-generated": "2026-01-01T11:00:00.000Z"},
            "procedures": procedures}


def write_logs(tmp_path, procedures, name="art.json"):
    d = tmp_path / "logs"
    d.mkdir(exist_ok=True)
    (d / name).write_text(json.dumps(attire(procedures)), encoding="utf-8")
    return d


def default_procs():
    return [
        proc("T1059.001", "guid-a01", 17, "2026-01-01T10:00:09.000Z", "2026-01-01T10:00:13.000Z", 1001),
        proc("T1547.001", "guid-a04", 1, "+2026-01-01T10:00:59.000Z", "2026-01-01T10:01:02.000Z", 2001),
        proc("T1547.001", "guid-a06", 2, "2026-01-01T10:01:59.000Z", "2026-01-01T10:02:02.000Z", 3001),
        proc("T1053.005", "guid-a08", 2, "2026-01-01T10:02:59.000Z", "2026-01-01T10:03:02.000Z", 4001),
        proc("T1082", "guid-c01", 1, "2026-01-01T10:03:59.000Z", "2026-01-01T10:04:05.000Z", 5001,
             stdout=f"Host Name: {SECRET_HOST}"),
        proc("T1059.003", "guid-c02", 2, "2026-01-01T10:04:59.000Z", "2026-01-01T10:05:03.000Z", 6001),
    ]


def run(tmp_path, procs=None, rows=None):
    db = build_silver(tmp_path, rows)
    logs = write_logs(tmp_path, procs if procs is not None else default_procs())
    return ac.compare(ac.load_runs([logs]), db, EXPECTED)


def by_id(report):
    return {r["id"]: r for r in report["runs"]}


# ---------- đọc log ----------

def test_load_attire_extracts_runs_without_identity(tmp_path):
    logs = write_logs(tmp_path, default_procs())
    runs = ac.load_runs([logs])
    assert len(runs) == 6
    a04 = [r for r in runs if r["guid"] == "guid-a04"][0]
    assert a04["pid"] == 2001 and a04["exit_code"] == 0
    assert a04["start"].isoformat() == "2026-01-01T10:00:59+00:00"     # dấu '+' đầu chuỗi của -UFormat được bỏ
    blob = json.dumps(runs, default=str)
    for secret in (SECRET_HOST, SECRET_USER, "10.9.8.7"):
        assert secret not in blob, f"{secret} lọt vào dữ liệu đã đọc"


def test_load_default_csv_logger(tmp_path):
    csv = tmp_path / "Invoke-AtomicTest-ExecutionLog.csv"
    csv.write_text(
        '"Execution Time (UTC)","Execution Time (Local)","Technique","Test Number","Test Name","Hostname",'
        '"IP Address","Username","GUID","ProcessId","ExitCode"\n'
        f'"2026-01-01T10:00:59Z","2026-01-01T17:00:59Z","T1547.001","1","Reg Key Run","{SECRET_HOST}",'
        f'"10.9.8.7","{SECRET_USER}","guid-a04","2001","0"\n', encoding="utf-8")
    runs = ac.load_runs([csv])
    assert len(runs) == 1 and runs[0]["pid"] == 2001 and runs[0]["stop"] is None
    assert SECRET_HOST not in json.dumps(runs, default=str)


def test_defender_hint_from_stderr_is_flag_only(tmp_path):
    procs = [proc("T1059.001", "guid-a01", 17, "2026-01-01T10:00:09.000Z", "2026-01-01T10:00:13.000Z", 1001,
                  exit_code=1, stderr="This script contains malicious content and has been blocked by your "
                                      "antivirus software.")]
    runs = ac.load_runs([write_logs(tmp_path, procs)])
    assert runs[0]["defender_hint"] is True
    assert "malicious" not in json.dumps(runs, default=str)            # chỉ giữ cờ, không giữ nội dung stdout/stderr


def test_defender_hint_false_for_ordinary_output(tmp_path):
    runs = {r["guid"]: r for r in ac.load_runs([write_logs(tmp_path, default_procs())])}
    assert runs["guid-c01"]["defender_hint"] is False                  # stdout bình thường không bật cờ


# ---------- phân loại ----------

def test_tp_fn_fp_tn_classification(tmp_path):
    r = by_id(run(tmp_path))
    assert r["A01"]["verdict"] == "TP" and "DACN-DET-001" in r["A01"]["matched_rules"]
    assert r["A04"]["verdict"] == "TP" and r["A04"]["matched_rules"] == ["DACN-DET-003"]
    assert r["A06"]["verdict"] == "FN_DU_KIEN"                          # khoảng trống rule đã biết
    assert r["A08"]["verdict"] == "TP" and r["A08"]["matched_rules"] == ["DACN-DET-004"]
    assert r["C01"]["verdict"] == "TN"
    assert r["C02"]["verdict"] == "FP" and r["C02"]["matched_rules"] == ["DACN-DET-001"]


def test_pid_reuse_outside_window_is_not_attributed(tmp_path):
    """Tiến trình pid 1001 lúc 10:30 khớp DET-001 nhưng nằm ngoài cửa sổ của A01: không được tính cho A01."""
    rows = [x for x in silver_rows() if x["id"] not in ("a01s", "a01c")]
    r = by_id(run(tmp_path, rows=rows))
    assert r["A01"]["verdict"] == "KHONG_THAY_TIEN_TRINH_GOC"


def test_unrelated_concurrent_process_not_counted(tmp_path):
    """noise2 (-enc) chạy cùng giây với A04 nhưng không thuộc cây tiến trình A04."""
    r = by_id(run(tmp_path))
    assert "DACN-DET-001" not in r["A04"]["matched_rules"]


def test_expected_fn_that_matches_is_flagged_for_review(tmp_path):
    rows = silver_rows() + [{"id": "a06x", "table": "registry", "timestamp": t("02:01"), "pid": 3001,
                             "process_guid": g(5), "image_path": CMD,
                             "target_object": "HKU\\S\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Run\\x"}]
    r = by_id(run(tmp_path, rows=rows))
    assert r["A06"]["verdict"] == "MATCH_NGOAI_DU_KIEN"


def test_telemetry_seen_and_missing(tmp_path):
    r = by_id(run(tmp_path))
    assert r["A04"]["telemetry"] == [1, 13] and r["A04"]["missing_telemetry"] == []
    assert r["A08"]["telemetry"] == [1] and r["A08"]["lineage_size"] == 3


def test_exec_failure_is_reported_not_hidden(tmp_path):
    procs = default_procs()
    procs[3] = proc("T1053.005", "guid-a08", 2, "2026-01-01T10:02:59.000Z", "2026-01-01T10:03:02.000Z", 4001,
                    exit_code=5)
    r = by_id(run(tmp_path, procs=procs))
    assert r["A08"]["exec_failed"] is True and r["A08"]["exit_code"] == 5


def test_test_not_in_logs_is_not_run_and_unknown_guid_listed(tmp_path):
    procs = default_procs() + [proc("T9999", "guid-unknown", 1, "2026-01-01T10:06:00.000Z",
                                    "2026-01-01T10:06:01.000Z", 8001)]
    rep = run(tmp_path, procs=procs)
    assert rep["not_run"] == ["A11"]
    assert rep["unknown_runs"] == [{"technique": "T9999", "guid": "guid-unknown"}]


def test_technique_summary_counts_only_observed(tmp_path):
    s = {x["technique"]: x for x in run(tmp_path)["by_technique"]}
    assert s["T1547.001"]["TP"] == 1 and s["T1547.001"]["FN_DU_KIEN"] == 1 and s["T1547.001"]["FN"] == 0
    assert s["T1059.001"]["TP"] == 1
    assert s["T1070.004"]["NOT_RUN"] == 1 and s["T1070.004"]["runs"] == 0
    assert s["T1059.003"]["FP"] == 1


# ---------- báo cáo và an toàn ----------

def test_report_has_no_identity_and_states_sample_size(tmp_path):
    rep = run(tmp_path)
    md = ac.to_markdown(rep)
    js = json.dumps(rep, default=str)
    for secret in (SECRET_HOST, SECRET_USER, "10.9.8.7"):
        assert secret not in md and secret not in js
    assert "Defender" in md and "cỡ mẫu" in md.lower()
    assert "| A01 |" in md


def test_compare_does_not_modify_source_silver(tmp_path):
    db = build_silver(tmp_path)
    before = db.read_bytes()
    ac.compare(ac.load_runs([write_logs(tmp_path, default_procs())]), db, EXPECTED)
    assert db.read_bytes() == before


def test_missing_silver_is_clear_error(tmp_path):
    with pytest.raises(FileNotFoundError):
        ac.compare([], tmp_path / "nope.duckdb", EXPECTED)


def test_cli_writes_report_and_exit_code(tmp_path):
    db = build_silver(tmp_path)
    logs = write_logs(tmp_path, default_procs())
    exp = tmp_path / "exp.yaml"
    exp.write_text(yaml.safe_dump(EXPECTED, allow_unicode=True), encoding="utf-8")
    out, js = tmp_path / "r.md", tmp_path / "r.json"
    code = ac.main(["--silver", str(db), "--logs", str(logs), "--expected", str(exp), "--out", str(out),
                    "--json", str(js)])
    assert code == 0 and out.exists() and json.loads(js.read_text(encoding="utf-8"))["runs"]


# ---------- tệp kỳ vọng thật ----------

def test_real_expected_file_is_consistent_with_rules():
    from detection.loader import load_rules
    exp = yaml.safe_load((HERE / "atomic_expected.yaml").read_text(encoding="utf-8"))
    rules = {rid for rid, r in load_rules().items() if r["status"] == "enabled"}
    ids, guids = set(), set()
    for x in exp["tests"]:
        assert x["category"] in ac.CATEGORIES, x
        assert x["id"] not in ids and x["guid"] not in guids
        ids.add(x["id"]); guids.add(x["guid"])
        for rid in x["target_rules"]:
            assert rid in rules, f"{x['id']}: rule {rid} không tồn tại"
        if x["category"] == "TP_EXPECTED":
            assert x["target_rules"], x["id"]
        if x["category"] == "CONTROL":
            assert not x["target_rules"]
        assert x.get("reason"), f"{x['id']}: thiếu lý do"
    assert exp["atomics_commit"] and len(exp["atomics_commit"]) == 40


def test_tp_requires_target_rule_not_any_rule(tmp_path):
    """A04 kỳ vọng DET-003; nếu cây tiến trình chỉ có DET-001 MATCH (không có Event 13) thì là FN, không phải TP."""
    rows = [x for x in silver_rows() if x["id"] not in ("a04c", "a04r")] + [
        {"id": "a04p", "table": "process", "timestamp": t("01:01"), "pid": 2003, "process_guid": g(12),
         "parent_guid": g(3), "image_path": PS, "command_line": "powershell.exe -enc QQBBAA=="}]
    r = by_id(run(tmp_path, rows=rows))["A04"]
    assert r["matched_rules"] == ["DACN-DET-001"] and r["verdict"] == "FN"
    assert r["missing_telemetry"] == [13]


def test_process_never_started_is_its_own_verdict(tmp_path):
    """Invoke-AtomicTest báo 'Access is denied' tại Process.Start (thường do Defender chặn khi tạo tiến trình):
    Attire ghi process-id/exit-code rỗng. Đây không phải mất telemetry của DACN và không tính TP/FN."""
    procs = default_procs()
    procs[0] = proc("T1059.001", "guid-a01", 17, "2026-01-01T10:00:09.000Z", "2026-01-01T10:00:09.000Z", None,
                    exit_code=None)
    rep = run(tmp_path, procs=procs)
    r = by_id(rep)["A01"]
    assert r["verdict"] == "KHONG_KHOI_TAO_DUOC" and r["exec_failed"] is True
    s = {x["technique"]: x for x in rep["by_technique"]}["T1059.001"]
    assert s["KHONG_KHOI_TAO_DUOC"] == 1 and s["TP"] == 0 and s["FN"] == 0
    assert "KHONG_KHOI_TAO_DUOC" in ac.to_markdown(rep)


# ---------- --bronze: nạp segment đã niêm phong mà core chưa kịp nạp ----------

def _bronze_with_a01(tmp_path):
    """Segment Bronze SYNTHETIC chứa Event 1 của A01 (pid 1001, powershell -e) mà Silver chưa có."""
    import bronze_contract as bc
    import scenario_xml as sx
    from agent.bronze_writer import BronzeWriter
    d = {"RuleName": "-", "UtcTime": "2026-01-01 10:00:10.500", "ProcessGuid": sx.guid("bronze-a01"),
         "ProcessId": "1001", "Image": PS, "CommandLine": "powershell.exe -e  JgAgAA==", "CurrentDirectory": "C:\\",
         "User": "LAB-HOST\\LABUSER", "IntegrityLevel": "Medium", "Hashes": "SHA256=" + "A" * 64,
         "ParentProcessGuid": sx.guid("runner"), "ParentProcessId": "1", "ParentImage": PS,
         "ParentCommandLine": "powershell.exe"}
    xml = sx._wrap(1, "2026-01-01T10:00:10.500Z", d)
    w = BronzeWriter(tmp_path / "bronze")
    w.append(bc.build_bronze_record(xml, mode="file", seq=0))
    w.seal()
    return tmp_path / "bronze"


def test_bronze_option_ingests_unprocessed_segments_into_copy(tmp_path):
    rows = [x for x in silver_rows() if x["id"] not in ("a01s", "a01c")]
    db = build_silver(tmp_path, rows)
    bronze = _bronze_with_a01(tmp_path)
    runs = ac.load_runs([write_logs(tmp_path, default_procs())])
    assert by_id(ac.compare(runs, db, EXPECTED))["A01"]["verdict"] == "KHONG_THAY_TIEN_TRINH_GOC"
    before = db.read_bytes()
    rep = ac.compare(runs, db, EXPECTED, bronze=bronze)
    assert by_id(rep)["A01"]["verdict"] == "TP"
    assert db.read_bytes() == before                                   # chỉ nạp vào bản sao


def test_report_states_silver_coverage_and_flags_runs_after_it(tmp_path):
    procs = default_procs() + [proc("T1070.004", "guid-a11", 4, "2026-01-01T12:00:00.000Z",
                                    "2026-01-01T12:00:02.000Z", 9001)]
    rep = run(tmp_path, procs=procs)
    assert rep["silver_coverage"]["max"].startswith("2026-01-01T10:30:00")
    a11 = by_id(rep)["A11"]
    assert a11["verdict"] == "KHONG_THAY_TIEN_TRINH_GOC" and a11["after_silver_end"] is True
    assert by_id(rep)["A04"]["after_silver_end"] is False
    md = ac.to_markdown(rep)
    assert "Silver có dữ liệu" in md and "--bronze" in md
