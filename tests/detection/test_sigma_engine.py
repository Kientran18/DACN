"""Rule Sigma chạy trong DetectionEngine trên Silver DuckDB, đi qua cùng luồng DetectionResult -> alert.
Fixture SYNTHETIC có nhãn (TP/TN/INSUFFICIENT) dựng lúc chạy; chuỗi đáng ngờ ghép lúc chạy. Không phải telemetry thật,
không phải số đo chất lượng phát hiện."""
import hashlib
import json
import uuid

import pytest

from alerts.builder import build_from_results
from alerts.store import AlertStore
from detection.engine import DetectionEngine
from detection.loader import load_rules
from detection.sigma.loader import load_sigma
from pipeline.silver_store import SilverStore

NS = uuid.UUID("5a5a5a5a-0000-4000-8000-000000000001")
HOST = "LABHOST"
GUID = "22222222-2222-2222-2222-222222222222"
ON = {"enabled": True, "allow_experimental": False, "max_rules": 50, "regex_max_length": 1000}
SCHT = "schtasks.exe"
DEFENDER = "Microsoft-Windows-Windows Defender/Operational"
PSCH = "Microsoft-Windows-PowerShell/Operational"


def eid(alias):
    return str(uuid.uuid5(NS, alias))


def sysmon(table, alias, sysmon_id, event_type, raw, n, **cols):
    row = {"event_id": eid(alias), "timestamp": f"2026-01-01T09:00:{n:02d}+00:00", "source": "SYSMON",
           "event_type": event_type, "sysmon_event_id": sysmon_id, "channel": "Microsoft-Windows-Sysmon/Operational",
           "record_id": n, "hostname": HOST, "process_guid": GUID, "raw_data": json.dumps(raw),
           "image_path": raw.get("Image", "C:\\Windows\\x.exe"), **cols}
    return table, row


def proc(alias, n, raw):
    return sysmon("silver_process_events", alias, 1, "PROCESS_START", raw, n, pid=100,
                  command_line=raw.get("CommandLine"), user_name=raw.get("User"))


P1 = {"Image": "C:\\Windows\\System32\\" + SCHT, "OriginalFileName": SCHT, "CommandLine": SCHT + " /create /tn t /tr c:\\x.exe",
      "User": "LAB\\analyst", "ParentImage": "C:\\Windows\\System32\\cmd.exe", "ParentCommandLine": "cmd", "Hashes": "SHA256=00",
      "IntegrityLevel": "Medium", "CurrentDirectory": "C:\\", "Description": "", "Product": "", "Company": "",
      "FileVersion": "", "LogonId": "0x1", "ParentUser": "LAB\\analyst"}

ROWS = {
    # nhãn: (bảng, hàng, {rule_id: outcome kỳ vọng})
    "tp_schtasks_create": (proc("tp_schtasks_create", 1, P1), {"DACN-SIG-92626ddd": "MATCH"}),
    "tn_schtasks_query": (proc("tn_schtasks_query", 2, {**P1, "CommandLine": SCHT + " /query"}), {"DACN-SIG-92626ddd": None}),
    "tn_schtasks_system": (proc("tn_schtasks_system", 3, {**P1, "User": "NT AUTHORITY\\SYSTEM"}), {"DACN-SIG-92626ddd": None}),
    # field CommandLine vắng trong raw_data (giả lập hàng thiếu field): không kết luận lành tính
    "insuff_schtasks_nocmd": (proc("insuff_schtasks_nocmd", 4, {k: v for k, v in P1.items() if k != "CommandLine"}),
                              {"DACN-SIG-92626ddd": "INSUFFICIENT_TELEMETRY"}),
    "tp_systeminfo_ofn": (proc("tp_systeminfo_ofn", 5, {**P1, "Image": "C:\\t\\renamed.exe", "OriginalFileName": "sysinfo.exe",
                                                         "CommandLine": "renamed.exe"}), {"DACN-SIG-0ef56343": "MATCH"}),
    "tp_run_key": (sysmon("silver_registry_events", "tp_run_key", 13, "REGISTRY_SET_VALUE",
                          {"EventType": "SetValue", "TargetObject": "HKU\\S-1\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Run\\x",
                           "Details": "C:\\t\\x.exe", "Image": "C:\\Windows\\System32\\reg.exe", "User": "LAB\\analyst"}, 6,
                          operation="SetValue", target_object="HKU\\k", hive="HKU", key_path="k"),
                   {"DACN-SIG-20f0ee37": "MATCH"}),
    "tn_run_key_empty": (sysmon("silver_registry_events", "tn_run_key_empty", 13, "REGISTRY_SET_VALUE",
                                {"EventType": "SetValue", "TargetObject": "HKU\\S-1\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Run\\x",
                                 "Details": "(Empty)", "Image": "C:\\Windows\\System32\\reg.exe", "User": "LAB\\analyst"}, 7,
                                operation="SetValue", target_object="HKU\\k", hive="HKU", key_path="k"),
                         {"DACN-SIG-20f0ee37": None}),
    "tp_startup_file": (sysmon("silver_file_events", "tp_startup_file", 11, "FILE_CREATE",
                               {"TargetFilename": "C:\\Users\\u\\AppData\\Roaming\\Microsoft\\Windows\\Start Menu\\Programs\\StartUp\\a.lnk",
                                "Image": "C:\\Windows\\explorer.exe", "User": "LAB\\analyst"}, 8,
                               operation="FILE_CREATE", file_path="C:\\a.lnk"),
                        {"DACN-SIG-2aa0a6b4": "MATCH"}),
    "tp_dns_regsvr32": (sysmon("silver_network_events", "tp_dns_regsvr32", 22, "DNS_QUERY",
                               {"Image": "C:\\Windows\\System32\\regsvr32.exe", "QueryName": "example.invalid", "QueryStatus": "0",
                                "QueryResults": "", "User": "LAB\\analyst"}, 9),
                        {"DACN-SIG-36e037c4": "MATCH"}),
    "tp_net_certutil": (sysmon("silver_network_events", "tp_net_certutil", 3, "NETWORK_CONNECT",
                               {"Image": "C:\\Windows\\System32\\certutil.exe", "Initiated": "true", "DestinationPort": "443",
                                "DestinationIp": "192.0.2.10", "Protocol": "tcp", "User": "LAB\\analyst"}, 10),
                        {"DACN-SIG-0dba975d": "MATCH"}),
    "tn_net_certutil_port": (sysmon("silver_network_events", "tn_net_certutil_port", 3, "NETWORK_CONNECT",
                                    {"Image": "C:\\Windows\\System32\\certutil.exe", "Initiated": "true", "DestinationPort": "8080",
                                     "DestinationIp": "192.0.2.10", "Protocol": "tcp", "User": "LAB\\analyst"}, 11),
                             {"DACN-SIG-0dba975d": None}),
}


def defender(alias, n, wid, **cols):
    return "silver_defender_events", {"event_id": eid(alias), "timestamp": f"2026-01-01T09:01:{n:02d}+00:00",
                                      "source": "WINDOWS_DEFENDER", "event_type": "X", "windows_event_id": wid,
                                      "channel": DEFENDER, "record_id": 100 + n, "hostname": HOST, "raw_data": "{}", **cols}


def ps(alias, n, sbid, num, total, text, path=""):
    return "silver_powershell_scriptblock_events", {
        "event_id": eid(alias), "timestamp": f"2026-01-01T09:02:{n:02d}+00:00", "source": "POWERSHELL",
        "event_type": "POWERSHELL_SCRIPT_BLOCK", "windows_event_id": 4104, "channel": PSCH, "record_id": 200 + n,
        "hostname": HOST, "script_block_id": sbid, "message_number": num, "message_total": total,
        "script_block_text": text, "script_text_sha256": hashlib.sha256(text.encode()).hexdigest(), "raw_data": json.dumps({"Path": path, "ScriptBlockText": text})}


SB1, SB2 = "aaaaaaaa-0000-4000-8000-0000000000a1", "aaaaaaaa-0000-4000-8000-0000000000a2"
SECRET = "p@ss" + "word=hunter2"
ROWS.update({
    "tp_defender_5001": (defender("tp_defender_5001", 1, 5001), {"DACN-SIG-b28e58e4": "MATCH"}),
    "tp_defender_1116": (defender("tp_defender_1116", 2, 1116, threat_name="EICAR", detection_id="d-1"),
                         {"DACN-SIG-57b649ef": "MATCH", "DACN-SIG-b28e58e4": None}),
    # script block 2 phần: chuỗi cmdlet nằm ở phần 2
    "tp_ps_part1": (ps("tp_ps_part1", 1, SB1, 1, 2, "$x = 1; " + SECRET + "\n"), {}),
    "tp_ps_part2": (ps("tp_ps_part2", 2, SB1, 2, 2, "$a = New-" + "ScheduledTaskAction -Execute x"),
                    {}),
    "tn_ps_benign": (ps("tn_ps_benign", 3, SB2, 1, 1, "Get-ChildItem C:\\"), {}),
})


@pytest.fixture()
def db(tmp_path):
    st = SilverStore(tmp_path / "sigma.duckdb")
    for _, ((table, row), _exp) in ROWS.items():
        st._insert(table, row)
    yield st
    st.close()


def rules_with_sigma():
    return {**load_rules(), **load_sigma(ON).rules}


def test_labeled_fixture_outcomes(db):
    eng = DetectionEngine(db.con, rules=rules_with_sigma())
    out = eng.run()
    got = {}
    for r in out:
        if r.rule_id.startswith("DACN-SIG-"):
            for e in r.contributing_event_ids:
                got.setdefault(e, {})[r.rule_id] = r.outcome
    for alias, ((_, row), exp) in ROWS.items():
        for rid, outcome in exp.items():
            assert got.get(row["event_id"], {}).get(rid) == outcome, (alias, rid)
    assert eng.run() == []                                     # chạy lại không phát kết quả mới (replay-safe)


def test_scriptblock_assembled_and_text_not_copied(db):
    out = DetectionEngine(db.con, rules=rules_with_sigma()).run()
    hits = [r for r in out if r.rule_id == "DACN-SIG-363eccc0" and r.outcome == "MATCH"]
    assert len(hits) == 1
    h = hits[0]
    assert sorted(h.contributing_event_ids) == sorted([eid("tp_ps_part1"), eid("tp_ps_part2")])
    dumped = json.dumps(h.to_dict())
    assert "ScheduledTaskAction" not in dumped and "hunter2" not in dumped
    assert h.matched_fields["sigma"]["fields"]["ScriptBlockText"]["redacted"] is True
    assert not any(r.rule_id.startswith("DACN-SIG-") and eid("tn_ps_benign") in r.contributing_event_ids for r in out)


def test_explanation_and_attribution(db):
    out = DetectionEngine(db.con, rules=rules_with_sigma()).run()
    r = next(x for x in out if x.rule_id == "DACN-SIG-92626ddd" and x.outcome == "MATCH")
    m = r.matched_fields
    assert m["sigma"]["selections_true"] == ["selection"]
    assert m["sigma"]["fields"]["Image"].endswith(SCHT) and "/create" in m["sigma"]["fields"]["CommandLine"]
    assert m["attribution"]["author"] and m["attribution"]["license"] == "DRL-1.1"
    assert "ddf1d4f87fd2" in m["attribution"]["source_url"]
    assert r.severity == "low"


def test_alerts_have_sigma_source_and_gaps_for_insufficient(db):
    rules = rules_with_sigma()
    eng = DetectionEngine(db.con, rules=rules)
    eng.run()
    store = AlertStore(db.con)
    res = eng.pending_delivery()
    built = build_from_results(store, {r.rule_id: eng.delivery_rule(r) for r in res}, res, db.con)
    sig = [a for a in store.list(limit=500) if a["rule_id"].startswith("DACN-SIG-")]
    assert sig and all(a["detection_source"] == "SIGMA" for a in sig)
    a = next(a for a in sig if a["rule_id"] == "DACN-SIG-92626ddd")
    assert a["rule_name"].startswith("[Sigma] ") and json.loads(a["mitre_technique_ids"]) == ["T1053.005"]
    assert any(g for g in built["gaps"])                       # INSUFFICIENT -> coverage gap, không phải alert
    assert not any(a["rule_id"] == "DACN-SIG-92626ddd" and a["contributing_event_ids"] == [eid("insuff_schtasks_nocmd")]
                   for a in sig)


def test_default_rules_have_no_sigma(db):
    out = DetectionEngine(db.con, rules=load_rules()).run()
    assert not any(r.rule_id.startswith("DACN-SIG-") for r in out)


def test_sigma_rule_change_triggers_rescan_without_duplicates(db):
    rules = rules_with_sigma()
    eng = DetectionEngine(db.con, rules=rules)
    first = eng.run()
    rules2 = dict(rules)
    r = dict(rules2["DACN-SIG-92626ddd"])
    r["rule_version"] = 2
    rules2["DACN-SIG-92626ddd"] = r
    again = DetectionEngine(db.con, rules=rules2).run()
    assert {x.rule_id for x in again} == {"DACN-SIG-92626ddd"}       # chỉ rule đổi version phát kết quả mới
    assert len([x for x in first if x.rule_id == "DACN-SIG-92626ddd"]) == len(again)
