"""DACN-DET-201/202 và mở rộng rule model (source_events, severity_by, context_fields, group_by_field, detection_source).
Hạng mục 5 của docs/architecture/w8/telemetry-defender-powershell-proposal.md. Fixture SYNTHETIC dựng theo cấu trúc mẫu thật."""
import json
from pathlib import Path

import pytest

import bronze_contract as bc
from agent.bronze_writer import BronzeWriter
from alerts.builder import build_from_results
from alerts.evidence import resolve_evidence
from alerts.store import AlertStore
from detection.engine import DetectionEngine
from detection.evaluator import evaluate_single
from detection.loader import RuleError, load_rules, validate_rule
from pipeline.silver_store import SilverStore

ROOT = Path(__file__).resolve().parents[2]
FIX = ROOT / "tests/fixtures/windows_channels"
SYN = ROOT / "poc/sysmon-collector/configs/synthetic_events.xml"
DEF = "Microsoft-Windows-Windows Defender/Operational"
PS = "Microsoft-Windows-PowerShell/Operational"


def seg(tmp_path, names=(), extra_xml=()):
    w = BronzeWriter(tmp_path / "b")
    for x in [x for n in names for x in bc.iter_raw_xml_from_file(FIX / n)] + list(extra_xml):
        w.append(bc.build_bronze_record(x, mode="file"))
    return w.seal()


def run_all(tmp_path, *names):
    st = SilverStore(tmp_path / "s.duckdb")
    st.ingest_segment(seg(tmp_path, names), "t")
    rules = load_rules()
    eng = DetectionEngine(st.con, rules=rules)
    results = eng.run()
    store = AlertStore(st.con)
    out = build_from_results(store, rules, results, st.con)
    return st, eng, rules, results, store, out


def by_rule(results, rid):
    return [r for r in results if r.rule_id == rid]


def test_det201_eicar_detection_and_action_become_one_external_alert(tmp_path):
    st, eng, rules, results, store, out = run_all(tmp_path, "defender_1116.synthetic.xml", "defender_1117.synthetic.xml")
    r201 = by_rule(results, "DACN-DET-201")
    assert [r.outcome for r in r201] == ["MATCH", "MATCH"]
    ctx = r201[0].matched_fields["context"]
    assert ctx["threat_name"] == "Virus:DOS/EICAR_Test_File" and ctx["severity_name"] == "Severe"
    assert ctx["resource_type"] == "file" and ctx["detection_id"] == "00000000-0000-4000-8000-0000000000a1"
    assert len(out["alerts"]) == 1 and out["suppressed"] == 1          # 1117 cùng detection_id gộp vào alert của 1116
    a = store.get(out["alerts"][0])
    assert a["detection_source"] == "EXTERNAL_DEFENDER" and a["severity"] == "medium"
    assert a["process_guid"] is None and a["mitre_technique_ids"] is None
    assert len(a["contributing_event_ids"]) == 2
    assert eng.run() == []                                              # chạy lại không phát thêm


def test_det201_different_detections_are_separate_alerts(tmp_path):
    st, eng, rules, results, store, out = run_all(tmp_path, "defender_1116.synthetic.xml", "defender_1116_cmdline.synthetic.xml")
    assert len(out["alerts"]) == 2
    ctxs = sorted(r.matched_fields["context"]["resource_type"] for r in by_rule(results, "DACN-DET-201"))
    assert ctxs == ["CmdLine", "file"]
    unknown = [r for r in by_rule(results, "DACN-DET-201") if r.matched_fields["context"]["resource_type"] == "CmdLine"][0]
    assert unknown.matched_fields["context"]["process_name"] == "Unknown"


def test_det202_severity_by_event_id_and_mitre(tmp_path):
    st, eng, rules, results, store, out = run_all(tmp_path, "defender_5001.synthetic.xml", "defender_5007.synthetic.xml")
    sev = {r.matched_fields["context"]["event_type"]: r.severity for r in by_rule(results, "DACN-DET-202")}
    assert sev == {"DEFENDER_RTP_DISABLED": "high", "DEFENDER_CONFIG_CHANGED": "low"}
    alerts = [store.get(a) for a in out["alerts"]]
    assert {a["rule_id"] for a in alerts} == {"DACN-DET-202"}
    assert all(json.loads(a["mitre_technique_ids"]) == ["T1562.001"] for a in alerts)
    assert all(a["detection_source"] == "EXTERNAL_DEFENDER" for a in alerts)
    assert not by_rule(results, "DACN-DET-201")                          # 5001/5007 không phải phát hiện mối đe dọa


def test_defender_only_ingestion_after_first_run_is_evaluated(tmp_path):
    """Con trỏ tăng dần phải thấy dữ liệu chỉ có ở bảng v1.3 (không có sự kiện Sysmon mới)."""
    st = SilverStore(tmp_path / "s.duckdb")
    st.ingest_segment(seg(tmp_path / "a", extra_xml=list(bc.iter_raw_xml_from_file(SYN))), "t1")
    eng = DetectionEngine(st.con, rules=load_rules())
    eng.run()
    st.ingest_segment(seg(tmp_path / "b", ["defender_1116.synthetic.xml"]), "t2")
    assert [r.outcome for r in by_rule(eng.run(), "DACN-DET-201")] == ["MATCH"]


def test_defender_timestamps_do_not_move_correlation_watermark(tmp_path):
    st = SilverStore(tmp_path / "s.duckdb")
    st.ingest_segment(seg(tmp_path, ["defender_1116.synthetic.xml"]), "t")
    eng = DetectionEngine(st.con, rules=load_rules())
    assert eng._host_watermarks() == {} and eng._watermark() is None


def test_defender_alert_evidence_resolves_to_raw_xml(tmp_path):
    st, eng, rules, results, store, out = run_all(tmp_path, "defender_1116.synthetic.xml")
    ev = resolve_evidence(st.con, out["alerts"][0], tmp_path / "b")
    assert ev["status"] == "FULL" and "<EventID>1116</EventID>" in ev["events"][0]["raw_xml"]
    assert ev["events"][0]["silver"]["threat_name"] == "Virus:DOS/EICAR_Test_File"


def test_engine_without_v13_tables_skips_channel_rules(tmp_path):
    st = SilverStore(tmp_path / "s.duckdb")
    st.con.execute("drop view v_powershell_scriptblocks_complete")
    st.con.execute("drop table silver_defender_events")
    st.con.execute("drop table silver_powershell_scriptblock_events")
    st.ingest_segment(seg(tmp_path, extra_xml=list(bc.iter_raw_xml_from_file(SYN))), "t")
    results = DetectionEngine(st.con, rules=load_rules()).run()       # không lỗi; rule Sysmon vẫn chạy
    assert not [r for r in results if r.rule_id in ("DACN-DET-201", "DACN-DET-202")]


def _rule(**kw):
    r = {"rule_id": "DACN-DET-990", "rule_version": 1, "name": "t", "description": "synthetic", "type": "single",
         "severity": "low", "status": "enabled", "source_events": [{"channel": DEF, "event_ids": [1116]}]}
    r.update(kw)
    return {k: v for k, v in r.items() if v is not None}


@pytest.mark.parametrize("kw,msg", [
    ({"sysmon_event_ids": [1]}, "chỉ khai một"),
    ({"source_events": [{"channel": "Security", "event_ids": [4688]}]}, "không có bảng Silver"),
    ({"source_events": [{"channel": DEF, "event_ids": [4104]}]}, "không hỗ trợ Event ID"),
    ({"source_events": [{"channel": PS, "event_ids": [4104]}], "detection_source": "EXTERNAL_DEFENDER"}, "EXTERNAL_DEFENDER"),
    ({"type": "correlation", "time_window_seconds": 5, "window_status": "TBD_UNCALIBRATED"}, "source_events chỉ dùng"),
    ({"source_events": None}, "sysmon_event_ids hoặc source_events"),
])
def test_loader_rejects_bad_source_events(kw, msg):
    with pytest.raises(RuleError, match=msg):
        validate_rule(_rule(**kw))


def test_loader_normalizes_channel_case_without_mutating_input():
    src = _rule(source_events=[{"channel": DEF.lower(), "event_ids": [1116]}])
    r = validate_rule(src)
    assert r["source_events"][0]["channel"] == DEF and src["source_events"][0]["channel"] == DEF.lower()


def test_evaluator_severity_by_and_context_only_on_match():
    rule = validate_rule(_rule(severity_by={"field": "windows_event_id", "map": {"1116": "high"}},
                               context_fields=["threat_name", "process_name"],
                               match={"all": [{"field": "threat_name", "op": "contains_any", "value": ["eicar"]}]}))
    row = {"event_id": "e1", "windows_event_id": 1116, "threat_name": "Virus:DOS/EICAR_Test_File", "process_name": None}
    r = evaluate_single(rule, row)
    assert r.severity == "high" and "windows_event_id=1116" in r.severity_reason
    assert r.matched_fields["context"] == {"threat_name": "Virus:DOS/EICAR_Test_File"}   # bỏ trường None
    assert evaluate_single(rule, dict(row, windows_event_id=1117)).severity == "low"
    nomatch = evaluate_single(rule, dict(row, threat_name="Other"))
    assert nomatch.outcome == "NO_MATCH" and nomatch.matched_fields == {}


def test_shipped_defender_rules_are_alert_only():
    rules = load_rules()
    for rid in ("DACN-DET-201", "DACN-DET-202"):
        assert rules[rid]["response_policy"] == "alert_only" and rules[rid]["detection_source"] == "EXTERNAL_DEFENDER"
    assert "mitre_technique_ids" not in rules["DACN-DET-201"]
