"""DACN-DET-203/204 (rule 'scriptblock' trên PowerShell 4104), hạng mục 6 của docs/architecture/w8.
Dữ liệu SYNTHETIC: XML 4104 dựng lúc chạy theo cấu trúc mẫu thật; chuỗi "đáng ngờ" được ghép lúc chạy (không để trong tệp tĩnh
để Defender trên VM không cách ly tệp fixture). Không có script nào được thực thi."""
import base64
import json
from pathlib import Path
from xml.sax.saxutils import escape

import pytest

import bronze_contract as bc
from agent.bronze_writer import BronzeWriter
from alerts.builder import build_from_results
from alerts.evidence import resolve_evidence
from alerts.store import AlertStore
from detection.engine import DetectionEngine
from detection.loader import load_rules
from detection.scriptblock import decode_candidates, evaluate_scriptblock
from pipeline.silver_store import SilverStore

IEX = "Invoke-" + "Expression"
DLS = "Down" + "loadString"
NS = "http://schemas.microsoft.com/win/2004/08/events/event"


def ps_xml(rid, num, total, text, sbid="00000000-0000-4000-8000-0000000000f1", ts="2026-11-28T01:10:00.0000000Z"):
    return (f"<Event xmlns='{NS}'><System><Provider Name='Microsoft-Windows-PowerShell' "
            "Guid='{a0c1853b-5c40-4b15-8766-3cf1c58f985a}'/><EventID>4104</EventID><Version>1</Version><Level>5</Level>"
            f"<Task>2</Task><Opcode>15</Opcode><Keywords>0x0</Keywords><TimeCreated SystemTime='{ts}'/>"
            f"<EventRecordID>{rid}</EventRecordID><Correlation/><Execution ProcessID='3333' ThreadID='4444'/>"
            "<Channel>Microsoft-Windows-PowerShell/Operational</Channel><Computer>SYNTH-HOST</Computer>"
            "<Security UserID='S-1-5-21-0-0-0-1001'/></System><EventData>"
            f"<Data Name='MessageNumber'>{num}</Data><Data Name='MessageTotal'>{total}</Data>"
            f"<Data Name='ScriptBlockText'>{escape(text)}</Data><Data Name='ScriptBlockId'>{sbid}</Data>"
            "<Data Name='Path'></Data></EventData></Event>")


class Env:
    def __init__(self, tmp_path):
        self.tmp, self.n = tmp_path, 0
        self.st = SilverStore(tmp_path / "s.duckdb")
        self.rules = load_rules()
        self.eng = DetectionEngine(self.st.con, rules=self.rules)
        self.store = AlertStore(self.st.con)

    def ingest(self, xmls):
        self.n += 1
        w = BronzeWriter(self.tmp / f"b{self.n}")
        for x in xmls:
            w.append(bc.build_bronze_record(x, mode="file"))
        self.st.ingest_segment(w.seal(), f"t{self.n}")

    def run(self):
        res = self.eng.run()
        return res, build_from_results(self.store, self.rules, res, self.st.con)


def only(results, rid):
    return [r for r in results if r.rule_id == rid]


def test_det203_match_alert_has_no_script_text_and_evidence_is_withheld(tmp_path):
    e = Env(tmp_path)
    secret = "SYNTHETIC-NOT-A-SECRET-123"
    e.ingest([ps_xml(10, 1, 1, f"$p = '{secret}'; $s = 'x' | {IEX}")])
    res, out = e.run()
    (r,) = only(res, "DACN-DET-203")
    assert r.matched_fields["patterns"] == ["invoke-expression"] and r.coverage_status == "FULL"
    assert r.matched_fields["script_length"] > 0 and len(r.matched_fields["script_sha256"]) == 64
    a = e.store.get(out["alerts"][0])
    dumped = json.dumps(a, default=str)
    assert secret not in dumped and IEX not in dumped                 # không có văn bản script trong alert
    assert json.loads(a["mitre_technique_ids"]) == ["T1059.001"] and a["detection_source"] == "RULE"
    ev = resolve_evidence(e.st.con, out["alerts"][0], tmp_path / "b1")
    assert ev["events"][0]["silver"] is None and ev["events"][0]["raw_xml"] is None    # API chưa trả script (hạng mục 8)
    assert secret not in json.dumps(ev, default=str)


def test_benign_block_no_result(tmp_path):
    e = Env(tmp_path)
    e.ingest([ps_xml(10, 1, 1, "Get-ChildItem C:\\lab | Select-Object Name")])
    res, out = e.run()
    assert not only(res, "DACN-DET-203") and not only(res, "DACN-DET-204") and out["alerts"] == []


def test_pattern_split_across_parts_matches_when_block_complete(tmp_path):
    e = Env(tmp_path)
    e.ingest([ps_xml(20, 1, 3, "# part one\n$a = 1 | Invoke-Ex"), ps_xml(21, 2, 3, "pression\n# part two"),
              ps_xml(22, 3, 3, "Write-Output done")])
    (r,) = only(e.run()[0], "DACN-DET-203")
    assert r.coverage_status == "FULL" and len(r.contributing_event_ids) == 3 and r.matched_fields["parts_seen"] == 3


def test_missing_part_no_fake_join_and_partial_coverage(tmp_path):
    e = Env(tmp_path)
    e.ingest([ps_xml(30, 1, 3, "x | Invoke-Ex"), ps_xml(32, 3, 3, "pression")])        # phần 2 thiếu
    assert not only(e.run()[0], "DACN-DET-203")                                         # không ghép giả qua chỗ hở
    e2 = Env(tmp_path / "b")
    e2.ingest([ps_xml(40, 1, 3, "# a"), ps_xml(42, 3, 3, f"y | {IEX}")])
    (r,) = only(e2.run()[0], "DACN-DET-203")
    assert r.coverage_status == "PARTIAL_SCRIPT_BLOCK" and r.missing_fields == ["MessageNumber:2"]
    assert "thiếu 1/3" in r.severity_reason


def test_late_part_completes_block_and_is_evaluated(tmp_path):
    e = Env(tmp_path)
    e.ingest([ps_xml(50, 1, 3, "x | Invoke-Ex"), ps_xml(52, 3, 3, "# end")])
    assert not only(e.run()[0], "DACN-DET-203")
    e.ingest([ps_xml(51, 2, 3, "pression")])
    (r,) = only(e.run()[0], "DACN-DET-203")
    assert r.coverage_status == "FULL"
    assert e.run() == ([], {"alerts": [], "gaps": [], "suppressed": 0, "skipped": 0})


def test_det204_decodes_utf16_base64_and_det203_does_not_see_it(tmp_path):
    e = Env(tmp_path)
    cmd = f"$c = New-Object Net.WebClient; $c.{DLS}('http://127.0.0.1/none') | {IEX}"
    enc = base64.b64encode(cmd.encode("utf-16-le")).decode()
    e.ingest([ps_xml(60, 1, 1, f"$payload = '{enc}'")])
    res, out = e.run()
    assert not only(res, "DACN-DET-203")
    (r,) = only(res, "DACN-DET-204")
    assert r.matched_fields["decoded_patterns"] == ["downloadstring", "invoke-expression", "net.webclient"]
    assert r.matched_fields["decoded_encodings"] == ["utf-16-le"]
    assert enc not in json.dumps(e.store.get(out["alerts"][0]), default=str)


def test_decode_candidates_limits():
    good = base64.b64encode(("Write-Output " + "a" * 40).encode("utf-8")).decode()
    binary = base64.b64encode(bytes(range(256))).decode()
    text = f"{good} {binary} {good[:-1]} " + "!" * 10
    decoded, seen = decode_candidates(text, 40)
    assert [enc for enc, _ in decoded] == ["utf-8"] and seen == 3      # nhị phân bỏ, độ dài lẻ bỏ
    assert decode_candidates(" ".join([good] * 10), 40, max_candidates=3)[1] == 3
    assert decode_candidates(good, 40, max_decoded_bytes=32)[0] == []          # 53 byte > 32


def test_evaluator_uses_gap_and_hashes_clean_text():
    rule = {"rule_id": "DACN-DET-990", "rule_version": 1, "severity": "low", "patterns": ["abcdef"]}
    parts = [{"message_number": 1, "script_block_text": "xxabc", "event_id": "e1"},
             {"message_number": 3, "script_block_text": "defyy", "event_id": "e3"}]
    assert evaluate_scriptblock(rule, "H", "s", 3, parts) is None
    parts[1]["script_block_text"] = "abcdef"
    r = evaluate_scriptblock(rule, "H", "s", 3, parts)
    assert r.matched_fields["script_length"] == len("xxabcabcdef") and r.subject == "H|s|3"


def test_shipped_powershell_rules():
    rules = load_rules()
    for rid in ("DACN-DET-203", "DACN-DET-204"):
        r = rules[rid]
        assert r["type"] == "scriptblock" and r["response_policy"] == "alert_only" and r["group_by_field"] == "script_block_id"
        assert r["mitre_technique_ids"] == ["T1059.001"]                  # T1027 chưa có căn cứ (D6)
    assert rules["DACN-DET-204"]["base64"]["min_length"] == 40


@pytest.mark.parametrize("name", ["ps4104_single.synthetic.xml", "ps4104_three_parts.synthetic.xml"])
def test_existing_benign_fixtures_do_not_trigger(tmp_path, name):
    e = Env(tmp_path)
    fix = Path(__file__).resolve().parents[2] / "tests/fixtures/windows_channels" / name
    e.ingest(list(bc.iter_raw_xml_from_file(fix)))
    res, _ = e.run()
    assert not only(res, "DACN-DET-203") and not only(res, "DACN-DET-204")
