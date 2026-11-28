"""Silver v1.3 (đề xuất) cho Windows Defender + PowerShell 4104: route theo kênh, mã lỗi, dedup, ghép script block.
Fixture SYNTHETIC dựng theo cấu trúc mẫu thật đã khử định danh (tests/fixtures/windows_channels/)."""
import json
from pathlib import Path

import pytest

import bronze_contract as bc
import bronze_to_silver_adapter as ad
from agent.bronze_writer import BronzeWriter
from pipeline.silver_store import SilverStore
from validator_windows_channels import WindowsChannelValidator, split_resource

ROOT = Path(__file__).resolve().parents[2]
FIX = ROOT / "tests/fixtures/windows_channels"
SYN = ROOT / "poc/sysmon-collector/configs/synthetic_events.xml"


def xmls(name):
    return list(bc.iter_raw_xml_from_file(FIX / name))


def ingest(tmp_path, *names, extra_xml=(), db="s.duckdb"):
    w = BronzeWriter(tmp_path / "b")
    for x in [x for n in names for x in xmls(n)] + list(extra_xml):
        w.append(bc.build_bronze_record(x, mode="file"))
    seg = w.seal()
    st = SilverStore(tmp_path / db)
    st.ingest_segment(seg, "t")
    return st, seg


def q(st, sql, *p):
    return st.con.execute(sql, list(p)).fetchall()


def dlq_codes(st):
    return sorted(r[0] for r in q(st, "select error_code from silver_quarantine_dlq"))


def test_defender_detection_and_action_share_detection_id(tmp_path):
    st, _ = ingest(tmp_path, "defender_1116.synthetic.xml", "defender_1117.synthetic.xml")
    rows = q(st, "select windows_event_id, event_type, detection_id, threat_name, severity_name, resource_type, resource_value,"
                 " process_name, action_name, level, source from silver_defender_events order by record_id")
    assert [r[0] for r in rows] == [1116, 1117]
    assert [r[1] for r in rows] == ["DEFENDER_MALWARE_DETECTED", "DEFENDER_MALWARE_ACTION"]
    assert rows[0][2] == rows[1][2] == "00000000-0000-4000-8000-0000000000a1"
    assert rows[0][3] == "Virus:DOS/EICAR_Test_File" and rows[0][4] == "Severe"
    assert rows[0][5] == "file" and rows[0][6].endswith("\\dacn_lab\\eicar_sample.txt")
    assert rows[0][7].endswith("\\powershell.exe")
    assert [r[8] for r in rows] == ["Not Applicable", "Quarantine"] and [r[9] for r in rows] == [3, 4]
    assert {r[10] for r in rows} == {"WINDOWS_DEFENDER"}
    assert dlq_codes(st) == []


def test_defender_cmdline_resource_and_unknown_process(tmp_path):
    st, _ = ingest(tmp_path, "defender_1116_cmdline.synthetic.xml")
    (rt, rv, pn, raw), = q(st, "select resource_type, resource_value, process_name, path_raw from silver_defender_events")
    assert rt == "CmdLine" and rv.startswith("C:\\Windows\\System32\\cmd.exe") and raw.startswith("CmdLine:_")
    assert pn == "Unknown"                    # giữ nguyên, không suy ra tiến trình


def test_defender_config_events(tmp_path):
    st, _ = ingest(tmp_path, "defender_5007.synthetic.xml", "defender_5001.synthetic.xml")
    rows = dict((r[0], r[1:]) for r in q(st, "select windows_event_id, event_type, old_value, new_value, threat_name"
                                             " from silver_defender_events"))
    assert rows[5007][0] == "DEFENDER_CONFIG_CHANGED" and rows[5007][1].endswith("= 0x1") and rows[5007][2].endswith("= 0x0")
    assert rows[5001] == ("DEFENDER_RTP_DISABLED", None, None, None)      # không có threat: NULL, không phải lỗi


def test_defender_missing_threat_goes_to_dlq(tmp_path):
    st, _ = ingest(tmp_path, "defender_1116_missing_threat.synthetic.xml")
    assert dlq_codes(st) == ["ERR_DEFENDER_MISSING_THREAT"]
    assert q(st, "select count(*) from silver_defender_events") == [(0,)]


def test_scriptblock_parts_and_complete_view(tmp_path):
    st, _ = ingest(tmp_path, "ps4104_three_parts.synthetic.xml", "ps4104_single.synthetic.xml")
    rows = q(st, "select message_number, message_total, writer_process_id, user_sid, level, script_path, length(script_text_sha256)"
                 " from silver_powershell_scriptblock_events where message_total = 3 order by message_number")
    assert [r[0] for r in rows] == [1, 2, 3] and {r[2] for r in rows} == {3333} and {r[4] for r in rows} == {5}
    assert rows[0][3] == "S-1-5-21-0-0-0-1001" and rows[0][5] is None and rows[0][6] == 64
    view = q(st, "select script_block_id, message_total, parts_seen, script_text, len(event_ids), writer_pid_count"
                 " from v_powershell_scriptblocks_complete order by message_total")
    assert [(v[1], v[2]) for v in view] == [(1, 1), (3, 3)]
    assert view[1][3] == "# dacn synthetic part one\n# dacn synthetic part two\nWrite-Output 'dacn synthetic three parts'"
    assert view[1][4] == 3 and view[1][5] == 1


def test_incomplete_block_not_in_view_and_not_fabricated(tmp_path):
    st, _ = ingest(tmp_path, "ps4104_missing_part.synthetic.xml")
    assert q(st, "select count(*) from silver_powershell_scriptblock_events") == [(2,)]
    assert q(st, "select count(*) from v_powershell_scriptblocks_complete") == [(0,)]


def test_bad_part_number_and_missing_field(tmp_path):
    bad_id = xmls("ps4104_single.synthetic.xml")[0].replace(
        "<Data Name='ScriptBlockId'>00000000-0000-4000-8000-000000000001</Data>", "<Data Name='ScriptBlockId'></Data>").replace(
        "<EventRecordID>42<", "<EventRecordID>43<")
    st, _ = ingest(tmp_path, "ps4104_bad_partno.synthetic.xml", extra_xml=[bad_id])
    assert dlq_codes(st) == ["ERR_PS_INVALID_PART_NUMBER", "ERR_PS_MISSING_SCRIPTBLOCK_FIELD"]


def test_unsupported_event_id_in_supported_channel(tmp_path):
    other = xmls("ps4104_single.synthetic.xml")[0].replace("<EventID>4104</EventID>", "<EventID>4100</EventID>")
    st, _ = ingest(tmp_path, extra_xml=[other])
    assert dlq_codes(st) == ["ERR_UNSUPPORTED_EVENT_ID"]


def test_replay_is_idempotent_and_lineage_written(tmp_path):
    st, seg = ingest(tmp_path, "defender_1116.synthetic.xml", "ps4104_three_parts.synthetic.xml")
    before = (q(st, "select count(*) from silver_defender_events"), q(st, "select count(*) from silver_powershell_scriptblock_events"))
    st.con.execute("delete from _ingest_ledger")          # ép nạp lại cùng segment
    res = st.ingest_segment(seg, "t2")
    assert res["inserted"] == 0 and res["duplicates"] == 4
    assert (q(st, "select count(*) from silver_defender_events"), q(st, "select count(*) from silver_powershell_scriptblock_events")) == before
    assert q(st, "select count(*) from silver_event_lineage") == [(4,)]


def test_sysmon_still_routed_to_sysmon_tables_in_mixed_segment(tmp_path):
    st, _ = ingest(tmp_path, "defender_1116.synthetic.xml", extra_xml=list(bc.iter_raw_xml_from_file(SYN)))
    assert q(st, "select count(*) from silver_defender_events") == [(1,)]
    assert q(st, "select count(*) from silver_process_events")[0][0] >= 1
    assert dlq_codes(st) == []


def _flat(name):
    rec = bc.build_bronze_record(xmls(name)[0], mode="file")
    return ad.to_silver_input(rec), rec


def test_validator_rejects_unsupported_channel_and_bad_timestamp():
    flat, rec = _flat("defender_1116.synthetic.xml")
    v = WindowsChannelValidator()
    assert not v.process_record(dict(flat, channel="Microsoft-Windows-Sysmon/Operational"), rec)
    assert not v.process_record(dict(flat, timestamp="not-a-time"), rec)
    assert not v.process_record(dict(flat, record_id=0), rec)
    assert [x.error_code for x in v.quarantine_dlq] == ["ERR_UNSUPPORTED_CHANNEL", "ERR_INVALID_TIMESTAMP", "ERR_INVALID_RECORD_ID"]


@pytest.mark.parametrize("path,expected", [
    ("file:_C:\\a\\b.txt", ("file", "C:\\a\\b.txt")), ("CmdLine:_cmd /c x", ("CmdLine", "cmd /c x")),
    ("C:\\no\\prefix.txt", (None, None)), ("", (None, None)), (None, (None, None))])
def test_split_resource(path, expected):
    assert split_resource(path) == expected


def test_raw_data_kept_verbatim(tmp_path):
    st, _ = ingest(tmp_path, "defender_1116.synthetic.xml")
    raw = json.loads(q(st, "select raw_data from silver_defender_events")[0][0])
    assert raw["Unused"] == "" and raw["FWLink"] == "" and "Security intelligence Version" in raw
