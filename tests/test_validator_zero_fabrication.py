"""U3 (audit): validator_poc không được tự điền giá trị không có trong nguồn (Zero Data Fabrication, CLAUDE.md mục 7).
Dữ liệu synthetic, tên máy giả."""
from validator_poc import SilverValidatorEngine

GUID = "{11111111-2222-3333-4444-555555555555}"


def net(**raw):
    return {"timestamp": "2026-10-18T09:12:02.0000000Z", "sysmon_event_id": 3, "record_id": 501,
            "channel": "Microsoft-Windows-Sysmon/Operational", "hostname": "LAB-HOST-01", "process_guid": GUID,
            "raw_data": {"Image": "C:\\lab\\a.exe", "SourceIp": "10.0.0.5", "SourcePort": "50000",
                         "DestinationIp": "10.0.0.9", "DestinationPort": "443", **raw}}


def test_missing_channel_is_quarantined_not_defaulted():
    rec = net(Protocol="tcp")
    del rec["channel"]
    eng = SilverValidatorEngine()
    assert eng.process_record(rec) is False
    assert [q.error_code for q in eng.quarantine_dlq] == ["ERR_MISSING_NATURAL_KEY"]


def test_event3_missing_or_invalid_protocol_is_quarantined_not_defaulted():
    """Hợp đồng W5 Bảng 4: protocol bắt buộc với ID 3, thuộc {TCP, UDP}; trước đây code tự điền 'TCP'."""
    for raw in ({}, {"Protocol": "icmp"}):
        eng = SilverValidatorEngine()
        assert eng.process_record(net(**raw)) is False
        assert [q.error_code for q in eng.quarantine_dlq] == ["ERR_NET_INVALID_IP_OR_PORT"]


def test_present_protocol_is_kept():
    eng = SilverValidatorEngine()
    eng.process_record(net(Protocol="udp"))
    assert eng.silver_network[0]["protocol"] == "UDP"


def test_dns_defaults_follow_w5_contract():
    """ID 22: Sysmon không ghi protocol/direction; hợp đồng W5 Bảng 4 quy định mặc định UDP/OUTBOUND (quyết định của Data)."""
    rec = {"timestamp": "2026-10-18T09:11:58.1200000Z", "sysmon_event_id": 22, "record_id": 502,
           "channel": "Microsoft-Windows-Sysmon/Operational", "hostname": "LAB-HOST-01", "process_guid": GUID,
           "raw_data": {"Image": "C:\\lab\\a.exe", "QueryName": "example.test", "QueryStatus": "0"}}
    eng = SilverValidatorEngine()
    assert eng.process_record(rec) is True
    row = eng.silver_network[0]
    assert row["protocol"] == "UDP" and row["direction"] == "OUTBOUND"
