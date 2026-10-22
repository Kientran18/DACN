#!/usr/bin/env python3
"""
Unit & Integration Test Suite cho Thiết kế Data Pipeline Tuần 5 (Issue #27).
Kiểm chứng toàn diện:
1. Khóa xác định UUIDv5 khớp 100% với mẫu thật Tuần 3 (DESKTOP-IDEMGQU).
2. Kiểm định Positive Samples trên cả 4 nhóm sự kiện (Process, File, Registry, Network).
3. Kiểm định Edge Cases cho DNS Event ID 22, Process Terminate ID 5, File Stream Hash ID 15.
4. Tính Idempotent và Deduplication khi nạp lặp lại bản ghi.
5. Cô lập lỗi vào Quarantine DLQ (Negative Samples) và tuân thủ Zero Data Fabrication.
6. Phát hiện độ lệch thời gian giữa SystemTime và UtcTime (Time Skew Warning).
"""

from __future__ import annotations

import json
import sys
import unittest
from pathlib import Path

# Đảm bảo import được module từ thư mục src/pipeline
PROJECT_ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(PROJECT_ROOT))
sys.path.insert(0, str(PROJECT_ROOT / "src" / "pipeline"))

from validator_poc import (  # type: ignore
    SilverValidatorEngine,
    calculate_shannon_entropy,
    generate_deterministic_event_id,
    infer_registry_value_type,
    strip_guid,
)


class TestDataPipelineW05(unittest.TestCase):
    """Bộ kiểm thử nghiệm thu hợp đồng dữ liệu và bộ Validator Tuần 5."""

    def setUp(self) -> None:
        self.engine = SilverValidatorEngine()

    def test_01_deterministic_uuidv5_matches_w3_real_samples(self) -> None:
        """Kiểm tra hàm sinh UUIDv5 khớp chính xác tuyệt đối với 4 tệp mẫu thật Tuần 3."""
        channel = "Microsoft-Windows-Sysmon/Operational"
        host = "DESKTOP-IDEMGQU"

        expected_pairs = [
            (185, "5b452d31-566e-59b4-9929-cbb8377ca690"),  # process.json
            (184, "2ef59e9e-cff1-525d-a58e-aecae054b171"),  # process.json
            (173, "73f999eb-369c-51e5-9ad3-72ed3755d856"),  # process.json
            (182, "cab6af4d-a862-5e4c-bfb5-42b5b46081cd"),  # file.json
            (180, "ab310dc5-7581-50ec-8b83-8dccc56d3f13"),  # file.json
            (191, "a95f919d-adca-5eb1-9560-f0f2b393c097"),  # registry.json
            (190, "36216620-092e-52be-afcd-69ac05b4ef61"),  # registry.json
            (194, "7536126d-407c-500d-a9b1-c9d7cec9f7df"),  # network.json
        ]
        for record_id, expected_uuid in expected_pairs:
            actual_uuid = generate_deterministic_event_id(host, channel, record_id)
            self.assertEqual(
                actual_uuid,
                expected_uuid,
                f"Mismatch UUIDv5 cho record_id={record_id}",
            )

    def test_02_strip_guid_and_registry_heuristics(self) -> None:
        """Kiểm tra chuẩn hóa GUID xóa ngoặc nhọn và suy diễn kiểu dữ liệu Registry."""
        self.assertEqual(
            strip_guid("{43F71EC6-8D5B-6AD4-2601-000000000400}"),
            "43f71ec6-8d5b-6ad4-2601-000000000400",
        )
        self.assertEqual(infer_registry_value_type("DWORD (0x00000001)"), "REG_DWORD")
        self.assertEqual(infer_registry_value_type("QWORD (0x0000000000000001)"), "REG_QWORD")
        self.assertEqual(infer_registry_value_type("Binary Data"), "REG_BINARY")
        self.assertEqual(infer_registry_value_type("EDR_POC_20261018_021142"), "STRING_UNSPECIFIED")

    def test_03_positive_event_id_22_dns_and_id_05_terminate(self) -> None:
        """Kiểm tra sự kiện DNS (Event ID 22) và Process Terminate (ID 5) không bị rơi vào Quarantine."""
        dns_event = {
            "timestamp": "2026-10-18T09:11:58.1200000Z",
            "source": "SYSMON",
            "event_type": "DNS_QUERY",
            "sysmon_event_id": 22,
            "channel": "Microsoft-Windows-Sysmon/Operational",
            "record_id": 193,
            "hostname": "DESKTOP-IDEMGQU",
            "process_guid": "{43f71ec6-8d48-6ad4-1c01-000000000400}",
            "raw_data": {
                "RuleName": "network",
                "UtcTime": "2026-10-18 09:11:58.115",
                "ProcessGuid": "{43f71ec6-8d48-6ad4-1c01-000000000400}",
                "ProcessId": "1616",
                "QueryName": "cloudflare.com",
                "QueryStatus": "0",
                "QueryResults": "::ffff:172.66.147.243;",
                "Image": "C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe",
            },
        }
        proc_term_event = {
            "timestamp": "2026-10-18T09:12:01.5000000Z",
            "source": "SYSMON",
            "event_type": "PROCESS_TERMINATE",
            "sysmon_event_id": 5,
            "channel": "Microsoft-Windows-Sysmon/Operational",
            "record_id": 195,
            "hostname": "DESKTOP-IDEMGQU",
            "process_guid": "{43f71ec6-8d5b-6ad4-2501-000000000400}",
            "raw_data": {
                "UtcTime": "2026-10-18 09:12:01.495",
                "ProcessGuid": "{43f71ec6-8d5b-6ad4-2501-000000000400}",
                "ProcessId": "4648",
                "Image": "C:\\Users\\Trankien\\AppData\\Local\\Temp\\edr_poc\\EDR_POC_drop.exe",
            },
        }

        self.assertTrue(self.engine.process_record(dns_event, "test_dns_id22"))
        self.assertTrue(self.engine.process_record(proc_term_event, "test_proc_id5"))
        self.assertEqual(len(self.engine.silver_network), 1)
        self.assertEqual(self.engine.silver_network[0]["dns_query_name"], "cloudflare.com")
        self.assertIsNone(self.engine.silver_network[0]["dest_ip"])
        self.assertEqual(len(self.engine.silver_process), 1)
        self.assertIsNone(self.engine.silver_process[0]["parent_guid"])
        self.assertEqual(self.engine.metrics.quarantined_count, 0)

    def test_04_idempotent_deduplication_on_replay(self) -> None:
        """Kiểm tra nạp lặp lại cùng một sự kiện sẽ bị chặn bởi cơ chế Deduplication UUIDv5."""
        sample_file_event = {
            "timestamp": "2026-10-18T09:11:53.2778558Z",
            "source": "SYSMON",
            "event_type": "FILE_CREATE",
            "sysmon_event_id": 11,
            "channel": "Microsoft-Windows-Sysmon/Operational",
            "record_id": 182,
            "hostname": "DESKTOP-IDEMGQU",
            "process_guid": "43f71ec6-8d48-6ad4-1c01-000000000400",
            "raw_data": {
                "RuleName": "file",
                "UtcTime": "2026-10-18 09:11:53.265",
                "ProcessGuid": "{43f71ec6-8d48-6ad4-1c01-000000000400}",
                "ProcessId": "1616",
                "Image": "C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe",
                "TargetFilename": "C:\\Users\\Trankien\\AppData\\Local\\Temp\\edr_poc\\drop.exe",
            },
        }

        first_insert = self.engine.process_record(sample_file_event, "batch_1")
        second_insert = self.engine.process_record(sample_file_event, "batch_1_replay")

        self.assertTrue(first_insert)
        self.assertFalse(second_insert)
        self.assertEqual(len(self.engine.silver_file), 1)
        self.assertEqual(self.engine.metrics.duplicates_dropped, 1)
        self.assertEqual(self.engine.silver_file[0]["operation"], "FILE_CREATE")

    def test_05_negative_samples_routed_to_quarantine_dlq(self) -> None:
        """Kiểm tra các bản ghi lỗi có nhãn bị cô lập vào Quarantine với đúng error_code."""
        jsonl_path = PROJECT_ROOT / "references" / "samples" / "w5_negative_and_edge_samples.jsonl"
        if jsonl_path.exists():
            lines = jsonl_path.read_text(encoding="utf-8").splitlines()
            for line in lines:
                if not line.strip():
                    continue
                rec = json.loads(line)
                tc_id = rec.get("test_case_id", "unknown")
                expected_err = rec.get("expected_error_code")
                ok = self.engine.process_record(rec, source_ref=tc_id)
                if expected_err is None:
                    self.assertTrue(ok, f"Test case {tc_id} lẽ ra phải PASS")
                else:
                    self.assertFalse(ok, f"Test case {tc_id} lẽ ra phải bị QUARANTINE")
                    last_q = self.engine.quarantine_dlq[-1]
                    self.assertEqual(
                        last_q.error_code,
                        expected_err,
                        f"Sai mã lỗi Quarantine cho {tc_id}",
                    )
        else:
            # Fallback nếu chạy độc lập không có file trên đĩa
            bad_rec = {
                "timestamp": "2026-10-18T09:12:00Z",
                "sysmon_event_id": 1,
                "record_id": 90001,
                "hostname": "DESKTOP-IDEMGQU",
                "process_guid": "",
                "raw_data": {"ProcessId": "4000", "Image": "cmd.exe"},
            }
            self.assertFalse(self.engine.process_record(bad_rec, "fallback_neg"))
            self.assertEqual(self.engine.quarantine_dlq[-1].error_code, "ERR_MISSING_PROCESS_GUID")

    def test_06_time_skew_warning_and_shannon_entropy(self) -> None:
        """Kiểm tra phát hiện độ lệch UtcTime (12.38s trên record 194) và tính Shannon Entropy."""
        net_record_194 = {
            "timestamp": "2026-10-18T09:11:59.4649146Z",
            "source": "SYSMON",
            "event_type": "NETWORK_CONNECT",
            "sysmon_event_id": 3,
            "channel": "Microsoft-Windows-Sysmon/Operational",
            "record_id": 194,
            "hostname": "DESKTOP-IDEMGQU",
            "process_guid": "43f71ec6-8d48-6ad4-1c01-000000000400",
            "raw_data": {
                "UtcTime": "2026-10-18 09:12:11.850",
                "ProcessGuid": "{43f71ec6-8d48-6ad4-1c01-000000000400}",
                "ProcessId": "1616",
                "Image": "C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe",
                "Protocol": "tcp",
                "Initiated": "true",
                "SourceIsIpv6": "false",
                "SourceIp": "10.0.2.15",
                "SourcePort": "49904",
                "DestinationIp": "172.66.147.243",
                "DestinationPort": "443",
            },
        }
        self.assertTrue(self.engine.process_record(net_record_194, "network.json#194"))
        self.assertEqual(self.engine.metrics.time_skew_warnings, 1)

        normal_cmd = "\\??\\C:\\Windows\\system32\\conhost.exe 0xffffffff -ForceV1"
        encoded_cmd = (
            "powershell.exe -NoP -NonI -W Hidden -Enc "
            "SQBFAFgAIAAoAE4AZQB3AC0ATwBiAGoAZQBjAHQAIABOAGUAdAAuAFcAZQBiAEMAbABpAGUAbgB0ACkA"
        )
        self.assertLess(calculate_shannon_entropy(normal_cmd), 4.5)
        self.assertGreater(calculate_shannon_entropy(encoded_cmd), 5.0)


if __name__ == "__main__":
    unittest.main(verbosity=2)