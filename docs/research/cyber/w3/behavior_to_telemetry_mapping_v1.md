# W03 Cyber — Updated Behavior-to-Telemetry Mapping

Issue #14. Mapping trường nguồn → dữ liệu chuẩn hóa theo `docs/architecture/w3/sysmon_raw_to_silver_mapping_v1.md`.

| Nhóm | Raw Sysmon | Silver/Collector JSON | Detection |
|---|---|---|---|
| Common | System.TimeCreated, EventRecordID, Computer | timestamp, record_id, hostname | Cửa sổ thời gian, chống trùng |
| Process | ProcessGuid, ParentProcessGuid | process_guid, data.parent_guid | Parent-child correlation |
| Process | Image, CommandLine, ParentImage | data.image_path, data.command_line, data.parent_image | DET-001/002/004/009 |
| Process | Hashes, User, IntegrityLevel | data.file_sha256, data.user_name, data.integrity_level | Context/enrichment |
| File | TargetFilename, Image, Hashes | data.file_path, data.image_path, data.file_sha256 | DET-005/010 |
| Registry | EventType, TargetObject, Details | data.operation, data.target_object, data.details | DET-003 |
| Network | DestinationIp, DestinationPort, Initiated | data.dest_ip, data.dest_port, data.direction | DET-005/006 |
| DNS | QueryName, QueryResults, QueryStatus | data.dns_query_name, data.query_results, data.query_status | DET-006 |

**Chú ý:** `command_line`, hash và user có thể NULL tùy loại event; bắt buộc ở mức rule khi sử dụng, không bắt buộc cho toàn bộ Silver. `process_guid` cũng có thể NULL với Sysmon 4/16. `event_id` (UUIDv5) khác `sysmon_event_id` (ID loại sự kiện).

## Kiểm chứng 4 tình huống từ mẫu PoC

1. **Process:** Event 1 ghi nhận PowerShell chạy executable PoC trong Temp; có ParentImage, ParentProcessGuid, CommandLine, Hashes. Đủ viết rule parent-child, chưa xác nhận PowerShell độc hại.
2. **File:** Event 11 (~09:11:53Z) → 29 (~09:11:53Z) → 1 (~09:11:55Z) → 26 (~09:11:57Z) trên executable cùng path/hash. Đủ xây dựng chuỗi DET-010 ở mức PoC.
3. **Registry:** Event 13 ghi SetValue tại HKU\\SID\\SOFTWARE\\EDR_PoC; Event 12 ghi DeleteValue/DeleteKey. Chưa có mẫu Run/RunOnce.
4. **Network:** Event 3 outbound TCP và Event 22 DNS chung ProcessGuid; QueryResults có IP tương ứng DestinationIp. Đây là correlation DNS/IP, không chứng minh C2.

## Yêu cầu triển khai

- Normalize đường dẫn Windows không phân biệt hoa/thường và xử lý dấu ngoặc kép trước khi so khớp.
- Normalize registry HKCU ↔ HKU\\SID, xử lý Run và RunOnce theo đường dẫn đầy đủ.
- DNS correlation: cùng host/process GUID, thời gian gần nhau, chuẩn hóa IPv4-mapped IPv6; chấp nhận DNS cache, nhiều IP và truy vấn không đi kèm kết nối.
- Event 3/22 trong mẫu có `UtcTime` chênh khoảng 12 giây so với `System.TimeCreated`; kiểm tra trước khi thiết lập window.
- Dữ liệu được giữ ở `raw_data` để truy vết và tái xử lý.

Nguồn mẫu: `references/samples/raw/`; manifest: `references/samples/raw/export_manifest.json`.
