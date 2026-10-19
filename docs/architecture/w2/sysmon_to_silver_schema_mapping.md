# Sysmon to Silver Schema Integration

## 1. Tổng quan
Hệ thống sử dụng Microsoft Sysmon (v15+) làm Collector chính trên Windows. Tài liệu này đặc tả cách ánh xạ (mapping) các Event ID của Sysmon vào 8 nhóm Dữ liệu (Data Groups) được định nghĩa trong `edr_data_requirements_architecture.md`.

## 2. Nguyên tắc Định danh Duy nhất (Primary Keys)
Sysmon sinh ra trường `ProcessGuid` (ví dụ: `{A1B2C3D4-1234-5678-90AB-CDEF12345678}`). 
Trường này sẽ được parse, loại bỏ ngoặc nhọn `{}` và lưu vào trường `process_guid` (UUIDv4) chuẩn của Silver Schema để giải quyết bài toán PID Reuse của Windows.

## 3. Ma trận Ánh xạ (Sysmon to Silver Table)

| Sysmon Event ID | Tên Event Sysmon | Silver Table Đích (DuckDB) | Payload mapping nổi bật |
|---|---|---|---|
| **Event ID 1** | Process creation | `silver_process_events` | `ProcessGuid` -> `process_guid`, `ParentProcessGuid` -> `parent_guid`, `CommandLine` -> `command_line`, `Hashes` -> parse lấy `sha256`. |
| **Event ID 5** | Process terminated | `silver_process_events` | Cập nhật `end_time` cho bản ghi process đã có. |
| **Event ID 3** | Network connection | `silver_network_events` | `Protocol`, `SourceIp`, `SourcePort`, `DestinationIp`, `DestinationPort`. |
| **Event ID 11** | FileCreate | `silver_file_events` | `operation` = 'CREATE', `TargetFilename` -> `file_path`. |
| **Event ID 23** | FileDelete | `silver_file_events` | `operation` = 'DELETE', tính toán entropy trước khi xóa. |
| **Event ID 12, 13** | RegistryEvent | `silver_registry_events` | `EventType` -> `operation`, `TargetObject` -> `target_object`, `Details` -> `details`. |
| **Event ID 22** | DNSEvent | `silver_network_events` | `QueryName` -> `dns_query_name`, làm giàu (enrich) cho Event ID 3. |

## 4. Xử lý các trường dữ liệu bị thiếu (Data Gaps)
So với chuẩn lý tưởng, Sysmon có một số giới hạn cần xử lý tại tầng Data Pipeline:
1. **Network Direction (INBOUND/OUTBOUND):** Sysmon Event ID 3 có trường `Initiated`. Nếu `Initiated = true` $\rightarrow$ `OUTBOUND`. Nếu `Initiated = false` $\rightarrow$ `INBOUND`.
2. **Entropy File:** Sysmon không tự tính entropy. Data Pipeline sẽ không lấy được `chunk_entropy` tại thời điểm sinh event, trường này sẽ set `NULL` hoặc phải mở luồng thread phụ đọc file cục bộ (có nguy cơ race condition nếu file bị xóa).
3. **Registry Value Type:** Sysmon không cung cấp trực tiếp `REG_SZ` hay `REG_DWORD`. Tầng Pydantic sẽ fallback về kiểu chuỗi (String) dạng thô.