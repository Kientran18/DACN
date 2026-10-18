# Ma Trận Ánh Xạ Dữ Liệu: Sysmon Raw to Silver Layer v1

Tài liệu đặc tả chi tiết logic chuyển đổi (ETL/ELT) từ các trường raw XML/JSON thu thập bởi Sysmon Collector sang các bảng chuẩn hóa trong DuckDB Silver Layer.

---

## 1. Quy Tắc Tiền Xử Lý Chung (Global Normalization Rules)
1. **Khóa Định Danh `event_id`:** Sử dụng thuật toán `uuid.uuid5` với Namespace DNS cố định:
   ```python
   EVENT_ID_NAMESPACE = uuid.UUID("6f1d3c52-8a0e-4b7a-9c1e-3d5a7b9e2f10")
   key = f"{Computer}|{Channel}|{EventRecordID}"
   event_id = str(uuid.uuid5(EVENT_ID_NAMESPACE, key))
   ```

2. **Loại Bỏ Ngoặc Nhọn GUID:** Tất cả các trường GUID từ Sysmon (`ProcessGuid`, `ParentProcessGuid`) có dạng `{GUID}` phải chạy qua hàm chuẩn hóa:
    ```python
    def strip_guid(val: str) -> str:
        return val.strip().strip("{}") if val else ""
    ```

3. **Múi Giờ UTC Chuẩn:** Trường `TimeCreated.SystemTime` hoặc `UtcTime` được chuyển đổi thành đối tượng Datetime gắn kèm thông tin múi giờ UTC (`tzinfo=timezone.utc`).

---

## 2. Ma Trận Ánh Xạ Chi Tiết Theo Loại Sự Kiện 

| Bảng Silver Đích | Cột Silver Đích | Trường Raw Sysmon Nguồn | Logic Biến Đổi & Chuẩn Hóa |
| :--- | :--- | :--- | :--- |
| **Tất cả bảng** | `event_id` | `Computer`, `Channel`, `EventRecordID` | Sinh Deterministic UUIDv5 |
| **Tất cả bảng** | `timestamp` | `System.TimeCreated.SystemTime` | Parse ISO 8601 UTC string -> Native Timestamp |
| **Tất cả bảng** | `source` | *Hằng số* | Gán giá trị cứng: `'SYSMON'` |
| **Tất cả bảng** | `sysmon_event_id` | `System.EventID` | Ép kiểu `int(EventID)` |
| **Tất cả bảng** | `host_id` | `System.Computer` | Lấy nguyên bản chuỗi máy trạm |
| **Tất cả bảng** | `process_guid` | `EventData.ProcessGuid` | `strip_guid(ProcessGuid)` |
| **Tất cả bảng** | `raw_data` | `EventData` | Serialize toàn bộ dictionary sang chuỗi JSON |
| **silver_process_events** | `event_type` | `System.EventID` | `1` -> `'PROCESS_START'`, `5` -> `'PROCESS_TERMINATE'` |
| **silver_process_events** | `pid`, `ppid` | `ProcessId`, `ParentProcessId` | Ép kiểu `int` |
| **silver_process_events** | `parent_guid` | `EventData.ParentProcessGuid` | `strip_guid(ParentProcessGuid)` |
| **silver_process_events** | `image_path` | `EventData.Image` | Giữ nguyên đường dẫn tệp nhị phân |
| **silver_process_events** | `command_line` | `EventData.CommandLine` | Giữ nguyên format đối số (UTF-8 an toàn) |
| **silver_process_events** | `file_sha256` | `EventData.Hashes` | Regex tìm kiếm `SHA256=([A-Fa-f0-9]{64})` |
| **silver_process_events** | `parent_image` | `EventData.ParentImage` | Giữ nguyên đường dẫn tiến trình cha |
| **silver_file_events** | `event_type` | `System.EventID` | `11` -> `'FILE_CREATE'`, `23/26` -> `'FILE_DELETE'` |
| **silver_file_events** | `file_path` | `EventData.TargetFilename` | Giữ nguyên đường dẫn tệp đích |
| **silver_file_events** | `file_extension` | `EventData.TargetFilename` | `Path(TargetFilename).suffix.lstrip(".").lower()` |
| **silver_file_events** | `file_sha256` | `EventData.Hashes` | Trích xuất băm SHA256 (sự kiện xóa file ID 23) |
| **silver_registry_events** | `operation` | `EventData.EventType` | `SetValue`, `CreateKey`, `DeleteKey`, `DeleteValue` |
| **silver_registry_events** | `target_object` | `EventData.TargetObject` | Giữ nguyên toàn bộ đường dẫn Registry |
| **silver_registry_events** | `hive` | `EventData.TargetObject` | Lấy phần tử đầu tiên sau split `\`: `parts[0]` |
| **silver_registry_events** | `value_name` | `EventData.TargetObject` | Lấy phần tử cuối sau split nếu operation là SetValue |
| **silver_registry_events** | `value_type_inferred` | `EventData.Details` | Nếu `startswith("DWORD")` -> `'REG_DWORD'`; nếu `startswith("Binary")` -> `'REG_BINARY'` |
| **silver_registry_events** | `details` | `EventData.Details` | Giữ nguyên chuỗi thiết lập cấu hình |
| **silver_network_events** | `protocol` | `EventData.Protocol` | In hoa chuỗi giao thức: `.upper()` |
| **silver_network_events** | `direction` | `EventData.Initiated` | `'OUTBOUND'` nếu `Initiated.lower() == 'true'`, ngược lại `'INBOUND'` |
| **silver_network_events** | `source_ip`, `dest_ip` | `SourceIp`, `DestinationIp` | Giữ nguyên chuỗi địa chỉ IP |
| **silver_network_events** | `source_port`, `dest_port` | `SourcePort`, `DestinationPort` | Ép kiểu `int` |