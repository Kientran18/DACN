# Ánh xạ Sysmon raw sang JSON collector và Silver dự kiến

Bản hiệu chỉnh 2026-10-19. Trạng thái chờ review. Tách rõ JSON đã chạy và adapter Silver chưa có code trong main.

## Envelope

| Raw XML | JSON collector | Silver dự kiến | Chuyển đổi |
|---|---|---|---|
| Computer, Channel, EventRecordID | event_id | event_id | UUIDv5 namespace 6f1d3c52-8a0e-4b7a-9c1e-3d5a7b9e2f10 |
| TimeCreated.SystemTime | timestamp | timestamp | JSON giữ chuỗi UTC nguồn; adapter DB mới parse timestamp |
| Hằng số | source | source | SYSMON |
| System.EventID | sysmon_event_id | sysmon_event_id | integer |
| System.Channel | channel | channel | string |
| System.EventRecordID | record_id | record_id | integer |
| System.Computer | hostname | hostname | Giữ cùng tên chuẩn; host_id ổn định cần thiết kế riêng, không dùng tên máy thay thế ngầm |
| EventData.ProcessGuid | process_guid | process_guid | Strip {} |
| EventData | raw_data | raw_data | Dictionary; giữ XML riêng để bảo toàn toàn bộ nguồn |
| EventID và EventType/Initiated | event_type | event_type | Theo schema v1 |

Không gọi namespace tùy chỉnh là uuid.NAMESPACE_DNS. Khóa UUIDv5 chỉ bảo đảm đọc lại cùng record cho cùng ID, chưa giải quyết log clear/reset hoặc clone host.

## Payload

Các cột dưới nằm trong JSON.data; khi đưa vào bảng Silver thì adapter flatten chúng. Collector chưa ghi DuckDB.

| Raw | JSON.data | Silver dự kiến | Loại/logic |
|---|---|---|---|
| ProcessId | pid | pid | ID 1/5; int |
| ParentProcessId | ppid | ppid | Chỉ ID 1; không bắt buộc ID 5 |
| ParentProcessGuid | parent_guid | parent_guid | Chỉ ID 1; strip {} |
| Image | image_path | image_path | Các loại có Image |
| CommandLine | command_line | command_line | ID 1 |
| CurrentDirectory | current_working_directory | current_working_directory | ID 1 |
| User | user_name | user_name | Collector hiện ánh xạ ID 1; loại khác giữ raw_data |
| IntegrityLevel | integrity_level | integrity_level | ID 1 |
| TerminalSessionId | session_id | session_id | ID 1; int |
| ParentImage, ParentCommandLine | parent_image, parent_command_line | Cùng tên | ID 1 |
| Hashes hoặc Hash | hashes, file_sha256 | Cùng tên | Parse key/value; thiếu SHA256 thành null |
| TargetFilename | file_path, file_extension | Cùng tên | ntpath.splitext cho đường dẫn Windows |
| IsExecutable, Archived | is_executable, archived | Cùng tên nếu cần | Chỉ khi nguồn có |
| EventID file | Không có operation trong data | operation nếu bảng cần | Adapter lấy top-level event_type; chưa hiện thực |
| Registry EventType | operation | operation | Giữ SetValue/CreateKey/DeleteKey/DeleteValue/RenameKey |
| TargetObject | target_object, hive, key_path, value_name | Cùng tên | value_name chỉ SetValue/DeleteValue |
| Details | details, new_data_str | Cùng tên nếu cần | new_data_str chỉ SetValue |
| Details | value_type_inferred | value_type_inferred | DWORD/QWORD/Binary hoặc STRING_UNSPECIFIED |
| Protocol | protocol | protocol | ID 3; upper |
| Initiated | direction | direction | ID 3; true OUTBOUND, false INBOUND |
| SourceIp, SourcePort | src_ip, src_port | src_ip, src_port | ID 3; port int |
| DestinationIp, DestinationPort | dest_ip, dest_port | dest_ip, dest_port | ID 3; port int |
| DestinationIsIpv6 | ip_version | ip_version | ID 3; IPv6/IPv4 |
| QueryName | dns_query_name | dns_query_name | ID 22 |
| QueryStatus, QueryResults | query_status, query_results | Cùng tên | ID 22 |

## Null và validation

Theo [schema](endpoint_event_schema_v1.md), required phụ thuộc Event ID. Không áp PPID cho ProcessTerminate hoặc socket fields cho DNS. Giá trị không có không được thay bằng dữ liệu giả; missing size dùng null. Các nhánh 4/16 dùng schema quản trị riêng, không bắt buộc process_guid.

## Tình trạng kiểm chứng

Bốn XML ID 1/11/13/3 tái tạo được đúng bốn JSON đã commit (3/2/2/1). ID 5/22 cần kiểm tra payload riêng. Việc parse/normalize mẫu không chứng minh validator Pydantic, DuckDB, pipeline liên tục hoặc Python live mode đã chạy. Tên cũ host_id/source_ip/source_port chỉ được dùng qua adapter có tên và contract rõ ràng.
