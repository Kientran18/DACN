# Endpoint Event Schema v1

Bản hiệu chỉnh 2026-10-19 đối chiếu collector và mẫu thật trong references/samples. Trạng thái: đề xuất hiệu chỉnh chờ Cyber/Data/Software review. Không tuyên bố Pydantic/DuckDB đã hiện thực schema này.

## 1 Khung JSON của collector

Collector xuất envelope ở top level và payload theo loại sự kiện trong `data`. Tên chuẩn ở giao diện JSON là `hostname`, `src_ip`, `src_port`. Nếu Silver dùng tên khác phải có adapter được đặc tả; không ngầm coi hai cấu trúc là giống nhau.

| Trường | Kiểu JSON | Bắt buộc trong bốn nhóm chính | Nguồn và quy tắc |
|---|---|---|---|
| event_id | string UUID | Có | UUIDv5 từ Computer, Channel, EventRecordID; namespace trong collector |
| timestamp | string ISO 8601 UTC | Có | System.TimeCreated.SystemTime; giữ độ chính xác nguồn |
| source | string | Có | SYSMON |
| event_type | string | Có | Theo bảng Event ID bên dưới |
| sysmon_event_id | integer | Có | System.EventID |
| channel | string | Có | System.Channel |
| record_id | integer | Có | System.EventRecordID |
| hostname | string | Có | System.Computer |
| process_guid | string hoặc null | Có giá trị với các mẫu process/file/registry/network hiện có | Strip dấu ngoặc; không bắt buộc cho sự kiện Sysmon quản trị 4/16 |
| data | object | Có | Payload được mapping |
| raw_data | object | Có | Dictionary EventData gốc, không phải toàn bộ XML |

Đây là contract dữ liệu hợp lệ dự kiến. Parser hiện cho phép một số field nguồn thiếu thành null; không phải validator schema nghiêm ngặt. Không tự sinh host fallback hoặc GUID giả. Bản ghi không đủ khóa truy vết cần được đánh dấu lỗi ở tầng validation tương lai.

UTC không sửa được đồng hồ nguồn sai; cần giữ riêng vấn đề clock drift. UUIDv5 hiện ổn định khi đọc lại cùng bản ghi, nhưng có thể va chạm định danh khi log bị clear/reset, host được đổi tên/clone; chưa có log-generation/agent identity để xử lý các trường hợp này.

## 2 Event ID và loại chuẩn

| ID | event_type | Phạm vi |
|---|---|---|
| 1 | PROCESS_START | Chính |
| 5 | PROCESS_TERMINATE | Chính |
| 11 | FILE_CREATE | Chính |
| 23, 26 | FILE_DELETE | Chính; config/mẫu hiện tại dùng 26 |
| 12 | REGISTRY_CREATE_KEY / REGISTRY_DELETE_KEY / REGISTRY_DELETE_VALUE | Theo EventType |
| 13 | REGISTRY_SET_VALUE | Chính |
| 14 | REGISTRY_RENAME_KEY | Có mapping, chưa có mẫu thật trong bộ hiện tại |
| 3 | NETWORK_CONNECT / NETWORK_ACCEPT | Theo Initiated |
| 22 | DNS_QUERY | Payload DNS riêng |
| 15 | FILE_STREAM_CREATE | Mở rộng, chưa có mẫu thật trong bộ hiện tại |
| 29 | FILE_EXECUTABLE_DETECTED | Mở rộng; đã có XML |
| 4, 16 | SYSMON_SERVICE_STATE / SYSMON_CONFIG_CHANGE | Quản trị; không ép schema bốn nhóm |
| Khác | SYSMON_EVENT_<ID> hoặc REGISTRY_EVENT | Fallback của collector; chưa xác nhận hỗ trợ ở Silver |

## 3 Process payload

| Trường data | Kiểu | ID 1 | ID 5 | Nguồn |
|---|---|---|---|---|
| pid | integer | Bắt buộc | Bắt buộc | ProcessId |
| image_path | string | Bắt buộc | Bắt buộc | Image |
| ppid | integer | Bắt buộc khi nguồn có; null cần đánh dấu thiếu | Không yêu cầu | ParentProcessId |
| parent_guid | string | Bắt buộc khi nguồn có; null cần đánh dấu thiếu | Không yêu cầu | ParentProcessGuid |
| command_line | string hoặc null | Tùy chọn | Không yêu cầu | CommandLine |
| current_working_directory | string hoặc null | Tùy chọn | Không yêu cầu | CurrentDirectory |
| user_name, integrity_level | string hoặc null | Tùy chọn | Không được collector ánh xạ | User, IntegrityLevel |
| session_id | integer hoặc null | Tùy chọn | Không yêu cầu | TerminalSessionId |
| parent_image, parent_command_line | string hoặc null | Tùy chọn | Không yêu cầu | ParentImage, ParentCommandLine |
| hashes | object | Tùy chọn | Không yêu cầu | Parse Hashes |
| file_sha256 | string hoặc null | Tùy chọn | Không yêu cầu | hashes.sha256 |

ID 5 là bản ghi kết thúc riêng; liên kết về ID 1 qua hostname/process_guid. Không giả định ID 5 có PPID, parent GUID, exit code. Nếu dựng bảng vòng đời thì end_time là dữ liệu dẫn xuất, chưa được collector sinh.

## 4 File payload

| Trường data | Kiểu | Yêu cầu | Nguồn |
|---|---|---|---|
| file_path | string | Bắt buộc | TargetFilename |
| file_extension | string hoặc null | Tùy chọn | ntpath.splitext |
| image_path | string hoặc null | Tùy chọn | Image |
| hashes | object | Tùy chọn | Hashes hoặc Hash |
| file_sha256 | string hoặc null | Tùy chọn | hashes.sha256 |
| is_executable, archived | boolean | Chỉ khi nguồn có | IsExecutable, Archived |

Thao tác nằm ở top-level event_type. Collector hiện không xuất data.operation cho File; nếu Silver cần thì adapter lấy từ event_type. ID 11 không có hash/size và không cung cấp đầy đủ write-in-place/rename; không dùng làm bằng chứng mọi thao tác ghi/đổi tên. Không gán size thiếu bằng 0 vì sẽ nhầm với file rỗng.

## 5 Registry payload

| Trường data | Kiểu | Yêu cầu | Nguồn |
|---|---|---|---|
| operation | string | Bắt buộc | EventType |
| target_object | string | Bắt buộc | TargetObject |
| hive, key_path | string hoặc null | Tùy chọn | Tách TargetObject |
| value_name | string hoặc null | Chỉ SetValue/DeleteValue | Thành phần cuối đường dẫn |
| details | string | Tùy chọn, có thể rỗng | Details |
| value_type_inferred | string | Chỉ SetValue | Heuristic từ Details |
| new_data_str | string | Chỉ SetValue | Bản sao Details |
| image_path | string hoặc null | Tùy chọn | Image |

DeleteKey/CreateKey không bắt buộc value_name; RenameKey chưa có payload chuẩn hóa NewName, giữ ở raw_data. STRING_UNSPECIFIED không phân biệt REG_SZ, REG_EXPAND_SZ, REG_MULTI_SZ; đây là suy diễn, không phải native registry type.

## 6 Network và DNS payload

| Trường data | Kiểu | ID 3 | ID 22 |
|---|---|---|---|
| protocol | string | Bắt buộc, in hoa | Không yêu cầu |
| direction | string | Bắt buộc, OUTBOUND/INBOUND | Không yêu cầu |
| src_ip, dest_ip | string | Bắt buộc | Không yêu cầu |
| src_port, dest_port | integer | Bắt buộc | Không yêu cầu |
| ip_version | string | Tùy chọn, từ DestinationIsIpv6 | Không yêu cầu |
| image_path | string hoặc null | Tùy chọn | Tùy chọn |
| dns_query_name | string | Không yêu cầu | Bắt buộc |
| query_status, query_results | string hoặc null | Không yêu cầu | Tùy chọn |

DNS không có socket IP/port/protocol của Event 3. Correlation qua process_guid, hostname, thời gian và kết quả DNS chỉ là phép đối chiếu; collector chưa join hai sự kiện. Không suy diễn HTTPS nội dung, bytes, duration hoặc kết luận C2 từ một kết nối.

## 7 Bằng chứng và giới hạn

Mẫu thật: [raw](../../../references/samples/raw), [JSON](../../../references/samples/json). Bốn JSON hiện chỉ chứa ID 1/11/13/3; XML có thêm ID 5/12/22/26/29/4/16. [Mapping](sysmon_raw_to_silver_mapping_v1.md) quy định adapter dự kiến. Review theo [hồ sơ tuần 1–3](../../project/week-01-03-review-and-ownership.md).
