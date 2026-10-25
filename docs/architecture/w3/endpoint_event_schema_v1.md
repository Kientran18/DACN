# Đặc Tả Kỹ Thuật: Endpoint Event Schema v1 (Silver Layer)

**Dự án:** Hệ thống Giám sát & Phát hiện Xâm nhập Điểm cuối Cục bộ (Local EDR)  
**Phiên bản:** 1.0.0  
**Tác giả:** Data Engineering Team  
**Trạng thái:** Bản đặc tả lịch sử W3; các điểm chưa tương thích đã được hiệu chỉnh bằng schema v1.1 ở W5, không mặc định đã được Cyber/Software phê duyệt  
**Căn chỉnh chuẩn:** ECS v8.11, OSSEM, Microsoft Sysmon v15+

---

## 1. Khung Bao Đóng Chung (Common Event Envelope v1)
Mọi sự kiện thu thập từ điểm cuối Windows khi chuẩn hóa vào tầng Silver (DuckDB) đều phải tuân thủ cấu trúc bao đóng chung sau đây. Khung này đảm bảo khả năng truy vết nguồn gốc, chống trùng lặp dữ liệu và bảo toàn tính toàn vẹn khi dựng chuỗi tấn công (Kill-chain / Attack graph).

| Trường Dữ Liệu | Kiểu Dữ Liệu | Bắt Buộc | Ràng Buộc / Giá Trị Mặc Định | Ý Nghĩa Kỹ Thuật & Nghiệp Vụ |
| :--- | :--- | :---: | :--- | :--- |
| `event_id` | `VARCHAR(36)` | **Có** | UUIDv5 Chuẩn | Mã định danh duy nhất có tính xác định (Deterministic), sinh từ bộ ba `(Computer, Channel, EventRecordID)`. |
| `timestamp` | `TIMESTAMP` | **Có** | ISO 8601 UTC | Thời điểm ghi nhận sự kiện tại máy trạm, ép cố định múi giờ UTC (`timezone.utc`). |
| `source` | `VARCHAR` | **Có** | `SYSMON` | Hệ con hoặc dịch vụ sinh log ban đầu trên hệ điều hành. |
| `event_type` | `VARCHAR` | **Có** | Xem Enum bên dưới | Phân loại sự kiện chuẩn hóa dùng chung cho luật phát hiện (Detection) và AI. |
| `sysmon_event_id` | `INTEGER` | **Có** | 1, 3, 5, 11, 12, 13, 14, 22, 23 | Event ID gốc trích xuất từ Windows Event Log. |
| `channel` | `VARCHAR` | Không | `Microsoft-Windows-Sysmon/Operational` | Tên kênh Windows Event Log nguồn. |
| `record_id` | `BIGINT` | **Có** | Giá trị số nguyên dương | Chỉ số bản ghi tuần tự `EventRecordID` của hệ điều hành. |
| `hostname` | `VARCHAR` | **Có** | Fallback: `LOCAL-HOST` | Định danh máy trạm phát sinh sự kiện (`Computer`). |
| `process_guid` | `VARCHAR(36)` | **Theo loại event** | UUID chuẩn (đã xóa `{}`), NULL khi event không cung cấp, ví dụ Sysmon 4/16 | GUID của tiến trình theo dõi khi có; không áp dụng cho mọi loại sự kiện. |
| `raw_data` | `JSON` | **Có** | Chuỗi JSON nguyên bản | Lưu giữ 100% dictionary `EventData` gốc phục vụ điều tra chuyên sâu và kiểm toán. |

*Danh mục chuẩn hóa `event_type`:* `PROCESS_START`, `PROCESS_TERMINATE`, `FILE_CREATE`, `FILE_DELETE`, `REGISTRY_SET_VALUE`, `REGISTRY_CREATE_KEY`, `REGISTRY_DELETE_VALUE`, `NETWORK_CONNECT`.

---

## 2. Đặc Tả 4 Nhóm Sự Kiện Trọng Yếu (Category Schemas v1)

### 2.1 Process Event Schema (Sysmon Event ID 1 & 5)
Lưu vết toàn bộ vòng đời khởi tạo và kết thúc tiến trình. Là thực thể trung tâm của cây phả hệ tấn công.

| Trường Dữ Liệu | Kiểu Dữ Liệu | Bắt Buộc | Nguồn Sysmon | Mục Đích Phục Vụ Cyber & AI |
| :--- | :--- | :---: | :--- | :--- |
| *Envelope* | *Envelope v1* | **Có** | *Header* | Kế thừa 100% khung bao đóng chung. |
| `pid` | `INTEGER` | **Có** | `ProcessId` | Định danh tiến trình tạm thời của OS tại thời điểm ghi nhận. |
| `ppid` | `INTEGER` | **Chỉ Event 1** | `ParentProcessId` | Sysmon Event 5 không có trường parent. |
| `parent_guid` | `VARCHAR(36)` | **Chỉ Event 1** | `ParentProcessGuid` | Sysmon Event 5 không có trường parent. |
| `image_path` | `VARCHAR` | **Có** | `Image` | Đường dẫn tệp nhị phân thực thi đầy đủ. |
| `command_line` | `VARCHAR` | Không | `CommandLine` | Toàn bộ cờ và đối số thực thi; dùng tính Shannon Entropy và bắt LOLBins. |
| `current_working_directory`| `VARCHAR` | Không | `CurrentDirectory` | Thư mục làm việc hiện hành khi tiến trình thực thi. |
| `user_name` | `VARCHAR` | Không | `User` | Tài khoản thực thi (`Domain\User`). |
| `integrity_level` | `VARCHAR` | Không | `IntegrityLevel` | Mức toàn vẹn Windows Token (`Low`, `Medium`, `High`, `System`). |
| `session_id` | `INTEGER` | Không | `TerminalSessionId` | ID phiên đăng nhập phiên làm việc trên máy trạm. |
| `parent_image` | `VARCHAR` | Không | `ParentImage` | Đường dẫn tệp nhị phân của tiến trình cha (phát hiện Office spawn Shell). |
| `parent_command_line`| `VARCHAR` | Không | `ParentCommandLine`| Dòng lệnh thực thi của tiến trình cha. |
| `file_sha256` | `VARCHAR(64)` | Không | `Hashes` (SHA256) | Mã băm cryptographic tra cứu IOCs tĩnh. |
| `hashes` | `JSON` | Không | `Hashes` | Toàn bộ các hash thu thập được (`sha256`, `imphash`, `md5`). |

### 2.2 File Event Schema (Sysmon Event ID 11 & 23/26)
Lưu vết can thiệp tệp tin nhạy cảm: sinh payload trong thư mục tạm, đổi tên tệp hàng loạt (Ransomware), hoặc xóa dấu vết.

| Trường Dữ Liệu | Kiểu Dữ Liệu | Bắt Buộc | Nguồn Sysmon | Mục Đích Phục Vụ Cyber & AI |
| :--- | :--- | :---: | :--- | :--- |
| *Envelope* | *Envelope v1* | **Có** | *Header* | Kế thừa 100% khung bao đóng chung. |
| `operation` | `VARCHAR` | **Có** | Mapping từ Event ID | Thao tác tệp: `FILE_CREATE`, `FILE_DELETE`. |
| `file_path` | `VARCHAR` | **Có** | `TargetFilename` | Đường dẫn tuyệt đối của tệp tin bị tác động. |
| `file_extension` | `VARCHAR` | Không | Trích xuất từ Path | Phần mở rộng tệp (`exe`, `ps1`, `dll`, `txt`). |
| `image_path` | `VARCHAR` | Không | `Image` | Tiến trình trực tiếp thực hiện hành vi can thiệp tệp. |
| `file_sha256` | `VARCHAR(64)` | Không | `Hashes` (ID 23) | Mã băm của tệp tin trước khi bị xóa (nếu có). |
| `hashes` | `JSON` | Không | `Hashes` | Dictionary chứa danh mục hash của tệp. |

### 2.3 Registry Event Schema (Sysmon Event ID 12, 13, 14)
Lưu vết can thiệp khóa cấu hình hệ thống: thiết lập Persistence qua AutoRun/RunOnce, thay đổi cấu hình bảo mật.

| Trường Dữ Liệu | Kiểu Dữ Liệu | Bắt Buộc | Nguồn Sysmon | Mục Đích Phục Vụ Cyber & AI |
| :--- | :--- | :---: | :--- | :--- |
| *Envelope* | *Envelope v1* | **Có** | *Header* | Kế thừa 100% khung bao đóng chung. |
| `operation` | `VARCHAR` | **Có** | `EventType` | Thao tác Registry: `SetValue`, `CreateKey`, `DeleteValue`. |
| `target_object` | `VARCHAR` | **Có** | `TargetObject` | Toàn bộ đường dẫn khóa/giá trị Registry bị can thiệp. |
| `hive` | `VARCHAR` | Không | Bóc tách từ Path | Nhánh Registry (`HKLM`, `HKCU`, `HKU`, `HKCR`). |
| `key_path` | `VARCHAR` | Không | Bóc tách từ Path | Đường dẫn nhánh Registry con sau khi lược bỏ Hive. |
| `value_name` | `VARCHAR` | Không | Bóc tách từ Path | Tên giá trị (Value Name) bị chỉnh sửa hoặc khởi tạo. |
| `value_type_inferred` | `VARCHAR` | Không | Suy diễn từ Details | Kiểu dữ liệu (`REG_DWORD`, `REG_QWORD`, `STRING_UNSPECIFIED`). |
| `details` | `VARCHAR` | Không | `Details` | Dữ liệu gán vào khóa Registry (`new_data_str`). |
| `image_path` | `VARCHAR` | Không | `Image` | Tiến trình thực hiện ghi đè cấu hình Registry. |

### 2.4 Network connection (Event ID 3) và DNS query (Event ID 22)
Lưu vết mở Socket và kết nối mạng: phát hiện C2 beaconing, tải tệp độc hại từ ngoài vào máy trạm.

| Trường Dữ Liệu | Kiểu Dữ Liệu | Bắt Buộc | Nguồn Sysmon | Mục Đích Phục Vụ Cyber & AI |
| :--- | :--- | :---: | :--- | :--- |
| *Envelope* | *Envelope v1* | **Có** | *Header* | Kế thừa 100% khung bao đóng chung. |
| `protocol` | `VARCHAR` | **Chỉ Event 3** | `Protocol` | DNS Event 22 không có trường Protocol/socket tuple. |
| `direction` | `VARCHAR` | **Chỉ Event 3** | `Initiated` | Không được suy diễn hướng mạng cho DNS Event 22. |
| `ip_version` | `VARCHAR` | Không | `SourceIsIpv6` | Phiên bản giao thức: `IPv4` hoặc `IPv6`. |
| `src_ip` | `VARCHAR` | **Chỉ Event 3** | `SourceIp` | NULL với DNS Event 22. |
| `src_port` | `INTEGER` | **Chỉ Event 3** | `SourcePort` | NULL với DNS Event 22. |
| `dest_ip` | `VARCHAR` | **Chỉ Event 3** | `DestinationIp` | NULL với DNS Event 22; không tự lấy từ QueryResults làm socket IP. |
| `dest_port` | `INTEGER` | **Chỉ Event 3** | `DestinationPort` | NULL với DNS Event 22. |
| `image_path` | `VARCHAR` | Không | `Image` | Tiến trình thực hiện kết nối mạng. |
| `dns_query_name` | `VARCHAR` | Không | `QueryName` (ID 22) | Tên miền phân giải trước khi mở socket. |

## 3. Ghi chú tương thích và hiệu chỉnh W3 → W5 (25/10/2026)

Đây là tài liệu baseline W3 được sửa để không xung đột với mẫu thật; **contract áp dụng cho thiết kế pipeline mới** là [Schema v1.1](../w5/schema_reconciliation_and_dictionary_v1_1.md) và [ADR 0006](../../decisions/0006_schema_v1_1_reconciliation_and_dns_support.md). Các ví dụ Event 5 và 22 xem `references/samples/raw/`. `timestamp` ưu tiên `System.TimeCreated.SystemTime`; `EventData.UtcTime` lưu riêng để điều tra lệch thời gian. Event 29 (`FILE_EXECUTABLE_DETECTED`) là loại dữ liệu bổ sung và không được gán nhầm thành Event 11.

Không suy diễn rằng `raw_data` JSON tại Silver chứa toàn bộ bản XML: raw XML đầy đủ cần bảo toàn riêng tại Bronze. Các trường tùy loại sự kiện không được ép non-null để đạt “coverage” giả.
