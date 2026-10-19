# Đặc Tả Kỹ Thuật: Endpoint Event Schema v1 (Silver Layer)

**Dự án:** Hệ thống Giám sát & Phát hiện Xâm nhập Điểm cuối Cục bộ (Local EDR)  
**Phiên bản:** 1.0.0  
**Tác giả:** Data Engineering Team  
**Đồng thuận:** Cyber Security Team, Software Team  
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
| `process_guid` | `VARCHAR(36)` | **Có** | UUID chuẩn (đã xóa `{}`) | GUID duy nhất của tiến trình thực hiện hành vi, thay thế triệt để PID. |
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
| `ppid` | `INTEGER` | **Có** | `ParentProcessId` | Định danh tiến trình cha tạm thời của OS. |
| `parent_guid` | `VARCHAR(36)` | **Có** | `ParentProcessGuid` | GUID duy nhất của tiến trình cha, dùng dựng Process Tree đệ quy. |
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

### 2.4 Network Event Schema (Sysmon Event ID 3 & 22)
Lưu vết mở Socket và kết nối mạng: phát hiện C2 beaconing, tải tệp độc hại từ ngoài vào máy trạm.

| Trường Dữ Liệu | Kiểu Dữ Liệu | Bắt Buộc | Nguồn Sysmon | Mục Đích Phục Vụ Cyber & AI |
| :--- | :--- | :---: | :--- | :--- |
| *Envelope* | *Envelope v1* | **Có** | *Header* | Kế thừa 100% khung bao đóng chung. |
| `protocol` | `VARCHAR` | **Có** | `Protocol` | Giao thức mạng (`TCP`, `UDP`), chuẩn hóa in hoa. |
| `direction` | `VARCHAR` | **Có** | `Initiated` | Hướng kết nối: `OUTBOUND` (nếu Initiated=true), ngược lại `INBOUND`. |
| `ip_version` | `VARCHAR` | Không | `SourceIsIpv6` | Phiên bản giao thức: `IPv4` hoặc `IPv6`. |
| `src_ip` | `VARCHAR` | **Có** | `SourceIp` | Địa chỉ IP nguồn. |
| `src_port` | `INTEGER` | **Có** | `SourcePort` | Cổng dịch vụ nguồn. |
| `dest_ip` | `VARCHAR` | **Có** | `DestinationIp` | Địa chỉ IP đích liên lạc. |
| `dest_port` | `INTEGER` | **Có** | `DestinationPort` | Cổng dịch vụ đích. |
| `image_path` | `VARCHAR` | Không | `Image` | Tiến trình thực hiện kết nối mạng. |
| `dns_query_name` | `VARCHAR` | Không | `QueryName` (ID 22) | Tên miền phân giải trước khi mở socket. |