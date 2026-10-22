# Rà Soát Bất Nhất Schema Tuần 3, Đề Xuất Schema v1.1 & Từ Điển Dữ Liệu Cập Nhật

**Dự án:** Hệ thống Giám sát & Phát hiện Xâm nhập Điểm cuối Cục bộ (Local EDR)  
**Issue tham chiếu:** `[W05][Data] Thiết kế Bronze/Silver/Gold, schema, chất lượng và lineage dữ liệu #27`  
**Người thực hiện:** Huỳnh Hữu Nhật (Data Engineer Lead)  
**Tài liệu đầu vào rà soát:**  
1. `docs/architecture/w3/endpoint_event_schema_v1.md`  
2. `docs/architecture/w3/sysmon_raw_to_silver_mapping_v1.md`  
3. `docs/architecture/w3/data_dictionary_and_quality_notes_v1.md`  
4. Bộ mẫu thực nghiệm: `process.json`, `file.json`, `registry.json`, `network.json`, `poc_run_20261018_021142.json`, `sysmon-config.xml`  
**Phiên bản:** 1.1.0 | **Ngày cập nhật:** 21/10/2026 (Tuần 5)

---

## 1. Báo Cáo Rà Soát Mâu Thuẫn & Khoảng Trống Giữa Tài Liệu W03 Và Mẫu Thật

Thay vì âm thầm chỉnh sửa, mục này ghi nhận đầy đủ **8 điểm bất nhất hoặc khoảng trống dữ liệu (Data Gaps)** được phát hiện khi đối chiếu chéo giữa 3 tài liệu thiết kế Tuần 3 với 6 tệp dữ liệu thực nghiệm thu thập từ máy trạm `DESKTOP-IDEMGQU`:

| Mã Vấn Đề | Hạng Mục / Trường Dữ Liệu | Trạng Thái Trong `endpoint_event_schema_v1.md` | Trạng Thái Trong `sysmon_raw_to_silver_mapping_v1.md` | Thực Tế Trong Mẫu JSON W03 & `sysmon-config.xml` | Chủ Sở Hữu Xử Lý | Quyết Định Chuẩn Hóa Trong Schema v1.1 |
| :---: | :--- | :--- | :--- | :--- | :---: | :--- |
| **INC-01** | **Tên trường định danh máy trạm** (`hostname` vs `host_id`) | Đặt tên cột là **`hostname`** (Fallback: `LOCAL-HOST`). | Lại ghi tên cột đích là **`host_id`** (ánh xạ từ `System.Computer`). | Cả 4 tệp JSON (`process.json`, `file.json`,...) đều xuất khóa là **`"hostname": "DESKTOP-IDEMGQU"`**. | Data & Software | Thống nhất sử dụng tên cột **`hostname`** xuyên suốt Bronze/Silver/Gold để khớp 100% với code Collector hiện hành. |
| **INC-02** | **Tên trường IP và Port nguồn** (`src_ip` vs `source_ip`) | Đặt tên là **`src_ip`** và **`src_port`** (đi cặp với `dest_ip`, `dest_port`). | Lại ghi cột đích là **`source_ip`** và **`source_port`**. | Trong `network.json` (`record_id: 194`), dữ liệu thực tế xuất ra là **`"src_ip": "10.0.2.15"`** và **`"src_port": 49904`**. | Data & Cyber | Thống nhất giữ chuẩn **`src_ip`**, **`src_port`**, **`dest_ip`**, **`dest_port`**; cập nhật lại bảng Mapping v1.1. |
| **INC-03** | **Cấu trúc JSON lồng (`data`) vs Bảng phẳng (Flat Table)** | Mô tả các bảng Silver dưới dạng bảng quan hệ phẳng (kế thừa Envelope). | Mô tả ánh xạ thẳng từ Sysmon Raw vào các cột bảng DuckDB. | Trong 4 tệp JSON mẫu W03, các trường đặc thù được bọc trong một object con **`"data": { ... }`** tách biệt với Envelope. | Data & Software | Định nghĩa rõ: Định dạng có khóa `"data": {...}` là **Collector Interchange JSON**, còn khi nạp vào DuckDB Silver sẽ được **làm phẳng (Flattened)** thành cột vật lý. |
| **INC-04** | **Thiếu trường `operation` trong `file.json`** | Quy định cột **`operation`** (`FILE_CREATE`, `FILE_DELETE`) là **Bắt buộc (`Có`)** trong File Schema. | Không ánh xạ cột `operation` cho bảng `silver_file_events` (chỉ ánh xạ `event_type`). | Trong `file.json` (`record_id: 180, 182`), bên trong `"data"` **không có trường `operation`**, chỉ có `"event_type": "FILE_CREATE"` ở cấp Envelope. | Data | Tại bước nạp Silver, nếu `data.operation` bị khuyết, pipeline tự động suy diễn an toàn từ `event_type` (hoặc `sysmon_event_id`) sang cột `operation`. |
| **INC-05** | **Trường thừa `new_data_str` trong `registry.json`** | Chỉ liệt kê cột **`details`** (trong phần mô tả có ghi chú chữ `new_data_str`). | Chỉ ánh xạ `EventData.Details` vào cột **`details`**. | Trong `registry.json` (`record_id: 190, 191`), object `"data"` chứa cả **`"details"`** lẫn **`"new_data_str"`** với giá trị giống hệt nhau. | Data & Software | Trong bảng DuckDB `silver_registry_events`, chỉ giữ duy nhất cột vật lý **`details`** để tránh dư thừa dữ liệu; bộ nạp Silver chấp nhận cả 2 khóa từ Collector. |
| **INC-06** | **Độ lệch thời gian giữa `SystemTime` và `UtcTime`** | Chỉ lưu 1 cột `timestamp` duy nhất. | Ghi nhận lấy từ `System.TimeCreated.SystemTime` hoặc `UtcTime`. | Trong `network.json` (`record_id: 194`), `timestamp` (`SystemTime`) là **`09:11:59.4649146Z`** nhưng `raw_data.UtcTime` lại là **`09:12:11.850`** (lệch $12.38\text{ s}$)! Ở `process.json` (`185`), lệch $44.8\text{ ms}$. | Data & Cyber | Giữ `timestamp` (`SystemTime`) làm trục thời gian chuẩn vì có độ phân giải $100\text{ ns}$, đồng thời bổ sung cột **`event_utc_time`** (`UtcTime`) vào Envelope v1.1 để kiểm toán độ trễ. |
| **INC-07** | **Bẫy Nullability đối với DNS Event ID 22 & Process Terminate ID 5** | Đánh dấu `src_ip`, `src_port`, `dest_ip`, `dest_port` là **Bắt buộc (`Có`)** cho mọi bản ghi bảng Network; `ppid`, `parent_guid` **Bắt buộc** cho mọi bản ghi bảng Process. | Chưa tách biệt điều kiện bắt buộc theo từng `EventID`. | `sysmon-config.xml` bật cả `DnsQuery` (ID 22) và `ProcessTerminate` (ID 5). Bản ghi ID 22 **không có IP/Port**, bản ghi ID 5 **không có ParentGuid/CommandLine**. | Data | Chuyển sang cơ chế **Validation phụ thuộc `sysmon_event_id`** (Conditional Mandatory Fields) trong Schema v1.1 để không đẩy nhầm sự kiện ID 5 và ID 22 vào Quarantine. |
| **INC-08** | **Thiếu ánh xạ cho Event ID 15, 26, 29 và format `poc_run_*.json`** | Chỉ liệt kê Event ID `11` và `23` cho File Events. | Ghi `23/26 -> FILE_DELETE`, chưa có `15` và `29`. | `sysmon-config.xml` bật Event ID **`11`, `15` (`FileCreateStreamHash`), `26` (`FileDeleteDetected`), `29` (`FileExecutableDetected`)**. File `poc_run_20261018_021142.json` dùng cấu trúc `marker` + `steps[]`. | Data & Cyber | Bổ sung đầy đủ enum cho ID `15`, `26`, `29` vào `silver_file_events`; hỗ trợ nạp trực tiếp cấu trúc `poc_run_*.json` vào bảng `silver_lab_test_runs`. |

---

## 2. Đề Xuất Schema v1.1 & Ghi Chú Chuyển Đổi (Migration Notes v1.0 $\rightarrow$ v1.1)

### 2.1. Tóm tắt các thay đổi trong Schema v1.1 (Backward-Compatible Upgrade)
1. **Bổ sung cột vào Common Silver Envelope v1.1:**
   * Thêm `event_utc_time` (`TIMESTAMPTZ NULL`) trích từ `raw_data.UtcTime`.
   * Thêm `ingest_timestamp` (`TIMESTAMPTZ NOT NULL`) ghi nhận thời điểm nạp vào DuckDB.
   * Thêm `rule_name` (`VARCHAR NULL`) trích từ `raw_data.RuleName` (bỏ qua giá trị rỗng `"-"`), hiện thực hóa ý tưởng Pre-tagging từ báo cáo Tuần 4.
2. **Mở rộng cột trong 4 bảng chuyên biệt:**
   * `silver_process_events`: Thêm cột `imphash` (`VARCHAR(32) NULL`) bên cạnh `file_sha256` vì `sysmon-config.xml` cấu hình `<HashAlgorithms>SHA256,IMPHASH</HashAlgorithms>` và mẫu `process.json` thực tế trả về cả hai mã băm này.
   * `silver_file_events`: Thêm cột `pid` (`INTEGER NULL`), `creation_utc_time` (`TIMESTAMPTZ NULL`), `user_name` (`VARCHAR NULL`) vốn đã có sẵn trong `file.json` (`raw_data.ProcessId`, `raw_data.CreationUtcTime`, `raw_data.User`).
   * `silver_registry_events`: Thêm cột `pid` (`INTEGER NULL`), `user_name` (`VARCHAR NULL`), `new_name` (`VARCHAR NULL` cho Event ID 14); hợp nhất `new_data_str` vào `details`.
   * `silver_network_events`: Thêm `pid` (`INTEGER NULL`), `user_name` (`VARCHAR NULL`), `dest_hostname` (`VARCHAR NULL`), `dns_query_status` (`INTEGER NULL`), `dns_query_results` (`VARCHAR NULL`); nới lỏng ràng buộc `NOT NULL` trên các cột 4-tuple IP/Port khi `sysmon_event_id = 22`.

### 2.2. Kịch bản SQL Migration cho DuckDB (Từ v1.0 lên v1.1)
Nếu hệ thống đã khởi tạo bảng theo Schema v1.0, thực thi kịch bản DDL sau để nâng cấp lên v1.1 mà không làm mất dữ liệu:

```sql
-- Nâng cấp bảng silver_process_events lên v1.1
ALTER TABLE silver_process_events ADD COLUMN IF NOT EXISTS event_utc_time TIMESTAMPTZ;
ALTER TABLE silver_process_events ADD COLUMN IF NOT EXISTS ingest_timestamp TIMESTAMPTZ DEFAULT CURRENT_TIMESTAMP;
ALTER TABLE silver_process_events ADD COLUMN IF NOT EXISTS rule_name VARCHAR;
ALTER TABLE silver_process_events ADD COLUMN IF NOT EXISTS imphash VARCHAR(32);

-- Nâng cấp bảng silver_file_events lên v1.1
ALTER TABLE silver_file_events ADD COLUMN IF NOT EXISTS event_utc_time TIMESTAMPTZ;
ALTER TABLE silver_file_events ADD COLUMN IF NOT EXISTS ingest_timestamp TIMESTAMPTZ DEFAULT CURRENT_TIMESTAMP;
ALTER TABLE silver_file_events ADD COLUMN IF NOT EXISTS rule_name VARCHAR;
ALTER TABLE silver_file_events ADD COLUMN IF NOT EXISTS pid INTEGER;
ALTER TABLE silver_file_events ADD COLUMN IF NOT EXISTS creation_utc_time TIMESTAMPTZ;
ALTER TABLE silver_file_events ADD COLUMN IF NOT EXISTS user_name VARCHAR;

-- Nâng cấp bảng silver_registry_events lên v1.1
ALTER TABLE silver_registry_events ADD COLUMN IF NOT EXISTS event_utc_time TIMESTAMPTZ;
ALTER TABLE silver_registry_events ADD COLUMN IF NOT EXISTS ingest_timestamp TIMESTAMPTZ DEFAULT CURRENT_TIMESTAMP;
ALTER TABLE silver_registry_events ADD COLUMN IF NOT EXISTS rule_name VARCHAR;
ALTER TABLE silver_registry_events ADD COLUMN IF NOT EXISTS pid INTEGER;
ALTER TABLE silver_registry_events ADD COLUMN IF NOT EXISTS user_name VARCHAR;
ALTER TABLE silver_registry_events ADD COLUMN IF NOT EXISTS new_name VARCHAR;

-- Nâng cấp bảng silver_network_events lên v1.1
ALTER TABLE silver_network_events ADD COLUMN IF NOT EXISTS event_utc_time TIMESTAMPTZ;
ALTER TABLE silver_network_events ADD COLUMN IF NOT EXISTS ingest_timestamp TIMESTAMPTZ DEFAULT CURRENT_TIMESTAMP;
ALTER TABLE silver_network_events ADD COLUMN IF NOT EXISTS rule_name VARCHAR;
ALTER TABLE silver_network_events ADD COLUMN IF NOT EXISTS pid INTEGER;
ALTER TABLE silver_network_events ADD COLUMN IF NOT EXISTS user_name VARCHAR;
ALTER TABLE silver_network_events ADD COLUMN IF NOT EXISTS dest_hostname VARCHAR;
ALTER TABLE silver_network_events ADD COLUMN IF NOT EXISTS dns_query_status INTEGER;
ALTER TABLE silver_network_events ADD COLUMN IF NOT EXISTS dns_query_results VARCHAR;
```

---

## 3. Từ Điển Dữ Liệu Toàn Diện (Data Dictionary v1.1)

| Tên Trường Chuẩn (v1.1) | Bảng Áp Dụng | Kiểu Lưu Trữ | Giá Trị Mẫu (Từ Dữ Liệu Thật `DESKTOP-IDEMGQU`) | Ý Nghĩa Kỹ Thuật, Nghiệp Vụ Cyber & AI |
| :--- | :--- | :--- | :--- | :--- |
| `event_id` | Tất cả bảng Silver | `VARCHAR(36)` | `2ef59e9e-cff1-525d-a58e-aecae054b171` | Khóa chính xác định (UUIDv5 từ `hostname\|channel\|record_id`), chống trùng lặp tuyệt đối khi replay. |
| `timestamp` | Tất cả bảng Silver | `TIMESTAMPTZ` | `2026-10-18T09:11:55.8363770Z` | Thời điểm hệ điều hành ghi nhận sự kiện (`SystemTime`), độ phân giải $100\text{ ns}$ phục vụ xếp thứ tự nhân quả. |
| `event_utc_time` | Tất cả bảng Silver | `TIMESTAMPTZ` | `2026-10-18T09:11:55.7890000Z` | Thời điểm driver Sysmon bắt sự kiện (`UtcTime`), dùng đối chiếu độ trễ hàng đợi EventLog. |
| `record_id` | Tất cả bảng Silver | `BIGINT` | `184` | Chỉ số `EventRecordID` tuần tự của kênh Sysmon, dùng kiểm tra hiện tượng mất log (gap detection) hoặc xóa log. |
| `hostname` | Tất cả bảng Silver | `VARCHAR(64)` | `DESKTOP-IDEMGQU` | Định danh máy trạm Windows phát sinh telemetry. |
| `process_guid` | Tất cả bảng Silver | `VARCHAR(36)` | `43f71ec6-8d5b-6ad4-2501-000000000400` | Khóa liên kết cốt lõi nối 4 bảng Process – File – Registry – Network, triệt tiêu hoàn toàn rủi ro PID Reuse (`ADR 0002`). |
| `parent_guid` | `silver_process_events` | `VARCHAR(36)` | `43f71ec6-8d48-6ad4-1c01-000000000400` | Khóa ngoại đệ quy trỏ về tiến trình cha, dùng dựng đồ thị phả hệ tấn công (Process Lineage DAG). |
| `pid` / `ppid` | Bảng Process & Phụ | `INTEGER` | `4648` / `1616` | Process ID tại thời điểm chạy, dùng đối chiếu với `runner_pid` của kịch bản kiểm thử Lab. |
| `image_path` | Tất cả bảng Silver | `VARCHAR` | `C:\Users\Trankien\AppData\Local\Temp\edr_poc\EDR_POC_20261018_021142_drop.exe` | Đường dẫn tệp thực thi; phát hiện chạy binary từ thư mục nhạy cảm (`\Temp\`, `\Downloads\`). |
| `command_line` | `silver_process_events` | `VARCHAR` | `"C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe" -NoProfile -ExecutionPolicy Bypass...` | Chuỗi đối số dòng lệnh; đầu vào tính **Shannon Entropy** và khớp mẫu cờ độc hại (`-enc`, `Bypass`, `-w hidden`). |
| `file_sha256` | Process & File | `VARCHAR(64)` | `A90C3FB350A11C6F6A6EFA9607987D924D1DE65E09CA9FAF2E0E0E00531EE335` | Mã băm SHA-256 của tệp thực thi hoặc tệp bị xóa, dùng tra cứu Threat Intelligence / IOCs tĩnh. |
| `imphash` | `silver_process_events` | `VARCHAR(32)` | `5CD891320C666621E9783444DB8CBA78` | Mã băm bảng Import (Import Hash) của tệp PE, giúp nhận diện họ mã độc ngay cả khi đã biên dịch lại. |
| `file_path` | `silver_file_events` | `VARCHAR` | `C:\Users\Trankien\AppData\Local\Temp\edr_poc\EDR_POC_20261018_021142_drop.exe` | Đường dẫn tệp được tạo/ghi/xóa; dùng nối với `image_path` để bắt chuỗi **Drop-and-Execute**. |
| `target_object` | `silver_registry_events`| `VARCHAR` | `HKU\S-1-5-21-...\SOFTWARE\EDR_PoC\TestDword` | Đường dẫn đầy đủ của khóa/giá trị Registry bị can thiệp. |
| `hive` / `key_path` / `value_name` | `silver_registry_events`| `VARCHAR` | `HKU` / `S-1-5-21-...\SOFTWARE\EDR_PoC` / `TestDword` | Ba thành phần chuẩn hóa từ `target_object` giúp truy vấn nhanh các nhánh Persistence (`\CurrentVersion\Run`). |
| `value_type_inferred`| `silver_registry_events`| `VARCHAR(32)` | `REG_DWORD`, `STRING_UNSPECIFIED` | Kiểu dữ liệu Registry suy diễn bằng heuristic từ trường `Details` của Sysmon Event ID 13. |
| `src_ip` / `dest_ip` | `silver_network_events` | `VARCHAR(45)` | `10.0.2.15` / `172.66.147.243` | Địa chỉ IP nguồn và đích của kết nối mạng (Event ID 3). |
| `src_port` / `dest_port`| `silver_network_events` | `INTEGER` | `49904` / `443` | Cổng giao tiếp nguồn và đích; phát hiện kết nối C2 qua cổng chuẩn hoặc cổng lạ. |
| `dns_query_name` | `silver_network_events` | `VARCHAR` | `cloudflare.com` (Event ID 22) | Tên miền được tiến trình yêu cầu phân giải DNS trước khi mở kết nối socket. |
| `rule_name` | Tất cả bảng Silver | `VARCHAR` | `file`, `registry`, `technique_id=T1059.001...` | Nhãn gợi ý từ bộ lọc `sysmon-config.xml` (`RuleName`). |

---

## 4. Ví Dụ Biến Đổi Thực Tế Raw $\rightarrow$ Silver Cho 4 Nhóm Sự Kiện

Dưới đây là minh chứng đối chiếu trực tiếp từ 4 tệp mẫu thực nghiệm (`process.json`, `file.json`, `registry.json`, `network.json`) sang các dòng bản ghi phẳng trong DuckDB Silver v1.1:

### 4.1. Nhóm Process (`process.json` – `record_id: 184`, Event ID 1)
* **Đầu vào Raw (`raw_data` & `System` Header):**
  * `Computer`: `"DESKTOP-IDEMGQU"`, `Channel`: `"Microsoft-Windows-Sysmon/Operational"`, `EventRecordID`: `184`, `EventID`: `1`, `TimeCreated`: `"2026-10-18T09:11:55.8363770Z"`
  * `ProcessGuid`: `"{43f71ec6-8d5b-6ad4-2501-000000000400}"`, `ParentProcessGuid`: `"{43f71ec6-8d48-6ad4-1c01-000000000400}"`
  * `ProcessId`: `"4648"`, `ParentProcessId`: `"1616"`, `Hashes`: `"SHA256=A90C3FB350A11C6F6A6EFA9607987D924D1DE65E09CA9FAF2E0E0E00531EE335,IMPHASH=5CD891320C666621E9783444DB8CBA78"`
* **Đầu ra Chuẩn hóa tại bảng `silver_process_events`:**
  * `event_id`: `"2ef59e9e-cff1-525d-a58e-aecae054b171"` (Khớp 100% công thức UUIDv5)
  * `event_type`: `"PROCESS_START"`, `sysmon_event_id`: `1`, `record_id`: `184`, `hostname`: `"DESKTOP-IDEMGQU"`
  * `process_guid`: `"43f71ec6-8d5b-6ad4-2501-000000000400"` (Đã xóa `{}`)
  * `parent_guid`: `"43f71ec6-8d48-6ad4-1c01-000000000400"` (Đã xóa `{}`)
  * `pid`: `4648` (`INTEGER`), `ppid`: `1616` (`INTEGER`), `session_id`: `1` (`INTEGER`)
  * `image_path`: `"C:\\Users\\Trankien\\AppData\\Local\\Temp\\edr_poc\\EDR_POC_20261018_021142_drop.exe"`
  * `file_sha256`: `"A90C3FB350A11C6F6A6EFA9607987D924D1DE65E09CA9FAF2E0E0E00531EE335"`
  * `imphash`: `"5CD891320C666621E9783444DB8CBA78"`, `rule_name`: `NULL` (vì `RuleName = "-"`)

### 4.2. Nhóm File (`file.json` – `record_id: 182`, Event ID 11)
* **Đầu vào Raw (`raw_data` & `System` Header):**
  * `EventRecordID`: `182`, `EventID`: `11`, `RuleName`: `"file"`, `ProcessGuid`: `"{43f71ec6-8d48-6ad4-1c01-000000000400}"`, `ProcessId`: `"1616"`
  * `TargetFilename`: `"C:\\Users\\Trankien\\AppData\\Local\\Temp\\edr_poc\\EDR_POC_20261018_021142_drop.exe"`
* **Đầu ra Chuẩn hóa tại bảng `silver_file_events`:**
  * `event_id`: `"cab6af4d-a862-5e4c-bfb5-42b5b46081cd"`
  * `event_type`: `"FILE_CREATE"`, `operation`: `"FILE_CREATE"`, `sysmon_event_id`: `11`, `rule_name`: `"file"`
  * `process_guid`: `"43f71ec6-8d48-6ad4-1c01-000000000400"`, `pid`: `1616`
  * `file_path`: `"C:\\Users\\Trankien\\AppData\\Local\\Temp\\edr_poc\\EDR_POC_20261018_021142_drop.exe"`
  * `file_extension`: `"exe"`, `file_sha256`: `NULL` (Do Event ID 11 không sinh hash, tránh tự chế dữ liệu giả)

### 4.3. Nhóm Registry (`registry.json` – `record_id: 191`, Event ID 13)
* **Đầu vào Raw (`raw_data` & `System` Header):**
  * `EventRecordID`: `191`, `EventID`: `13`, `RuleName`: `"registry"`, `EventType`: `"SetValue"`
  * `TargetObject`: `"HKU\\S-1-5-21-237846928-68144873-1231419655-1001\\SOFTWARE\\EDR_PoC\\TestDword"`
  * `Details`: `"DWORD (0x00000001)"`
* **Đầu ra Chuẩn hóa tại bảng `silver_registry_events`:**
  * `event_id`: `"a95f919d-adca-5eb1-9560-f0f2b393c097"`
  * `event_type`: `"REGISTRY_SET_VALUE"`, `operation`: `"SetValue"`, `rule_name`: `"registry"`
  * `process_guid`: `"43f71ec6-8d48-6ad4-1c01-000000000400"`, `pid`: `1616`
  * `hive`: `"HKU"`, `key_path`: `"S-1-5-21-237846928-68144873-1231419655-1001\\SOFTWARE\\EDR_PoC"`, `value_name`: `"TestDword"`
  * `value_type_inferred`: `"REG_DWORD"`, `details`: `"DWORD (0x00000001)"`

### 4.4. Nhóm Network (`network.json` – `record_id: 194`, Event ID 3)
* **Đầu vào Raw (`raw_data` & `System` Header):**
  * `EventRecordID`: `194`, `EventID`: `3`, `TimeCreated`: `"2026-10-18T09:11:59.4649146Z"`, `UtcTime`: `"2026-10-18 09:12:11.850"`
  * `Protocol`: `"tcp"`, `Initiated`: `"true"`, `SourceIsIpv6`: `"false"`, `SourceIp`: `"10.0.2.15"`, `SourcePort`: `"49904"`, `DestinationIp`: `"172.66.147.243"`, `DestinationPort`: `"443"`
* **Đầu ra Chuẩn hóa tại bảng `silver_network_events`:**
  * `event_id`: `"7536126d-407c-500d-a9b1-c9d7cec9f7df"`
  * `timestamp`: `2026-10-18 09:11:59.464914+00:00`, `event_utc_time`: `2026-10-18 09:12:11.850000+00:00`
  * `event_type`: `"NETWORK_CONNECT"`, `protocol`: `"TCP"`, `direction`: `"OUTBOUND"`, `ip_version`: `"IPv4"`
  * `src_ip`: `"10.0.2.15"`, `src_port`: `49904`, `dest_ip`: `"172.66.147.243"`, `dest_port`: `443`
  * `dns_query_name`: `NULL`, `dns_query_status`: `NULL`, `dns_query_results`: `NULL`