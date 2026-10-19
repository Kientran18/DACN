# Báo Cáo Tiến Độ Tuần 3: Chuẩn Hóa Schema & Ánh Xạ Dữ Liệu Thu Thập (Schema Normalization & Telemetry Mapping)

**Dự án:** Hệ thống Giám sát & Phát hiện Xâm nhập Điểm cuối Cục bộ (Local EDR)  
**Vai trò phụ trách:** Data Engineer / Pipeline & Storage  
**Thời gian hoàn thành:** Tuần 3 (Kế hoạch 12 tuần ĐACN)  
**Trạng thái:** HOÀN THÀNH (Definition of Done: 100%)

---

## 1. Mục Tiêu & Phạm Vi Công Việc Tuần 3
Nối tiếp kết quả thiết kế kiến trúc Tuần 1 và phân tích yêu cầu hành vi Tuần 2, trọng tâm của Tuần 3 là hoàn thiện lớp chuẩn hóa dữ liệu (Silver Layer) dựa trên dữ liệu thu thập thực tế từ điểm cuối Windows:
* Đánh giá và đối soát các yêu cầu thu thập (telemetry requirements) từ phía Cyber Team.
* Thu thập và phân tích mẫu sự kiện thô (raw telemetry logs) từ Software Team.
* Chuẩn hóa khung bao đóng sự kiện (Common Event Envelope) và đặc tả 4 Category Schemas: Process, File, Registry, Network.
* Thiết lập ma trận ánh xạ trường dữ liệu thô sang chuẩn hóa (Raw-to-Normalized Mapping).
* Hoàn thiện Từ điển dữ liệu (Data Dictionary) và ghi chú rủi ro chất lượng dữ liệu (Data Quality Notes).
* Tổ chức rà soát chéo (Cross-functional Review) với Cyber Team và Software Team để xác nhận tính khả thi.

---

## 2. Kết Quả Thực Hiện Các Nhiệm Vụ Cốt Lõi (Tasks Completed)

### 2.1. Chuẩn Hóa Khung Bao Đóng & Định Danh Sự Kiện (Common Envelope & Identity Strategy)
* **Quy chuẩn `event_id` xác định (Deterministic UUIDv5):** Thay thế giải pháp sinh UUIDv4 ngẫu nhiên ở Tuần 1 bằng thuật toán sinh `UUIDv5` dựa trên bộ định danh `f"{Computer}|{Channel}|{EventRecordID}"`. Giải pháp này đảm bảo tính duy nhất và khả năng chạy lại pipeline (idempotency) mà không gây trùng lặp bản ghi.
* **Chuẩn hóa Timestamp:** Toàn bộ mốc thời gian từ Sysmon (`TimeCreated.SystemTime` và `UtcTime`) được parse đồng nhất về định dạng chuẩn ISO 8601 UTC kèm hậu tố `Z`, loại bỏ nguy cơ trôi lệch cửa sổ trượt (sliding window) do sai lệch múi giờ cục bộ.
* **Chiến lược liên kết phả hệ tiến trình (Process Correlation):** Triệt tiêu hoàn toàn việc dùng `pid` làm khóa liên kết để ngăn ngừa rủi ro PID Reuse trên Windows. Mọi quan hệ giữa các bảng sự kiện (Process, File, Registry, Network) đều sử dụng `process_guid` (đã chuẩn hóa bỏ dấu ngoặc nhọn `{}`) làm khóa liên kết.
* **Bảo tồn dữ liệu thô (Raw Data Preservation):** Mọi bản ghi chuẩn hóa tại Silver Layer đều duy trì cột `raw_data` chứa toàn bộ dictionary gốc của Sysmon EventData, phục vụ kiểm toán an ninh và trích xuất đặc trưng mở rộng.

### 2.2. Xây Dựng 4 Bộ Schema Chuẩn Hóa (Category Schemas v1)
Đã hoàn tất đặc tả kỹ thuật chi tiết tại `docs/architecture/endpoint_event_schema_v1.md`:
1. **Process Event Schema (Sysmon ID 1 & 5):** Lưu vết khởi tạo và kết thúc tiến trình; bổ sung các trường ngữ cảnh `parent_image`, `parent_command_line`, `integrity_level`, `user_name` và phân tách mã băm `file_sha256`.
2. **File Event Schema (Sysmon ID 11 & 23/26):** Theo dõi việc tạo dropper, ghi đè và xóa tệp trong các thư mục nhạy cảm (`\Temp`, `\Downloads`, `\AppData`); trích xuất phần mở rộng tệp `file_extension` và bảo toàn hash tệp khi xóa.
3. **Registry Event Schema (Sysmon ID 12, 13, 14):** Ghi nhận các can thiệp vào khóa AutoRun/RunOnce, Winlogon, IFEO; bóc tách phân cấp `hive`, `key_path`, `value_name` và tích hợp hàm suy diễn kiểu dữ liệu `value_type_inferred`.
4. **Network Event Schema (Sysmon ID 3 & 22):** Lưu vết kết nối socket ra ngoài (C2 communication) gồm giao thức `protocol`, chiều kết nối `direction` (suy diễn từ cờ `Initiated`), IP/Port nguồn và đích, cùng liên kết tên miền `dns_query_name`.

### 2.3. Ma Trận Ánh Xạ & Từ Điển Dữ Liệu (Mapping Matrix & Data Dictionary)
* Thiết lập ma trận ánh xạ 1-1 và các quy tắc chuyển đổi (ETL rules) từ XML/JSON thô sang Silver DuckDB tại `docs/architecture/sysmon_raw_to_silver_mapping_v1.md`.
* Hoàn thiện bảng chú giải thuật ngữ, kiểu dữ liệu, giá trị mẫu và ý nghĩa phát hiện an ninh tại `docs/architecture/data_dictionary_and_quality_notes_v1.md`.

---

## 3. Kết Quả Xác Minh Thực Nghiệm & Dữ Liệu PoC

Pipeline chuẩn hóa đã được kiểm thử trực tiếp trên chuỗi dữ liệu thực nghiệm PoC thu thập từ máy trạm Windows (`poc_run_20261018_021142.json` trên host `DESKTOP-IDEMGQU`):
* **Mẫu Process (Event ID 1):** Bóc tách chính xác chuỗi spawn từ PowerShell gọi thực thi tiến trình con `EDR_POC_..._drop.exe` và `conhost.exe`; bóc tách thành công hash SHA256 và parent lineage.
* **Mẫu File (Event ID 11):** Ghi nhận chính xác hành vi tạo file nhị phân trong thư mục Temp `C:\Users\Trankien\AppData\Local\Temp\edr_poc\..._drop.exe`.
* **Mẫu Registry (Event ID 13):** Bóc tách chính xác thao tác `SetValue` vào nhánh `HKU\...\SOFTWARE\EDR_PoC\TestDword`, suy diễn chuẩn xác kiểu `REG_DWORD`.
* **Mẫu Network (Event ID 3):** Phân tích thành công kết nối outbound qua cổng 443 tới địa chỉ IP `172.66.147.243`.

---

## 4. Biên Bản Rà Soát Liên Nhóm (Cross-Functional Review Confirmation)

| Bộ Phận | Đại Diện | Nội Dung Rà Soát | Kết Quả Đánh Giá |
| :--- | :--- | :--- | :---: |
| **Cyber Team** | Detection Lead | Kiểm tra danh mục trường phục vụ 13 kỹ thuật MITRE ATT&CK (DET-001 đến DET-010). Xác nhận đầy đủ các trường rule-based và đặc trưng trích xuất AI. | **PASS (Confirmed)** |
| **Software Team** | Collector Lead | Đối soát khả năng thu thập của Sysmon Collector (`sysmon-config.xml` và `sysmon_collector_poc.py`). Xác nhận toàn bộ trường đều sẵn sàng và trích xuất ổn định. | **PASS (Confirmed)** |

---

## 5. Bảng Nghiệm Thu Tiêu Chí Hoàn Thành (Definition of Done Verification)

| STT | Tiêu Chí Nghiệm Thu (DoD) | Minh Chứng / Trạng Thái | Đánh Giá |
| :---: | :--- | :--- | :---: |
| 1 | A common event envelope is defined | Đã định nghĩa tại `docs/architecture/endpoint_event_schema_v1.md` mục 1 | **Đạt** |
| 2 | Four main event categories have schemas | Đã đặc tả 4 schema: Process, File, Registry, Network tại mục 2 | **Đạt** |
| 3 | Mandatory and optional fields are documented | Đã phân loại chi tiết từng trường trong bảng đặc tả schema | **Đạt** |
| 4 | Each field has a defined data type | Đã chuẩn hóa kiểu dữ liệu SQL/Pydantic (`VARCHAR`, `INTEGER`, `TIMESTAMP`,...) | **Đạt** |
| 5 | Raw source fields are mapped to normalized fields | Đã hoàn thành bảng ma trận tại `docs/architecture/sysmon_raw_to_silver_mapping_v1.md` | **Đạt** |
| 6 | Event timestamps are standardized | Chuẩn hóa về ISO 8601 UTC có hậu tố `Z` kèm múi giờ UTC | **Đạt** |
| 7 | Process correlation strategy is documented | Áp dụng `process_guid` và `parent_guid` (strip `{}`), loại bỏ rủi ro PID Reuse | **Đạt** |
| 8 | Raw events can be preserved for audit/reprocessing | Lưu giữ JSON gốc qua trường `raw_data` và tầng Bronze JSONL | **Đạt** |
| 9 | Cyber confirms detection-required fields | Cyber team xác nhận đạt yêu cầu cho 13 kỹ thuật tấn công | **Đạt** |
| 10 | Software confirms fields can be collected | Software team xác nhận thông qua mã nguồn PoC và mẫu log thực tế | **Đạt** |

---

## 6. Kế Hoạch Tuần Tiếp Theo (Tuần 4)
1. Cập nhật mã nguồn Pydantic (`pipeline/schemas/events.py`) và DDL DuckDB (`pipeline/storage/db.py`) để đồng bộ hoàn toàn với bộ Schema v1 vừa chuẩn hóa.
2. Nâng cấp module ETL `pipeline/process_pipeline.py` tích hợp logic bóc tách mới (Deterministic UUIDv5, strip GUID, registry type inference).
3. Triển khai xây dựng tầng Gold Layer: module trích xuất đặc trưng `pipeline/features/extractor.py` (Process Tree depth, Sliding Window counters, Shannon Entropy) phục vụ huấn luyện mô hình phát hiện.