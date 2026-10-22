# ADR 0006: Đối Chiếu Thống Nhất Endpoint Event Schema v1.1, Chuẩn Hóa Trục Thời Gian Kép Và Hỗ Trợ Đa Hình Sự Kiện (DNS ID 22 & Process ID 5)

* **Trạng thái:** Đã chấp thuận (Accepted)
* **Ngày quyết định:** 21/10/2026 (Tuần 5)
* **Người đề xuất:** Huỳnh Hữu Nhật (Data Engineer Lead)
* **Tham vấn & Đồng thuận:** Cyber Security Team, Software Team
* **Liên kết Issue:** `[W05][Data] Thiết kế Bronze/Silver/Gold, schema, chất lượng và lineage dữ liệu #27`
* **Kế thừa & Mở rộng:** `ADR 0001`, `ADR 0002`, `ADR 0003` (Tuần 3)

---

## 1. Bối Cảnh & Các Mâu Thuẫn Phát Hiện Từ Thực Nghiệm Tuần 3

Khi đối chiếu chéo giữa đặc tả lý thuyết Tuần 3 (`endpoint_event_schema_v1.md`, `sysmon_raw_to_silver_mapping_v1.md`) với bộ mẫu thực nghiệm thu thập trên máy trạm `DESKTOP-IDEMGQU` (`process.json`, `file.json`, `registry.json`, `network.json`, `sysmon-config.xml`), nhóm Data ghi nhận 4 nhóm mâu thuẫn kỹ thuật cần giải quyết dứt điểm trước khi đóng băng hợp đồng dữ liệu cho Giai đoạn 2:

1. **Lệch tên trường giữa Schema, Mapping và JSON thực tế:**
   * Tên máy trạm: Schema v1 gọi là `hostname`, tài liệu Mapping gọi là `host_id`, còn JSON thực tế xuất `"hostname"`.
   * Địa chỉ IP/Port nguồn: Schema v1 và `network.json` dùng `src_ip`/`src_port`, nhưng tài liệu Mapping lại ghi `source_ip`/`source_port`.
   * Bảng File (`file.json`) thiếu trường `data.operation` dù Schema v1 quy định bắt buộc; bảng Registry (`registry.json`) lại xuất trùng lặp cả `details` và `new_data_str`.
2. **Độ lệch thời gian thực tế giữa `System.TimeCreated.SystemTime` và `EventData.UtcTime`:**
   * Trong mẫu thật `network.json` (`record_id: 194`), thời điểm hệ điều hành ghi nhận sự kiện (`timestamp` / `SystemTime`) là `2026-10-18T09:11:59.4649146Z`, trong khi trường `raw_data.UtcTime` lại là `2026-10-18 09:12:11.850` (lệch nhau **$12.385\text{ giây}$**). Nếu không quy định rõ trường nào làm trục thời gian chuẩn, các cửa sổ trượt $5\text{ giây}$ sẽ tính toán sai lệch.
3. **Bẫy Nullability đối với các sự kiện có cấu trúc đa hình (Polymorphic Event Payloads):**
   * Trong `sysmon-config.xml`, nhóm bật thu thập cả **Sysmon Event ID 22 (`DnsQuery`)** và **Event ID 5 (`ProcessTerminate`)**.
   * Bản ghi Event ID 22 không có bộ 4-tuple socket (`src_ip`, `src_port`, `dest_ip`, `dest_port`); bản ghi Event ID 5 không có thông tin tiến trình cha (`ppid`, `parent_guid`). Nếu áp dụng cứng nhắc ràng buộc `NOT NULL` của Schema v1.0, 100% sự kiện DNS và Process Terminate hợp lệ sẽ bị đẩy nhầm vào Quarantine!
4. **Nguy cơ va chạm khóa `UUIDv5` khi xóa kênh Windows EventLog (`EventRecordID` Reset):**
   * Công thức `ADR 0001` ($\text{UUIDv5}(\text{Computer} \mid \text{Channel} \mid \text{EventRecordID})$) hoạt động hoàn hảo trong điều kiện bình thường. Tuy nhiên, nếu kênh log bị xóa trắng bằng lệnh `wevtutil cl`, `EventRecordID` sẽ đếm lại từ `1`, gây nguy cơ trùng khóa với các bản ghi cũ trước khi xóa.

---

## 2. Quyết Định Kiến Trúc (Schema v1.1 Specification Decisions)

### Quyết định 1: Chuẩn hóa tên trường thống nhất trong Schema v1.1
* Chốt sử dụng **`hostname`**, **`src_ip`**, **`src_port`**, **`dest_ip`**, **`dest_port`**, và **`details`** làm tên cột chuẩn trên toàn bộ các tầng.
* Bộ nạp Silver tự động làm phẳng (flatten) đối tượng `"data"` của Collector và tự động suy diễn `operation = event_type` cho bảng `silver_file_events` nếu trường `data.operation` bị khuyết, đảm bảo tương thích ngược 100% với code Collector Tuần 3 của nhóm Software.
* Bổ sung cột **`imphash`** (`VARCHAR(32)`) vào `silver_process_events` và mở rộng `silver_file_events` hỗ trợ đầy đủ các Event ID **`11, 15, 23, 26, 29`** theo đúng `sysmon-config.xml`.

### Quyết định 2: Thiết lập Trục Thời Gian Kép (Dual-Timestamp Axis)
* Chọn **`timestamp`** (ánh xạ từ `System.TimeCreated.SystemTime`, độ phân giải $100\text{ ns}$ UTC) làm **trục thời gian chuẩn duy nhất** cho mọi phép nối bảng, sắp xếp nhân quả và tính toán cửa sổ trượt.
* Bổ sung cột **`event_utc_time`** (ánh xạ từ `EventData.UtcTime`) và **`ingest_timestamp`** vào Common Silver Envelope v1.1 để phục vụ giám sát chất lượng dữ liệu (phát hiện độ trễ ghi log khi $|\text{timestamp} - \text{event\_utc\_time}| > 5\text{ s}$).

### Quyết định 3: Kiểm định bắt buộc có điều kiện theo `sysmon_event_id` (Conditional Validation)
* Giữ nguyên mô hình **4 bảng sự kiện cốt lõi** (`silver_process_events`, `silver_file_events`, `silver_registry_events`, `silver_network_events`) để không làm phân mảnh truy vấn, nhưng áp dụng luật kiểm định phụ thuộc vào `sysmon_event_id`:
  * Tại `silver_network_events`: Khi `sysmon_event_id = 3` (`NETWORK_CONNECT`), bắt buộc `src_ip`, `src_port`, `dest_ip`, `dest_port` khác `NULL`. Khi `sysmon_event_id = 22` (`DNS_QUERY`), cho phép 4 cột IP/Port nhận giá trị `NULL` và bắt buộc `dns_query_name` khác `NULL`.
  * Tại `silver_process_events`: Khi `sysmon_event_id = 1` (`PROCESS_START`), bắt buộc `ppid` và `parent_guid` khác `NULL`. Khi `sysmon_event_id = 5` (`PROCESS_TERMINATE`), cho phép `ppid`, `parent_guid`, `command_line` nhận giá trị `NULL`.

### Quyết định 4: Bảo toàn công thức `UUIDv5` gốc kèm cơ chế phát hiện `Channel Epoch`
* Trong vận hành bình thường (khi `record_id` tăng đơn điệu), giữ nguyên công thức `f"{hostname}|{channel}|{record_id}"` của `ADR 0001` để khớp tuyệt đối 100% với toàn bộ mã `event_id` trong bộ mẫu Tuần 3.
* Bổ sung bảng `silver_ingestion_watermarks` theo dõi `last_record_id` của từng `(hostname, channel)`. Nếu phát hiện `record_id` tụt lùi ở một thời điểm `timestamp` mới hơn (dấu hiệu xóa log `T1070.001`), pipeline phát cảnh báo an ninh và tự động nối thêm hậu tố `#epoch_<YYYYMMDD_HHMMSS>` vào chuỗi `channel` khi băm `UUIDv5`, ngăn chặn hoàn toàn va chạm khóa với lịch sử.

---

## 3. Hệ Quả (Consequences)

* Toàn bộ 8 bản ghi mẫu thật Tuần 3 và các mẫu biên (DNS Event ID 22, Process Terminate ID 5, File Stream Hash ID 15) đều vượt qua bước kiểm định một cách chính xác mà không cần sửa lại code của Software Collector.
* Nhóm Cyber có đầy đủ dữ liệu DNS (`dns_query_name`, `dns_query_status`, `dns_query_results`), `imphash` và `rule_name` ngay trong DuckDB để viết luật phát hiện cho toàn bộ 13 kỹ thuật MITRE đã chọn.