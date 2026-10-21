# Đặc Tả Validation, Ma Trận Chất Lượng Dữ Liệu, Quarantine/Replay, Lineage & Quản Trị v1.0

**Dự án:** Hệ thống Giám sát & Phát hiện Xâm nhập Điểm cuối Cục bộ (Local EDR)  
**Issue tham chiếu:** `[W05][Data] Thiết kế Bronze/Silver/Gold, schema, chất lượng và lineage dữ liệu #27`  
**Người thực hiện:** Huỳnh Hữu Nhật (Data Engineer Lead)  
**Phiên bản:** 1.0.0 | **Ngày cập nhật:** 21/10/2026 (Tuần 5)

---

## 1. Đặc Tả Quy Tắc Validation Theo Event Type & Nguyên Tắc "Zero Data Fabrication"

### 1.1. Nguyên tắc "Không tự chế dữ liệu để vượt qua kiểm định" (Zero Data Fabrication Policy)
Một rủi ro nghiêm trọng trong các pipeline dữ liệu là việc lập trình viên gán giá trị giả (như `process_guid = "00000000-0000-0000-0000-000000000000"`, `record_id = -1`, `dest_ip = "0.0.0.0"`, hoặc `timestamp = NOW()`) khi bản ghi gốc bị khuyết trường bắt buộc để ép bản ghi chui lọt vào tầng Silver. Trong hệ thống EDR, hành vi này **bị nghiêm cấm tuyệt đối** vì:
* Nếu gán `process_guid` mặc định toàn số `0`, hàng trăm sự kiện lỗi không liên quan sẽ bị gom chung vào một "tiến trình ma" duy nhất, làm nổ cảnh báo giả (False Positive) trên bộ đếm Sliding Window và làm hỏng hoàn toàn cây tiến trình `WITH RECURSIVE`.
* Nếu gán `timestamp = NOW()` khi lỗi parse thời gian, thứ tự nhân quả của chuỗi tấn công sẽ bị đảo lộn.

**Quy tắc bắt buộc:**
1. Nếu thiếu hoặc hỏng **trường bắt buộc (Mandatory Field)** của loại sự kiện tương ứng $\rightarrow$ **Lập tức từ chối nạp vào Silver và chuyển hướng sang tầng Quarantine** kèm mã lỗi tường minh.
2. Nếu thiếu **trường tùy chọn (Optional Field)** (ví dụ: Event ID 11 không có `Hashes`, Event ID 22 không có `dest_ip`, Event ID 5 không có `parent_guid`) $\rightarrow$ Lưu giá trị `NULL` chuẩn của SQL (không dùng chuỗi `"-"` hay `"N/A"`).

### 1.2. Bảng Quy Tắc Kiểm Định Chi Tiết (Validation Rules Specification)

| Nhóm Kiểm Tra | Trường Áp Dụng | Điều Kiện Hợp Lệ (Validation Constraint) | Quy Tắc Ép Kiểu (Type Coercion) | Mã Lỗi Khi Vi Phạm (Quarantine Error Code) |
| :--- | :--- | :--- | :--- | :--- |
| **1. Cú pháp gốc** | Toàn bộ dòng JSONL | Chuỗi văn bản phải là một JSON Object hợp lệ. | `json.loads(line)` | `ERR_CORRUPTED_JSON` |
| **2. Khóa tự nhiên** | `hostname`, `channel`, `record_id` | `hostname` và `channel` không rỗng; `record_id` phải là số nguyên dương ($\text{record\_id} > 0$). | `int(record_id)`, `.strip()` | `ERR_MISSING_NATURAL_KEY` hoặc `ERR_INVALID_RECORD_ID` |
| **3. Thời gian UTC** | `timestamp` (`SystemTime`) | Chuỗi ISO 8601 hợp lệ; nằm trong khoảng hợp lý: `2020-01-01T00:00:00Z` $\le t \le \text{ingest\_time} + 5\text{ phút}$. | Chuyển về `datetime` có `tzinfo=timezone.utc` (cắt phần lẻ nanosecond quá 6 chữ số nếu parser Python yêu cầu). | `ERR_INVALID_TIMESTAMP` hoặc `ERR_FUTURE_TIME_SKEW` |
| **4. Danh mục sự kiện**| `sysmon_event_id`, `event_type` | `sysmon_event_id` $\in \{1, 3, 5, 11, 12, 13, 14, 15, 22, 23, 26, 29\}$; `event_type` thuộc tập Enum chuẩn. | `int(sysmon_event_id)` | `ERR_UNSUPPORTED_EVENT_ID` |
| **5. Định danh Tiến trình**| `process_guid` (Mọi sự kiện), `parent_guid` (Khi `ID=1`) | Sau khi chạy `strip_guid()`, chuỗi phải khớp biểu thức chính quy UUID chuẩn 36 ký tự: `^[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}$`. | `.strip().strip("{}").lower()` | `ERR_MISSING_PROCESS_GUID` hoặc `ERR_MALFORMED_GUID` |
| **6. Ràng buộc riêng `ID=1`** | `pid`, `ppid`, `image_path` | `pid > 0`, `ppid >= 0`, `image_path` không được rỗng hoặc `NULL`. | `int(pid)`, `int(ppid)` | `ERR_PROC_START_MISSING_FIELD` hoặc `ERR_TYPE_COERCION_FAILED` |
| **7. Ràng buộc riêng File** | `file_path`, `image_path` (`ID=11,15,23,26,29`)| `file_path` (`TargetFilename`) và `image_path` (`Image`) không được rỗng. | Giữ chuỗi UTF-8, trích `file_extension`. | `ERR_FILE_EVENT_MISSING_PATH` |
| **8. Ràng buộc riêng Registry**| `operation`, `target_object` (`ID=12,13,14`) | `target_object` phải bắt đầu bằng nhánh Hive hợp lệ (`HKLM\`, `HKU\`, `HKCU\`, `HKCR\`, `HKCC\`). Với `ID=13`, trường `details` không được `NULL`. | Tách `hive`, `key_path`, `value_name`; chạy `infer_registry_value_type()`. | `ERR_REG_INVALID_TARGET` hoặc `ERR_REG_MISSING_DETAILS` |
| **9. Ràng buộc riêng Network `ID=3`**| `protocol`, `direction`, `src_ip`, `src_port`, `dest_ip`, `dest_port` | `src_ip` và `dest_ip` phải parse được qua `ipaddress.ip_address()`; `src_port` và `dest_port` $\in [0, 65535]$; `protocol` $\in \{\text{'TCP'}, \text{'UDP'}\}$. | `int(port)`, `.upper()` cho `protocol`. | `ERR_NET_INVALID_IP_OR_PORT` |
| **10. Ràng buộc riêng DNS `ID=22`**| `dns_query_name`, `image_path` | `dns_query_name` (`QueryName`) không được rỗng; các trường IP/Port được phép `NULL`. | `int(QueryStatus)` (nếu có). | `ERR_DNS_MISSING_QUERY_NAME` |

---

## 2. Đặc Tả Deterministic `event_id`, Deduplication & Xử Lý Log Rotation

### 2.1. Công thức sinh khóa và phạm vi duy nhất (Uniqueness Scope)
Kế thừa `ADR 0001` từ Tuần 3, khóa chính `event_id` được tính bằng thuật toán băm xác định **UUIDv5 (SHA-1)** với Namespace cố định của dự án (`6f1d3c52-8a0e-4b7a-9c1e-3d5a7b9e2f10`):

$$\text{event\_id} = \text{UUIDv5}\Big(\text{EDR\_NAMESPACE},\; \text{UPPER}(\text{hostname}) \;\Vert\; \text{"|"} \;\Vert\; \text{channel} \;\Vert\; \text{"|"} \;\Vert\; \text{record\_id}\Big)$$

*(Lưu ý: Trong bộ mẫu thực nghiệm Tuần 3 trên máy `DESKTOP-IDEMGQU`, `hostname` đã ở dạng chữ hoa `"DESKTOP-IDEMGQU"`, nên `generate_deterministic_event_id("DESKTOP-IDEMGQU", "Microsoft-Windows-Sysmon/Operational", 185)` luôn sinh ra chính xác mã `5b452d31-566e-59b4-9929-cbb8377ca690` khớp 100% với tệp `process.json`).*

### 2.2. Giải quyết rủi ro Reset `EventRecordID` khi xóa kênh Log (`wevtutil cl`)
* **Phân tích góc khuất kỹ thuật:**
  1. **Log Rotation thông thường (Circular Logging khi đầy dung lượng kênh):** Khi tệp `.evtx` đạt ngưỡng dung lượng tối đa (ví dụ $1\text{ GB}$), Windows ghi đè các bản ghi cũ nhất nhưng **chỉ số `EventRecordID` vẫn tiếp tục tăng đơn điệu (kiểu `uint64`) chứ không quay về 1**.
  2. **Xóa trắng kênh Log chủ động (Log Clear / Reset):** Nếu quản trị viên hoặc kẻ tấn công chạy lệnh `wevtutil cl Microsoft-Windows-Sysmon/Operational` (hoặc cài đặt lại hệ điều hành cùng tên `hostname`), Windows sẽ tạo lại tệp log mới và **`EventRecordID` bị đặt lại về `1`**. Khi đó, bộ ba `(hostname, channel, record_id)` mới sẽ trùng với bản ghi cũ trong lịch sử!
* **Cơ chế phát hiện và xử lý trong Pipeline (Epoch / Reset Detection):**
  * Pipeline duy trì bảng trạng thái kiểm toán `silver_ingestion_watermarks (hostname, channel, last_record_id, last_timestamp_utc, channel_epoch_date)`.
  * Khi nhận một bản ghi có $\text{record\_id} < \text{last\_record\_id}$ nhưng $\text{timestamp} > \text{last\_timestamp\_utc}$ (ví dụ: hôm qua `record_id` đang là `50,000`, hôm nay `record_id` tụt về `12` ở thời điểm mới hơn):
    1. Pipeline lập tức phát cảnh báo an ninh mức `HIGH` (**Log Tampering / Channel Cleared Detected – MITRE T1070.001**).
    2. Để bảo toàn tính tương thích ngược 100% với toàn bộ `event_id` của bộ mẫu Tuần 3 (khi `record_id` tăng bình thường), công thức chuẩn vẫn giữ nguyên 3 thành phần `f"{hostname}|{channel}|{record_id}"`. Nếu phát hiện sự kiện `CHANNEL_RESET`, pipeline gắn hậu tố epoch mới vào tên kênh (`Microsoft-Windows-Sysmon/Operational#epoch_20261021`) để khóa `UUIDv5` không bao giờ đụng độ với dữ liệu lịch sử trước khi xóa log.

### 2.3. Đảm bảo tính Idempotent khi chạy lại (Idempotent Replay)
1. **Chống trùng trong cùng một lô (In-Batch Deduplication):** Bộ nạp Python duy trì một tập hợp `seen_event_ids: set[str]` trong bộ nhớ cho mỗi batch để loại bỏ ngay lập tức các bản ghi bị Collector gửi đúp.
2. **Chống trùng tại tầng cơ sở dữ liệu (Database-Level Idempotency):** Mọi câu lệnh chèn vào DuckDB Silver đều sử dụng cú pháp:
   ```sql
   INSERT OR IGNORE INTO silver_process_events VALUES (...);
   ```
   Nhờ đó, việc chạy lại cùng một tệp Bronze 1 lần hay 100 lần đều cho ra **cùng một trạng thái dữ liệu duy nhất** trong DuckDB (`duplicates_dropped` được ghi nhận vào bảng metrics của lần chạy).

---

## 3. Thiết Kế Tầng Quarantine (Dead-Letter Queue) & Chính Sách Replay

### 3.1. Cấu trúc bản ghi Quarantine (`data/quarantine/validation_errors.jsonl`)
Mỗi bản ghi không vượt qua bước Validation được đóng gói vào một phong bì cách ly (Quarantine Envelope) lưu tại `data/quarantine/year=YYYY/month=MM/day=DD/quarantine_<batch_id>.jsonl` và bảng `silver_quarantine_dlq` trong DuckDB:

```json
{
  "quarantine_id": "f47ac10b-58cc-4372-a567-0e02b2c3d479",
  "quarantined_at_utc": "2026-10-21T14:30:00.123456Z",
  "error_code": "ERR_MISSING_PROCESS_GUID",
  "error_stage": "SCHEMA_VALIDATION",
  "error_reason": "Mandatory field 'process_guid' is empty or missing in Sysmon Event ID 1",
  "severity": "ERROR",
  "retry_count": 0,
  "reprocess_status": "PENDING_TRIAGE",
  "raw_reference": {
    "source_file": "data/bronze/sysmon/year=2026/month=10/day=18/sysmon_batch_001.jsonl",
    "line_number": 9,
    "record_id": 99901,
    "hostname": "DESKTOP-IDEMGQU",
    "sysmon_event_id": 1
  },
  "raw_payload": {
    "timestamp": "2026-10-18T09:12:00.0000000Z",
    "source": "SYSMON",
    "sysmon_event_id": 1,
    "record_id": 99901,
    "hostname": "DESKTOP-IDEMGQU",
    "process_guid": "",
    "raw_data": {"ProcessId": "4000", "Image": "C:\\Windows\\System32\\cmd.exe"}
  }
}
```

### 3.2. Phân loại mã lỗi & Chính sách Retry / Replay
| Mã Lỗi (`error_code`) | Nguyên Nhân Gốc | Khả Năng Tự Phục Hồi | Chính Sách Xử Lý & Replay |
| :--- | :--- | :---: | :--- |
| `ERR_CORRUPTED_JSON` | Dòng JSON bị cắt cụt do tắt máy đột ngột khi đang flush file. | Không | Giữ ở trạng thái `PERMANENT_FAILURE`, kiểm tra dòng kế tiếp. |
| `ERR_UNSUPPORTED_EVENT_ID`| Sysmon sinh Event ID mới (ví dụ ID 4, 16) chưa có trong bảng phân luồng. | Có (Sau khi nâng cấp parser) | Khi cập nhật code bổ sung nhánh xử lý ID mới, chạy lệnh `--replay-quarantine` để nạp lại vào Silver. |
| `ERR_TYPE_COERCION_FAILED`| Trường số (`ProcessId`, `SourcePort`) chứa ký tự lạ không ép được sang `int`. | Tùy trường hợp | Kỹ sư Data kiểm tra `raw_payload`; nếu do format mới của Sysmon (ví dụ số hex `0x...`), cập nhật hàm parser và replay. |
| `ERR_MISSING_PROCESS_GUID`| Bản ghi thiếu khóa liên kết `ProcessGuid`. | Không | Đánh dấu `REJECTED_DATA_GAP` – tuyệt đối không đẩy vào Silver để bảo vệ tính toàn vẹn của Process Tree. |
| `ERR_INVALID_TIMESTAMP` | Chuỗi thời gian bị hỏng hoặc lệch về năm `1970` / tương lai xa. | Không | Đánh dấu `REJECTED_TIME_ANOMALY`, gửi thông báo kiểm tra đồng hồ NTP của máy trạm. |

---

## 4. Ma Trận Chất Lượng Dữ Liệu (Data Quality Matrix) & Kịch Bản Kiểm Thử

### 4.1. Sáu chiều đo lường chất lượng dữ liệu (6 Data Quality Dimensions)

| Chiều Chất Lượng | Công Thức Đo Lường (Metric Formula) | Ngưỡng Mục Tiêu (SLO) | Cách Thức Kiểm Tra Tự Động Trong Pipeline |
| :--- | :--- | :---: | :--- |
| **1. Completeness** (Tính đầy đủ) | $\frac{\text{Số bản ghi có đủ 100\% trường bắt buộc}}{\text{Tổng số bản ghi đầu vào}} \times 100\%$ | $\ge 99.5\%$ | Đếm số bản ghi không bị vướng lỗi `ERR_*_MISSING_*` tại bộ Validator. |
| **2. Validity** (Tính hợp lệ) | $\frac{\text{Số bản ghi đúng kiểu, đúng miền giá trị \& regex UUID/IP}}{\text{Tổng số bản ghi đầu vào}} \times 100\%$ | $\ge 99.5\%$ | Kiểm tra định dạng UUID 36 ký tự, IP hợp lệ, Port $\in [0, 65535]$, Enum chuẩn. |
| **3. Uniqueness** (Tính duy nhất) | $\frac{\text{COUNT(DISTINCT event\_id)}}{\text{COUNT(*)}} \times 100\%$ (trên từng bảng Silver) | **$100.0\%$** | Ràng buộc cứng `PRIMARY KEY (event_id)` trên DuckDB + kiểm tra trùng lặp trong batch. |
| **4. Consistency** (Tính nhất quán liên bảng)| $\frac{\text{Số sự kiện File/Reg/Net có process\_guid khớp bảng Process}}{\text{Tổng số sự kiện File/Reg/Net}} \times 100\%$ | $\ge 95.0\%$ *(Lưu ý tiến trình khởi chạy trước khi bật Sysmon)* | Truy vấn `LEFT JOIN` giữa `silver_file/registry/network_events` với `silver_process_events` qua `process_guid`. |
| **5. Timeliness** (Tính kịp thời) | $\Delta t_{\text{lag}} = \text{ingest\_timestamp} - \text{timestamp}$ | Trung vị $\Delta t_{\text{lag}} \le 5\text{ s}$ (Khi chạy stream) | Đo độ lệch giữa thời điểm sự kiện và thời điểm nạp vào Silver; cảnh báo nếu $|\text{timestamp} - \text{event\_utc\_time}| > 10\text{ s}$. |
| **6. Quarantine Ratio** (Tỷ lệ cách ly) | $\frac{\text{Số bản ghi rơi vào Quarantine DLQ}}{\text{Tổng số bản ghi đọc từ Bronze}} \times 100\%$ | **$\le 0.5\%$** (Môi trường chuẩn) | Nếu tỷ lệ Quarantine vượt $5\%$ trong một batch, phát cảnh báo lỗi cấu hình Collector. |

### 4.2. Kết quả kiểm chứng trên mẫu thật (Positive Samples) và mẫu lỗi có nhãn (Negative Samples)

Bộ kiểm thử thực nghiệm trong `src/pipeline/validator_poc.py` chạy trực tiếp trên **8 bản ghi thật** từ 4 tệp JSON Tuần 3 (`process.json`: 3, `file.json`: 2, `registry.json`: 2, `network.json`: 1), **1 bản ghi DNS Event ID 22 mẫu**, **2 bản ghi nạp trùng lặp (Duplicate Replay)**, và **4 bản ghi lỗi tự tạo có nhãn (Labeled Negative Samples)**:

| Mã Test Case | Phân Loại | Nguồn Dữ Liệu / Bản Ghi Cụ Thể | Hiện Tượng / Kịch Bản Kiểm Thử | Kết Quả Mong Đợi (Expected Outcome) | Trạng Thái Thực Nghiệm (`validator_poc.py`) |
| :--- | :--- | :--- | :--- | :--- | :---: |
| **TC-POS-01** | Positive (Sample Thật) | `process.json` (`record_id: 173, 184, 185`) | 3 sự kiện `PROCESS_START` (ID 1) từ máy `DESKTOP-IDEMGQU`. | Sinh đúng `event_id` UUIDv5, xóa `{}` ở `process_guid` & `parent_guid`, tách `file_sha256` và `imphash`, chèn vào `silver_process_events`. | **`PASS` (3/3 nạp thành công)** `[TESTED]` |
| **TC-POS-02** | Positive (Sample Thật) | `file.json` (`record_id: 180, 182`) | 2 sự kiện `FILE_CREATE` (ID 11) tạo tệp `.txt` và `_drop.exe`. | Tự động điền `operation = 'FILE_CREATE'`, chấp nhận `file_sha256 = NULL`, chèn vào `silver_file_events`. | **`PASS` (2/2 nạp thành công)** `[TESTED]` |
| **TC-POS-03** | Positive (Sample Thật) | `registry.json` (`record_id: 190, 191`) | 2 sự kiện `REGISTRY_SET_VALUE` (ID 13) ghi khóa `TestString` và `TestDword`. | Bóc tách `hive='HKU'`, suy diễn đúng `REG_DWORD` và `STRING_UNSPECIFIED`, chèn vào `silver_registry_events`. | **`PASS` (2/2 nạp thành công)** `[TESTED]` |
| **TC-POS-04** | Positive (Sample Thật) | `network.json` (`record_id: 194`) | 1 sự kiện `NETWORK_CONNECT` (ID 3) kết nối tới `172.66.147.243:443`. | Chuẩn hóa `protocol='TCP'`, `direction='OUTBOUND'`, ghi nhận cảnh báo nhẹ độ lệch `UtcTime` ($12.38\text{ s}$), chèn vào `silver_network_events`. | **`PASS` (1/1 nạp thành công)** `[TESTED]` |
| **TC-POS-05** | Positive (Edge Case ID 22)| Mẫu DNS Event ID 22 (`record_id: 193`) | Sự kiện `DnsQuery` phân giải tên miền không có `src_ip`, `dest_ip`, `dest_port`. | Nhờ quy tắc Conditional Validation cho `ID=22`, bản ghi **không bị đẩy vào Quarantine** mà nạp thẳng vào `silver_network_events` với `dns_query_name`. | **`PASS` (1/1 nạp thành công)** `[TESTED]` |
| **TC-DEDUP-01**| Idempotency & Dedup | Nạp lại `process.json` (`record_id: 185`) và `file.json` (`record_id: 182`) lần 2 | Giả lập chạy replay hoặc Collector gửi trùng sự kiện. | Hàm UUIDv5 sinh ra đúng khóa cũ (`5b452d31-...` và `cab6af4d-...`); DuckDB bỏ qua không chèn trùng; bộ đếm `duplicates_dropped` tăng thêm `2`. | **`PASS` (0 bản ghi trùng trong DB)** `[TESTED]` |
| **TC-NEG-01** | Negative (Labeled Fail) | Bản ghi lỗi `record_id: 90001` (Thiếu `process_guid`) | Sự kiện Event ID 1 có `"process_guid": ""` và `"ProcessGuid": ""`. | Bị chặn ngay tại tầng Validation, đẩy vào Quarantine với mã lỗi **`ERR_MISSING_PROCESS_GUID`**. | **`PASS` (Cô lập vào Quarantine)** `[TESTED]` |
| **TC-NEG-02** | Negative (Labeled Fail) | Bản ghi lỗi `record_id: "CORRUPTED_ID"` (Sai kiểu dữ liệu) | Trường `record_id` chứa chuỗi văn bản không thể ép kiểu sang số nguyên dương. | Bị chặn và đẩy vào Quarantine với mã lỗi **`ERR_INVALID_RECORD_ID`**. | **`PASS` (Cô lập vào Quarantine)** `[TESTED]` |
| **TC-NEG-03** | Negative (Labeled Fail) | Bản ghi lỗi `record_id: 90003` (Sai định dạng Timestamp) | Trường `timestamp` chứa chuỗi `"1970-01-01T00:00:00Z"` (hoặc `"NOT_A_TIMESTAMP"`). | Bị chặn và đẩy vào Quarantine với mã lỗi **`ERR_INVALID_TIMESTAMP`**. | **`PASS` (Cô lập vào Quarantine)** `[TESTED]` |
| **TC-NEG-04** | Negative (Labeled Fail) | Bản ghi lỗi `record_id: 90004` (Event ID 3 thiếu `dest_ip`) | Sự kiện `NETWORK_CONNECT` (ID 3) có `"dest_ip": null` hoặc IP sai cú pháp `"999.999.1.1"`. | Bị chặn và đẩy vào Quarantine với mã lỗi **`ERR_NET_INVALID_IP_OR_PORT`** (Không tự chế IP `0.0.0.0`). | **`PASS` (Cô lập vào Quarantine)** `[TESTED]` |

---

## 5. Đặc Tả Data Lineage & Truy Vết Điều Tra Toàn Diện (End-to-End Traceability)

### 5.1. Sơ đồ chuỗi khóa liên kết truy vết xuôi – ngược (Bidirectional Lineage Chain)
Hệ thống đảm bảo từ bất kỳ một cảnh báo nào ở tầng Gold, chuyên viên phân tích (SOC / Cyber Team) đều có thể truy vết ngược (Backward Lineage) về đúng dòng sự kiện gốc tại tầng Bronze chỉ trong 1 câu truy vấn SQL:

```text
[TẦNG GOLD / ALERT: gold_security_alerts]
  alert_id: "a1b2c3d4-..." | rule_id: "DET-001" | process_guid: "43f71ec6-8d5b-6ad4-2501-000000000400"
  contributing_event_ids: ["cab6af4d-a862-5e4c-bfb5-42b5b46081cd", "2ef59e9e-cff1-525d-a58e-aecae054b171"]
          |
          +---> (Liên kết qua feature_record_ids[])
          v
[TẦNG FEATURE STORE: gold_process_features]
  process_guid: "43f71ec6-8d5b-6ad4-2501-000000000400"
  tree_depth: 2 | is_temp_execution: TRUE | cmd_shannon_entropy: 4.18
  source_event_ids: ["cab6af4d-...", "2ef59e9e-...", "5b452d31-..."]
          |
          +---> (Liên kết 1-N qua khóa chính event_id & khóa phả hệ process_guid / parent_guid)
          v
[TẦNG SILVER: 4 Bảng Sự Kiện Chuẩn Hóa DuckDB]
  1. silver_file_events     (event_id: "cab6af4d-...", record_id: 182) -> Tạo file EDR_POC_..._drop.exe
  2. silver_process_events  (event_id: "2ef59e9e-...", record_id: 184) -> Chạy tiến trình EDR_POC_..._drop.exe
  3. silver_process_events  (event_id: "5b452d31-...", record_id: 185) -> Spawn tiến trình con conhost.exe
  4. silver_registry_events (event_id: "a95f919d-...", record_id: 191) -> Ghi khóa HKU\...\EDR_PoC\TestDword
  5. silver_network_events  (event_id: "7536126d-...", record_id: 194) -> Kết nối TCP 172.66.147.243:443
          |
          +---> (Liên kết 1-1 qua bộ khóa tự nhiên hostname + channel + record_id & cột raw_data)
          v
[TẦNG BRONZE: Tệp JSONL Nguyên Bản & Lab Ground-Truth]
  - Tệp sự kiện: process.json (184, 185), file.json (182), registry.json (191), network.json (194)
  - Tệp kịch bản: poc_run_20261018_021142.json (marker: "EDR_POC_20261018_021142", steps 1..5)
```

### 5.2. Minh chứng Truy vết Thực tế trên Chuỗi Sự kiện `poc_run_20261018_021142.json`
Khi kết nối 4 tệp JSON thực nghiệm trên máy `DESKTOP-IDEMGQU` bằng khóa `process_guid` và `parent_guid`, chúng ta khôi phục được chính xác **100% bức tranh tấn công đa bảng** của kịch bản PoC:

1. **Tiến trình gốc (Root Anchor Process):**
   * `powershell.exe` (`pid = 1616`, `process_guid = "43f71ec6-8d48-6ad4-1c01-000000000400"`), chạy lệnh `-NoProfile -ExecutionPolicy Bypass -File .\scripts\run-poc-activities.ps1`.
2. **Nhánh hành vi trực tiếp từ `powershell.exe` (`43f71ec6-8d48-6ad4-1c01-000000000400`):**
   * `09:11:51.948Z` (`record_id: 180` – `silver_file_events`): Tạo tệp `EDR_POC_20261018_021142.txt` (Khớp `step: 3_file_activity` lúc `09:11:51.846Z` trong `poc_run_20261018_021142.json`).
   * `09:11:53.277Z` (`record_id: 182` – `silver_file_events`): Drop tệp thực thi `EDR_POC_20261018_021142_drop.exe` vào thư mục `\Temp\edr_poc\`.
   * `09:11:55.836Z` (`record_id: 184` – `silver_process_events`): Khởi chạy tiến trình con `EDR_POC_20261018_021142_drop.exe` (`pid = 4648`, `process_guid = "43f71ec6-8d5b-6ad4-2501-000000000400"`, có `parent_guid = "43f71ec6-8d48-6ad4-1c01-000000000400"`).
   * `09:11:57.719Z` (`record_id: 190, 191` – `silver_registry_events`): Ghi 2 giá trị Registry `TestString` và `TestDword` (Khớp `step: 4_registry_activity` lúc `09:11:57.593Z`).
   * `09:11:59.464Z` (`record_id: 194` – `silver_network_events`): Mở kết nối HTTPS (`443`) ra địa chỉ `172.66.147.243` (Khớp `step: 5_network_activity` lúc `09:11:57.835Z`).
3. **Nhánh hành vi cháu sinh ra từ `EDR_POC_..._drop.exe` (`43f71ec6-8d5b-6ad4-2501-000000000400`):**
   * `09:11:55.886Z` (`record_id: 185` – `silver_process_events`): Sinh tiến trình cháu `conhost.exe` (`pid = 2444`, `process_guid = "43f71ec6-8d5b-6ad4-2601-000000000400"`, `tree_depth = 3`).

---

## 6. Chính Sách Lưu Trữ (Retention), Bảo Mật Quyền Riêng Tư & Dọn Dẹp Dữ Liệu Lab

### 6.1. Đề xuất thời hạn lưu trữ theo tầng (Data Retention Policy)

| Tầng Dữ Liệu | Định Dạng Lưu Trữ | Thời Hạn Lưu Trữ Mặc Định | Cơ Chế Xoay Vòng & Sao Lưu (Rotation & Backup) |
| :--- | :--- | :---: | :--- |
| **Bronze (Raw JSONL)** | `.jsonl` (Nén `.zst` sau 24 giờ) | **14 ngày** (Môi trường máy trạm cục bộ) | Xóa tự động các thư mục phân vùng `year/month/day` quá 14 ngày sau khi đã xác nhận `ingestion_status = COMMITTED` sang Silver. |
| **Quarantine (DLQ)** | `.jsonl` + Bảng DuckDB | **30 ngày** | Lưu giữ để kỹ sư Data phân tích lỗi parser; tự động dọn dẹp các bản ghi đã `RESOLVED` sau 14 ngày. |
| **Silver (Normalized)** | DuckDB + Parquet Partition | **90 ngày** | Các phân vùng quá 30 ngày trong DuckDB được xuất (offload) ra tệp Parquet nén `ZSTD` chỉ đọc (Cold Archive). |
| **Feature & Gold Alerts**| DuckDB + `alerts.jsonl` | **365 ngày** | Dung lượng rất nhỏ, lưu trữ dài hạn phục vụ điều tra lịch sử và đánh giá xu hướng an ninh. |

### 6.2. Kiểm soát truy cập & Chống rò rỉ dữ liệu nhạy cảm (PII & Credential Sanitization)
Dữ liệu điểm cuối chứa nhiều thông tin nhạy cảm như tên người dùng (`DESKTOP-IDEMGQU\Trankien`), đường dẫn thư mục cá nhân (`C:\Users\Trankien\...`), và đặc biệt là đối số dòng lệnh (`command_line`) có thể vô tình chứa mật khẩu hoặc khóa API do người dùng truyền qua CLI:
1. **Kiểm soát quyền truy cập tệp cục bộ (Windows ACLs):** Thư mục `data/bronze/`, `data/silver/`, `data/gold/` trên máy trạm chỉ cấp quyền Đọc/Ghi cho tài khoản dịch vụ `NT AUTHORITY\SYSTEM` và nhóm `Administrators`; chặn quyền đọc của các tài khoản `Users` thông thường.
2. **Che giấu thông tin mật khẩu trên `command_line` (Credential Redaction Filter):** Khi chia sẻ mẫu dữ liệu lên GitHub Repository hoặc xuất báo cáo ra ngoài máy trạm, pipeline áp dụng bộ lọc biểu thức chính quy để che các khóa nhạy cảm:
   * Regex: `(?i)(--password|-p|password=|pwd=|apikey=|token=|bearer\s+|secret=)([^\s"']+)` $\rightarrow$ Thay thế phần giá trị bằng `"[REDACTED_SECRET]"`.
   * Chuẩn hóa tên người dùng trong các bộ mẫu công khai (nếu cần): Thay `C:\Users\<Username>\` bằng biến môi trường hoặc giữ tên tài khoản Lab chuyên dụng.
3. **Quy trình cô lập và xóa dữ liệu thử nghiệm (Lab Test Data Cleanup):**
   * Mọi dữ liệu sinh ra từ kịch bản thử nghiệm (`poc_run_*.json` hoặc Atomic Red Team) đều mang dấu hiệu nhận biết qua trường `marker` (ví dụ: `"EDR_POC_20261018_021142"`) hoặc nằm trong bảng `silver_lab_test_runs`.
   * Khi chuyển sang chế độ đo Baseline hành vi bình thường cho mô hình AI, cung cấp câu lệnh dọn sạch dữ liệu thử nghiệm:
     ```sql
     -- Xóa toàn bộ sự kiện thuộc các phiên chạy thử nghiệm PoC khỏi tập huấn luyện Benign Baseline
     DELETE FROM silver_process_events WHERE command_line LIKE '%EDR_POC_%' OR image_path LIKE '%\edr_poc\%';
     ```

---

## 7. Biên Bản Rà Soát Liên Nhóm (Cyber & Software) Và Các Quyết Định Cuối Cùng

### 7.1. Rà soát yêu cầu dữ liệu cùng Cyber Team (Detection Alignment)
* **Yêu cầu từ Cyber Team:** Cần đảm bảo đủ trường cho 10 nhóm luật phát hiện (`DET-001` $\rightarrow$ `DET-010`), bao gồm cả phát hiện tạo luồng dữ liệu ẩn ADS (`Event ID 15 - FileCreateStreamHash`), phát hiện xóa tệp (`Event ID 23/26`), phát hiện ghi tệp thực thi (`Event ID 29`) và truy vấn DNS (`Event ID 22`) như đã cấu hình trong `sysmon-config.xml`.
* **Đáp ứng của Data Team trong Schema v1.1:**
  * Đã mở rộng bảng `silver_file_events` hỗ trợ đầy đủ Event ID `11, 15, 23, 26, 29`.
  * Đã bổ sung cột `imphash`, `rule_name`, `dns_query_status`, `dns_query_results`, `dest_hostname`.
  * Thiết kế sẵn SQL View `v_silver_enriched_events` nối tự động `silver_file/registry/network_events` với `silver_process_events` qua `process_guid`, giúp Cyber Team lấy được ngay `command_line` và `parent_image` khi viết luật trên sự kiện File/Network.

### 7.2. Rà soát giao diện Collector cùng Software Team (Collector Interface Alignment)
* **Thống nhất với Software Team:**
  * Software Collector giữ nguyên cấu trúc xuất JSON hiện tại (như trong `process.json`, `file.json`, `registry.json`, `network.json`) để không phải đập đi xây lại code Collector Tuần 3.
  * Bộ nạp Silver của Data Team (trong `validator_poc.py`) hỗ trợ đọc trực tiếp cả 2 chế độ: (1) JSON có sẵn khóa `"data"` từ Collector PoC Tuần 3, và (2) JSON chỉ có `"raw_data"` thô từ Sysmon XML, tự động làm phẳng và kiểm định trước khi đưa vào DuckDB.

### 7.3. Bảng câu hỏi mở (Open Questions) & Quyết định chốt (Final Decisions W05)

| Mã Câu Hỏi | Nội Dung Câu Hỏi Mở (Open Question) | Các Phương Án Cân Nhắc | Quyết Định Cuối Cùng (Chốt Tuần 5) |
| :---: | :--- | :--- | :--- |
| **OQ-W5-01** | Khi `System.TimeCreated.SystemTime` và `EventData.UtcTime` lệch nhau (như trong `network.json` lệch $12.38\text{ s}$), dùng mốc nào làm khóa thời gian chính? | **PA1:** Dùng `UtcTime`.<br>**PA2:** Dùng `SystemTime` làm cột `timestamp` chính và lưu thêm `event_utc_time`. | **Chốt PA2:** Dùng `SystemTime` làm `timestamp` chính vì có độ phân giải $100\text{ ns}$ đồng nhất trên mọi kênh Windows EventLog; lưu `UtcTime` vào `event_utc_time` để theo dõi độ trễ. |
| **OQ-W5-02** | Sự kiện DNS (Event ID 22) nên tách thành bảng `silver_dns_events` riêng hay giữ chung trong `silver_network_events`? | **PA1:** Tách thành bảng thứ 5.<br>**PA2:** Giữ trong `silver_network_events` để bảo toàn mô hình 4 nhóm sự kiện, cho phép `NULL` trên cột IP/Port khi `ID=22`. | **Chốt PA2:** Giữ trong `silver_network_events` với `event_type = 'DNS_QUERY'` và áp dụng Conditional Validation theo `sysmon_event_id` (như đã đặc tả ở Mục 1.2). |
| **OQ-W5-03** | Xử lý thế nào với trường `Event 23 (FileDelete archived)` vs `Event 26 (FileDeleteDetected)` được nêu trong comment của `sysmon-config.xml` (`Q-C2`)? | **PA1:** Chỉ nhận Event ID 23.<br>**PA2:** Ánh xạ cả Event ID 23 và Event ID 26 về chung `event_type = 'FILE_DELETE'` trong bảng `silver_file_events`. | **Chốt PA2:** Bảng `silver_file_events` chấp nhận cả ID `23` và ID `26` đều ánh xạ về `operation = 'FILE_DELETE'`, giữ nguyên `sysmon_event_id` gốc để phân biệt khi cần. |