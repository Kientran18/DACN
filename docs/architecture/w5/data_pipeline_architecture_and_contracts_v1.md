# Đặc Tả Kiến Trúc Data Pipeline & Hợp Đồng Dữ Liệu Đa Tầng (Bronze / Silver / Gold) v1.0

**Dự án:** Hệ thống Giám sát & Phát hiện Xâm nhập Điểm cuối Cục bộ (Local EDR)  
**Issue tham chiếu:** `[W05][Data] Thiết kế Bronze/Silver/Gold, schema, chất lượng và lineage dữ liệu #27`  
**Tài liệu tổng hợp đích:** `[W05][Team] Thống nhất thiết kế Data Pipeline và nghiệm thu các hợp đồng dữ liệu #26`  
**Người thực hiện:** Huỳnh Hữu Nhật (Data Engineer Lead)  
**Đồng thuận & Rà soát:** Cyber Security Team (Detection Lead), Software Team (Collector Lead)  
**Phiên bản:** 1.0.0 | **Ngày cập nhật:** 21/10/2026 (Tuần 5)

---

## 1. Phạm Vi & Phân Định Trạng Thái Thực Nghiệm

Theo đúng định hướng kế hoạch 12 tuần (hướng tới mốc thiết kế lõi M2 vào cuối Tuần 8), tài liệu này thiết lập kiến trúc tổng thể và hợp đồng dữ liệu (Data Contracts) xuyên suốt từ điểm cuối đến tầng cảnh báo. Để đảm bảo tính minh bạch kỹ thuật, mọi thành phần trong thiết kế được gắn nhãn trạng thái rõ ràng:

* **`[TESTED POC - ĐÃ KIỂM CHỨNG THỰC NGHIỆM]`:** Các thành phần đã có code thu thập mẫu thật trên máy trạm `DESKTOP-IDEMGQU` (bộ mẫu `poc_run_20261018_021142.json`, `process.json`, `file.json`, `registry.json`, `network.json`, `sysmon-config.xml` từ Tuần 3) và được kiểm chứng qua script `validator_poc.py` ở Tuần 5.
* **`[DESIGN CONTRACT W05 - HỢP ĐỒNG THIẾT KẾ TUẦN 5]`:** Các đặc tả giao diện, cấu trúc bảng DuckDB, quy tắc kiểm định chất lượng và hợp đồng Feature/Gold đã chốt giữa 3 nhóm (Data – Cyber – Software) để làm căn cứ lập trình ở các tuần tiếp theo.
* **`[PHASE 2 PLAN - KẾ HOẠCH GIAI ĐOẠN 2 (W06-W08)]`:** Các cơ chế vận hành tự động hóa hoàn toàn (liên tục đẩy stream, tự động chạy lại Quarantine theo lịch, mô hình AI chấm điểm bất thường và Detection Engine chạy thời gian thực).

---

## 2. Kiến Trúc Tổng Thể Pipeline End-to-End (Data Flow Diagram)

Luồng dữ liệu của hệ thống Local EDR tuân theo kiến trúc Medallion cải tiến (**Endpoint $\rightarrow$ Bronze $\rightarrow$ Validation/Quarantine $\rightarrow$ Silver $\rightarrow$ Feature Store $\rightarrow$ Detection/AI $\rightarrow$ Gold/Alert**):

```text
+======================================================================================================+
|                        KIẾN TRÚC DATA PIPELINE END-TO-END (LOCAL EDR W05)                            |
+======================================================================================================+

  [1. ENDPOINT TELEMETRY SOURCES]                              [LAB / ADVERSARY EMULATION]
   Microsoft Sysmon v15.15 (schemaversion 4.90)                 PoC Runner / Atomic Red Team
   Kênh: Microsoft-Windows-Sysmon/Operational                   (run-poc-activities.ps1 / Invoke-Atomic)
   Event IDs: 1, 3, 5, 11, 12, 13, 14, 15, 22, 26, 29                          |
                        |                                                      |
                        v (Win32 EventLog API / XML-to-JSON Collector)         v (Execution Logger)
+-------------------------------------------------------+    +-----------------------------------------+
| 2. TẦNG BRONZE (Immutable Raw Storage - JSONL)        |    | BRONZE LAB GROUND-TRUTH (JSON/JSONL)    |
| - Đường dẫn: data/bronze/sysmon/YYYY/MM/DD/*.jsonl    |    | - data/bronze/lab_runs/poc_run_*.json   |
| - Lưu 100% raw_data + collector metadata + manifest   |    | - Lưu marker, host, start_utc, steps[]  |
+-------------------------------------------------------+    +-----------------------------------------+
                        |                                                      |
                        v (Batch / Micro-batch Ingestion)                      |
+-------------------------------------------------------+                      |
| 3. TẦNG VALIDATION, DEDUP & NORMALIZATION ENGINE      |                      |
| - Kiểm tra cấu trúc JSON & trường bắt buộc theo ID    |                      |
| - Sinh khóa xác định: UUIDv5(Computer|Channel|RecID)  |                      |
| - Chuẩn hóa: Strip GUID {}, UTC Timestamp, Type Cast  |                      |
+-----------------------+-------------------------------+                      |
                        |                                                      |
         +--------------+--------------+                                       |
         | (Hợp lệ - PASS)             | (Vi phạm - FAIL)                      |
         v                             v                                       |
+-------------------------------+  +----------------------------------------+  |
| 4. TẦNG SILVER (Normalized)   |  | 3B. QUARANTINE / DEAD-LETTER (DLQ)     |  |
| DuckDB: endpoint_silver.duckdb|  | - data/quarantine/YYYY/MM/DD/*.jsonl   |  |
| - silver_process_events       |  | - Lưu: quarantine_id, error_code,      |  |
| - silver_file_events          |  |   error_reason, raw_reference, payload |  |
| - silver_registry_events      |  | - Hỗ trợ Replay sau khi vá lỗi parser  |  |
| - silver_network_events       |  +----------------------------------------+  |
| - silver_lab_test_runs <------+----------------------------------------------+
| - SQL Enriched Views          |
+---------------+---------------+
                |
                v (SQL Window Functions + Recursive CTE Lineage + Python UDF)
+------------------------------------------------------------------------------------------------------+
| 5. TẦNG FEATURE STORE (Behavioral & Structural Features Contract)                                    |
| - Bảng: gold_process_features (DuckDB / Parquet)                                                     |
| - Nhóm đặc trưng: Process Tree Depth, Sliding Window Counters (5s/10s/60s), Command-Line Entropy     |
| - Liên kết truy vết ngược: source_event_ids[] -> silver_*.event_id                                   |
+---------------+--------------------------------------------------------------------------------------+
                |
                +-------------------------------+------------------------------+
                | (Luồng Rule-based Detection)  | (Luồng AI Anomaly Scoring)   |
                v                               v                              |
+-------------------------------+  +----------------------------------------+  |
| 6A. CYBER DETECTION ENGINE    |  | 6B. AI INFERENCE ENGINE [PHASE 2]      |  |
| - Khớp luật DET-001..DET-010  |  | - Isolation Forest / Autoencoder       |  |
| - Đối chiếu MITRE ATT&CK      |  | - Chấm điểm anomaly_score (0.0 -> 1.0) |  |
+---------------+---------------+  +--------------------+-------------------+  |
                |                                       |                      |
                +-------------------+-------------------+                      |
                                    |                                          |
                                    v                                          |
+------------------------------------------------------------------------------+-----------------------+
| 7. TẦNG GOLD / ALERT (Analytical & Investigation Contract)                                           |
| - Bảng: gold_security_alerts (DuckDB) & xuất JSONL cho UI/CLI                                        |
| - Chứa: alert_id, severity, mitre_technique_id, process_guid, contributing_event_ids[], lineage_trace|
| - Đối chiếu với silver_lab_test_runs để tính Precision / Recall / F1-Score trong môi trường Lab      |
+------------------------------------------------------------------------------------------------------+
```

### Giải thích trách nhiệm từng tầng (Layer Responsibilities)

| Tầng Kiến Trúc | Trách Nhiệm Cốt Lõi | Đầu Vào (Input) | Đầu Ra (Output) | Công Nghệ Lưu Trữ / Xử Lý |
| :--- | :--- | :--- | :--- | :--- |
| **1. Collector** `[TESTED POC]` | Đọc sự kiện từ kênh `Microsoft-Windows-Sysmon/Operational`, bóc tách XML sang cấu trúc JSON chuẩn và ghi xuống đĩa cục bộ. | Luồng sự kiện `.evtx` từ nhân Windows (Sysmon Driver). | Các dòng bản ghi JSON (Interchange Envelope). | Python Collector (`win32evtlog` / PowerShell PoC). |
| **2. Bronze Layer** `[DESIGN W05]` | Lưu trữ bất biến (Immutable, Append-only) toàn bộ dữ liệu thô nhận từ Collector kèm thông tin kiểm toán để phục vụ chạy lại (Replay) 100%. | Luồng JSON từ Collector + File log chạy kịch bản Lab (`poc_run_*.json`). | Các tệp `.jsonl` phân vùng theo ngày kèm tệp kiểm kê `manifest.json`. | Hệ thống tệp cục bộ (JSON Lines + SHA-256 Manifest). |
| **3. Validation & Quarantine** `[TESTED POC]` | Kiểm tra tính hợp lệ của schema theo từng `sysmon_event_id`, ép kiểu an toàn, sinh khóa `UUIDv5` chống trùng lặp và cô lập bản ghi lỗi. | Các dòng bản ghi từ tệp Bronze JSONL. | Bản ghi sạch đẩy vào Silver; bản ghi lỗi đẩy vào Quarantine DLQ. | Python (`Pydantic` / Custom Validator) + JSONL DLQ. |
| **4. Silver Layer** `[TESTED POC]` | Lưu trữ dữ liệu đã chuẩn hóa, làm phẳng (flattened) thành 4 bảng sự kiện chuyên biệt và các SQL Views làm giàu ngữ cảnh tiến trình. | Bản ghi hợp lệ đã qua bước Validation & Deduplication. | 4 bảng sự kiện chuẩn hóa + 1 bảng Lab Ground-Truth trong DuckDB. | **DuckDB** (`endpoint_silver.duckdb`) & Parquet Backup. |
| **5. Feature Engineering** `[DESIGN W05]` | Tính toán các đặc trưng hành vi theo cửa sổ thời gian trượt, độ sâu cây phả hệ tiến trình và độ hỗn loạn chuỗi lệnh (Shannon Entropy). | Truy vấn từ 4 bảng Silver trong DuckDB. | Bảng vector đặc trưng `gold_process_features` gắn kèm mảng `source_event_ids`. | DuckDB SQL (`WITH RECURSIVE`, Windowing) + Python. |
| **6. Detection / AI** `[PHASE 2]` | Thực thi bộ luật phát hiện hành vi (DET-001 $\rightarrow$ DET-010) của nhóm Cyber và mô hình học máy phát hiện bất thường. | Bảng Silver / Enriched Views (cho Rule) và `gold_process_features` (cho AI). | Các phát hiện (Detections) kèm điểm số tin cậy và nhãn MITRE ATT&CK. | SQL Rule Engine / Python Detection Runner. |
| **7. Gold / Alert** `[DESIGN W05]` | Hợp nhất kết quả phát hiện thành cảnh báo an ninh hoàn chỉnh, cung cấp đầy đủ thông tin truy vết ngược về tận bản ghi Bronze gốc. | Kết quả từ Detection Engine & AI Inference. | Bảng `gold_security_alerts` và file xuất cảnh báo `alerts.jsonl`. | DuckDB (`endpoint_gold.duckdb`) + JSONL Alert Output. |

---

## 3. Thiết Kế Chi Tiết Tầng Bronze (Raw Storage & Integrity Spec)

### 3.1. Nguyên tắc thiết kế tầng Bronze
1. **Bất biến tuyệt đối (Immutability):** Dữ liệu một khi đã ghi xuống tầng Bronze không bao giờ bị sửa đổi (`UPDATE`) hoặc ghi đè.
2. **Bảo toàn ngữ cảnh gốc (`ADR 0003`):** Lưu giữ nguyên vẹn đối tượng `raw_data` (chứa toàn bộ các cặp khóa-giá trị của thẻ `<EventData>` từ Sysmon XML) và các thông số `<System>` mà không tự ý cắt bỏ trường lạ.
3. **Phân biệt thời gian xảy ra sự kiện và thời gian thu thập:** Bổ sung trường `ingest_timestamp_utc` và `batch_id` để đo độ trễ của pipeline (Ingestion Lag).

### 3.2. Cấu trúc thư mục và quy ước đặt tên tệp (File Organization)
```text
data/
└── bronze/
    ├── sysmon/
    │   └── year=2026/
    │       └── month=10/
    │           └── day=18/
    │               ├── sysmon_batch_20261018_091142_001.jsonl
    │               └── sysmon_batch_20261018_091142_001.manifest.json
    └── lab_runs/
        └── poc_run_20261018_021142.json
```

### 3.3. Hợp đồng dữ liệu bản ghi Bronze (Bronze Record Contract v1.1)
Trong thực nghiệm Tuần 3 (`process.json`, `file.json`, `registry.json`, `network.json`), Collector đã xuất ra cấu trúc JSON kết hợp giữa thông tin `<System>` ở cấp ngoài và `<EventData>` trong khóa `raw_data`. Ở Tuần 5, hợp đồng tầng Bronze chính thức hóa cấu trúc này và bổ sung 3 trường metadata kiểm toán (`bronze_ingest_utc`, `collector_batch_id`, `raw_payload_sha256`):

| Trường Bronze | Kiểu Dữ Liệu | Bắt Buộc | Nguồn Cung Cấp | Mô Tả Chi Tiết |
| :--- | :--- | :---: | :--- | :--- |
| `bronze_ingest_utc` | `STRING (ISO 8601)` | **Có** | Collector / Ingestor | Thời điểm bản ghi được ghi xuống tệp Bronze cục bộ (UTC, hậu tố `Z`). |
| `collector_batch_id`| `STRING` | **Có** | Collector | Mã định danh lô thu thập (ví dụ: `batch_20261018_091142`). |
| `raw_payload_sha256`| `STRING(64)` | **Có** | Collector / Ingestor | Mã băm SHA-256 của chuỗi JSON canonical `raw_data` để kiểm tra tính toàn vẹn. |
| `timestamp` | `STRING (ISO 8601)` | **Có** | `System.TimeCreated.SystemTime` | Thời điểm nhân Windows ghi nhận sự kiện (độ phân giải $100\text{ ns}$, UTC). |
| `source` | `STRING` | **Có** | Collector Constant | Giá trị cố định: `"SYSMON"`. |
| `sysmon_event_id` | `INTEGER` | **Có** | `System.EventID` | Mã sự kiện gốc của Sysmon (`1`, `3`, `5`, `11`, `12`, `13`, `14`, `15`, `22`, `26`, `29`). |
| `channel` | `STRING` | **Có** | `System.Channel` | Kênh log Windows: `"Microsoft-Windows-Sysmon/Operational"`. |
| `record_id` | `INTEGER` | **Có** | `System.EventRecordID` | Số thứ tự bản ghi tăng đơn điệu trong kênh log của máy trạm. |
| `hostname` | `STRING` | **Có** | `System.Computer` | Tên định danh máy trạm (ví dụ: `"DESKTOP-IDEMGQU"`). |
| `raw_data` | `OBJECT (JSON)` | **Có** | `EventData.*` | Toàn bộ từ điển dữ liệu gốc của Sysmon chưa qua ép kiểu hay cắt gọt. |

### 3.4. Đặc tả tệp kiểm kê `manifest.json` và cơ chế Reprocessing
Mỗi tệp `.jsonl` khi đóng lô (batch flush) phải đi kèm một tệp `.manifest.json` phục vụ kiểm tra toàn vẹn (Integrity Check) và theo dõi trạng thái nạp (Checkpoint):

```json
{
  "batch_id": "sysmon_batch_20261018_091142_001",
  "file_name": "sysmon_batch_20261018_091142_001.jsonl",
  "host_name": "DESKTOP-IDEMGQU",
  "created_at_utc": "2026-10-18T09:12:05.0000000Z",
  "record_count": 8,
  "min_record_id": 173,
  "max_record_id": 194,
  "min_event_timestamp_utc": "2026-10-18T09:11:45.2533473Z",
  "max_event_timestamp_utc": "2026-10-18T09:11:59.4649146Z",
  "file_sha256": "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
  "schema_version": "1.1.0",
  "ingestion_status": "COMMITTED"
}
```
* **Khả năng chạy lại (Reprocessing):** Khi nâng cấp logic bóc tách ở tầng Silver (ví dụ: thêm cột mới từ `raw_data`), kỹ sư dữ liệu chỉ cần chạy lệnh replay trỏ vào thư mục `data/bronze/sysmon/`. Pipeline sẽ kiểm tra `file_sha256` khớp với `manifest.json` trước khi nạp lại vào DuckDB.

---

## 4. Thiết Kế Chi Tiết Tầng Silver (Normalized Schema v1.1 & DuckDB Spec)

### 4.1. Khung bao đóng chuẩn hóa (Common Silver Envelope v1.1)
Ở tầng Silver trong DuckDB, đối tượng lồng `data` từ JSON của Collector được **làm phẳng hoàn toàn (flattened)** thành các cột vật lý có kiểu dữ liệu chặt chẽ để tối ưu tốc độ quét cột (Vectorized Columnar Execution). Mọi bảng trong 4 nhóm sự kiện đều có chung 12 cột đầu tiên thuộc **Common Silver Envelope v1.1**:

| STT | Tên Cột Silver (v1.1) | Kiểu DuckDB | Null? | Nguồn Ánh Xạ & Quy Tắc Chuẩn Hóa |
| :---: | :--- | :--- | :---: | :--- |
| 1 | `event_id` | `VARCHAR(36)` | `NOT NULL` | **`PRIMARY KEY`** – Sinh từ hàm xác định $\text{UUIDv5}(\text{hostname} \mid \text{channel} \mid \text{record\_id})$. |
| 2 | `timestamp` | `TIMESTAMPTZ` | `NOT NULL` | Thời điểm `System.TimeCreated.SystemTime` chuẩn hóa về UTC. |
| 3 | `event_utc_time` | `TIMESTAMPTZ` | `NULL` | Thời điểm `raw_data.UtcTime` trong `EventData` (phục vụ kiểm tra độ trễ ghi log). |
| 4 | `ingest_timestamp` | `TIMESTAMPTZ` | `NOT NULL` | Thời điểm pipeline chèn bản ghi vào DuckDB Silver (UTC). |
| 5 | `source` | `VARCHAR(32)` | `NOT NULL` | Hằng số `'SYSMON'`. |
| 6 | `event_type` | `VARCHAR(32)` | `NOT NULL` | Enum chuẩn hóa: `'PROCESS_START'`, `'PROCESS_TERMINATE'`, `'FILE_CREATE'`, `'FILE_DELETE'`, `'FILE_STREAM_HASH'`, `'FILE_EXECUTABLE_DETECTED'`, `'REGISTRY_SET_VALUE'`, `'REGISTRY_CREATE_KEY'`, `'REGISTRY_DELETE_KEY'`, `'REGISTRY_DELETE_VALUE'`, `'REGISTRY_RENAME'`, `'NETWORK_CONNECT'`, `'DNS_QUERY'`. |
| 7 | `sysmon_event_id` | `INTEGER` | `NOT NULL` | Mã sự kiện Sysmon gốc: `1, 3, 5, 11, 12, 13, 14, 15, 22, 23, 26, 29`. |
| 8 | `channel` | `VARCHAR(64)` | `NOT NULL` | Mặc định `'Microsoft-Windows-Sysmon/Operational'`. |
| 9 | `record_id` | `BIGINT` | `NOT NULL` | Chỉ số `EventRecordID` nguyên dương ($> 0$). |
| 10 | `hostname` | `VARCHAR(64)` | `NOT NULL` | Chuẩn hóa `.strip().upper()` từ `System.Computer` (ví dụ: `'DESKTOP-IDEMGQU'`). |
| 11 | `process_guid` | `VARCHAR(36)` | `NOT NULL` | Đã xóa ngoặc nhọn `{}` và chuyển về chữ thường `.lower()` từ `raw_data.ProcessGuid`. |
| 12 | `rule_name` | `VARCHAR` | `NULL` | Lấy từ `raw_data.RuleName` (nếu bằng `'-'` hoặc rỗng thì gán `NULL`). |
| 13 | `raw_data` | `JSON` | `NOT NULL` | Chuỗi JSON bảo tồn nguyên trạng đối tượng `raw_data` (`ADR 0003`). |

---

### 4.2. Đặc tả 4 bảng sự kiện chuyên biệt (Category Tables v1.1)

#### Bảng 1: `silver_process_events` (Sysmon Event ID 1 & Event ID 5)
Lưu ý quan trọng: Sự kiện **Event ID 5 (`PROCESS_TERMINATE`)** của Sysmon chỉ cung cấp `UtcTime`, `ProcessGuid`, `ProcessId`, `Image` và `User`; nó **không có** `ParentProcessGuid`, `ParentProcessId`, `CommandLine` hay `Hashes`. Do đó, hợp đồng dữ liệu v1.1 quy định tính bắt buộc (Nullability) phân biệt rõ giữa Event ID 1 và Event ID 5:

| Tên Cột | Kiểu DuckDB | Bắt Buộc Khi `ID=1` | Bắt Buộc Khi `ID=5` | Nguồn (`raw_data.*`) & Logic Biến Đổi |
| :--- | :--- | :---: | :---: | :--- |
| *(13 cột Envelope)* | *(Theo Envelope)* | **Có** | **Có** | Kế thừa đầy đủ Common Silver Envelope v1.1. |
| `pid` | `INTEGER` | **Có** | **Có** | `int(raw_data.ProcessId)` ($> 0$). |
| `ppid` | `INTEGER` | **Có** | Không (`NULL`) | `int(raw_data.ParentProcessId)` (Chỉ có ở Event ID 1). |
| `parent_guid` | `VARCHAR(36)` | **Có** | Không (`NULL`) | `strip_guid(raw_data.ParentProcessGuid)` (Chỉ có ở Event ID 1). |
| `image_path` | `VARCHAR` | **Có** | **Có** | `raw_data.Image`. |
| `command_line` | `VARCHAR` | **Có** | Không (`NULL`) | `raw_data.CommandLine`. |
| `current_working_directory`| `VARCHAR` | Không | Không (`NULL`) | `raw_data.CurrentDirectory`. |
| `user_name` | `VARCHAR` | Không | Không | `raw_data.User` (ví dụ: `'DESKTOP-IDEMGQU\Trankien'`). |
| `integrity_level` | `VARCHAR(16)` | Không | Không (`NULL`) | `raw_data.IntegrityLevel` (`'Low'`, `'Medium'`, `'High'`, `'System'`). |
| `session_id` | `INTEGER` | Không | Không (`NULL`) | `int(raw_data.TerminalSessionId)`. |
| `parent_image` | `VARCHAR` | Không | Không (`NULL`) | `raw_data.ParentImage`. |
| `parent_command_line`| `VARCHAR` | Không | Không (`NULL`) | `raw_data.ParentCommandLine`. |
| `file_sha256` | `VARCHAR(64)` | Không | Không (`NULL`) | Trích xuất `SHA256=...` từ `raw_data.Hashes` (viết hoa 64 ký tự hex). |
| `imphash` | `VARCHAR(32)` | Không | Không (`NULL`) | Trích xuất `IMPHASH=...` từ `raw_data.Hashes`. |
| `hashes` | `JSON` | Không | Không (`NULL`) | Từ điển JSON chứa toàn bộ các thuật toán băm thu được. |

#### Bảng 2: `silver_file_events` (Sysmon Event ID 11, 15, 23, 26, 29)
Bám sát tệp cấu hình `sysmon-config.xml` của nhóm (bật các Event ID `11`, `15`, `26`, `29` và dự phòng `23`):

| Tên Cột | Kiểu DuckDB | Bắt Buộc | Nguồn (`raw_data.*`) & Logic Biến Đổi |
| :--- | :--- | :---: | :--- |
| *(13 cột Envelope)* | *(Theo Envelope)* | **Có** | Kế thừa Common Silver Envelope v1.1. |
| `operation` | `VARCHAR(32)` | **Có** | Đồng bộ từ `event_type`: `11` $\rightarrow$ `'FILE_CREATE'`, `15` $\rightarrow$ `'FILE_STREAM_HASH'`, `23/26` $\rightarrow$ `'FILE_DELETE'`, `29` $\rightarrow$ `'FILE_EXECUTABLE_DETECTED'`. |
| `pid` | `INTEGER` | Không | `int(raw_data.ProcessId)`. |
| `file_path` | `VARCHAR` | **Có** | `raw_data.TargetFilename`. |
| `file_extension` | `VARCHAR(32)` | Không | Phần mở rộng viết thường không có dấu chấm (ví dụ: `'exe'`, `'txt'`). |
| `image_path` | `VARCHAR` | **Có** | `raw_data.Image` (Tiến trình thực hiện thao tác tệp). |
| `creation_utc_time` | `TIMESTAMPTZ` | Không | Parse từ `raw_data.CreationUtcTime` (nếu có). |
| `user_name` | `VARCHAR` | Không | `raw_data.User`. |
| `file_sha256` | `VARCHAR(64)` | Không | Có giá trị ở Event ID `15`, `23`, `26`, `29`; mang giá trị `NULL` ở Event ID `11`. |
| `hashes` | `JSON` | Không | Dictionary các mã băm trích từ `raw_data.Hashes` (mặc định `'{}'`). |

#### Bảng 3: `silver_registry_events` (Sysmon Event ID 12, 13, 14)

| Tên Cột | Kiểu DuckDB | Bắt Buộc | Nguồn (`raw_data.*`) & Logic Biến Đổi |
| :--- | :--- | :---: | :--- |
| *(13 cột Envelope)* | *(Theo Envelope)* | **Có** | Kế thừa Common Silver Envelope v1.1. |
| `operation` | `VARCHAR(32)` | **Có** | `raw_data.EventType` (`'SetValue'`, `'CreateKey'`, `'DeleteKey'`, `'DeleteValue'`, `'RenameKey'`). |
| `pid` | `INTEGER` | Không | `int(raw_data.ProcessId)`. |
| `target_object` | `VARCHAR` | **Có** | `raw_data.TargetObject` (Đường dẫn khóa/giá trị Registry đầy đủ). |
| `hive` | `VARCHAR(16)` | **Có** | Phần tử đầu tiên sau khi tách `target_object` theo dấu `\` (`'HKLM'`, `'HKU'`, `'HKCU'`, `'HKCR'`). |
| `key_path` | `VARCHAR` | **Có** | Nhánh đường dẫn khóa sau khi tách bỏ `hive` và `value_name`. |
| `value_name` | `VARCHAR` | Không | Phần tử cuối cùng của `target_object` (khi `operation` là `'SetValue'` hoặc `'DeleteValue'`). |
| `value_type_inferred`| `VARCHAR(32)` | Không | Suy diễn từ `Details`: `'REG_DWORD'`, `'REG_QWORD'`, `'REG_BINARY'`, `'STRING_UNSPECIFIED'`, hoặc `'UNKNOWN'`. |
| `details` | `VARCHAR` | Không | `raw_data.Details` (Bắt buộc có khi `sysmon_event_id = 13`, có thể `NULL` khi `id = 12`). |
| `new_name` | `VARCHAR` | Không | `raw_data.NewName` (Chỉ xuất hiện khi `sysmon_event_id = 14` - đổi tên khóa). |
| `image_path` | `VARCHAR` | **Có** | `raw_data.Image`. |
| `user_name` | `VARCHAR` | Không | `raw_data.User`. |

#### Bảng 4: `silver_network_events` (Sysmon Event ID 3: NetworkConnect & Event ID 22: DnsQuery)
**Lưu ý thiết kế trọng tâm cho DNS Event ID 22:** Trong `sysmon-config.xml`, cả `NetworkConnect` (ID 3) và `DnsQuery` (ID 22) đều được thu thập. Tuy nhiên, bản ghi Sysmon Event ID 22 **chỉ chứa** `QueryName`, `QueryStatus`, `QueryResults`, `ProcessGuid`, `ProcessId`, `Image`, `User` mà **không chứa** `Protocol`, `Initiated`, `SourceIp`, `SourcePort`, `DestinationIp`, `DestinationPort`. Do đó, hợp đồng bảng `silver_network_events` áp dụng **Conditional Mandatory Rules** theo `sysmon_event_id`:

| Tên Cột | Kiểu DuckDB | Bắt Buộc Khi `ID=3` (Socket) | Bắt Buộc Khi `ID=22` (DNS) | Nguồn (`raw_data.*`) & Logic Biến Đổi |
| :--- | :--- | :---: | :---: | :--- |
| *(13 cột Envelope)* | *(Theo Envelope)* | **Có** | **Có** | `event_type = 'NETWORK_CONNECT'` (ID 3) hoặc `'DNS_QUERY'` (ID 22). |
| `pid` | `INTEGER` | Không | Không | `int(raw_data.ProcessId)`. |
| `image_path` | `VARCHAR` | **Có** | **Có** | `raw_data.Image`. |
| `user_name` | `VARCHAR` | Không | Không | `raw_data.User`. |
| `protocol` | `VARCHAR(16)` | **Có** | Không (Mặc định `'UDP'`) | `raw_data.Protocol.upper()` (`'TCP'`, `'UDP'`). |
| `direction` | `VARCHAR(16)` | **Có** | Không (Mặc định `'OUTBOUND'`) | `'OUTBOUND'` nếu `raw_data.Initiated == 'true'`, ngược lại `'INBOUND'`. |
| `ip_version` | `VARCHAR(8)` | Không | Không (`NULL`) | `'IPv6'` nếu `raw_data.SourceIsIpv6 == 'true'`, ngược lại `'IPv4'`. |
| `src_ip` | `VARCHAR(45)` | **Có** | Không (`NULL`) | `raw_data.SourceIp` (Cho phép `NULL` khi là sự kiện DNS ID 22). |
| `src_port` | `INTEGER` | **Có** | Không (`NULL`) | `int(raw_data.SourcePort)` ($0 \le \text{port} \le 65535$). |
| `dest_ip` | `VARCHAR(45)` | **Có** | Không (`NULL`) | `raw_data.DestinationIp` (Cho phép `NULL` khi là sự kiện DNS ID 22). |
| `dest_port` | `INTEGER` | **Có** | Không (`NULL`) | `int(raw_data.DestinationPort)` ($0 \le \text{port} \le 65535$). |
| `dest_hostname` | `VARCHAR` | Không | Không (`NULL`) | `raw_data.DestinationHostname` (nếu bằng `'-'` thì gán `NULL`). |
| `dns_query_name` | `VARCHAR` | Không (`NULL`) | **Có** | `raw_data.QueryName` (Tên miền truy vấn ở Event ID 22). |
| `dns_query_status` | `INTEGER` | Không (`NULL`) | Không | `int(raw_data.QueryStatus)` (Ví dụ: `0` = Thành công, `9003` = `NXDOMAIN`). |
| `dns_query_results` | `VARCHAR` | Không (`NULL`) | Không | `raw_data.QueryResults` (Danh sách IP hoặc CNAME phân giải được). |

---

### 4.3. Thiết kế Lưu trữ Silver & Truy vấn Cục bộ với DuckDB

1. **Lựa chọn kiến trúc lưu trữ:**
   * Sử dụng cơ sở dữ liệu phân tích nhúng **DuckDB** (`data/silver/endpoint_silver.duckdb`) kết hợp xuất định kỳ ra định dạng cột nén **Apache Parquet** (`ZSTD` compression) theo phân vùng ngày.
   * *Lý do lựa chọn:* Chạy in-process ngay trong tiến trình Python mà không cần cài đặt dịch vụ cơ sở dữ liệu nền (như PostgreSQL hay OpenSearch), tiêu tốn bộ nhớ RAM cực thấp nhưng hỗ trợ đầy đủ SQL OLAP (Window Functions, `WITH RECURSIVE`, JSON extraction).
2. **Chiến lược Khóa chính & Chỉ mục (Primary Key & Indexing Strategy):**
   * Trên cả 4 bảng Silver, cột `event_id` được khai báo là `PRIMARY KEY` để kích hoạt chỉ mục ART (Adaptive Radix Tree) tự động của DuckDB, phục vụ thao tác chống trùng lặp `INSERT OR IGNORE INTO ...` (hoặc `ON CONFLICT (event_id) DO NOTHING`).
   * Tạo chỉ mục phụ trên khóa liên kết tiến trình và thời gian:
     ```sql
     CREATE INDEX idx_proc_guid_ts ON silver_process_events (process_guid, timestamp);
     CREATE INDEX idx_proc_parent_guid ON silver_process_events (parent_guid);
     CREATE INDEX idx_file_proc_guid ON silver_file_events (process_guid, timestamp);
     CREATE INDEX idx_reg_proc_guid ON silver_registry_events (process_guid, timestamp);
     CREATE INDEX idx_net_proc_guid ON silver_network_events (process_guid, timestamp);
     ```
   * Khi lưu trữ sang tệp Parquet dài hạn, các bản ghi được sắp xếp vật lý theo `ORDER BY hostname, timestamp ASC, record_id ASC` để tối ưu cơ chế **Zone Map (Min/Max Row Group Pruning)** của DuckDB.
3. **Phân biệt Mục tiêu Hiệu năng (Design Targets) và Số đo Thực nghiệm (Empirical Measurements):**
   * **`[EMPIRICAL MEASUREMENT - ĐÃ ĐO TRÊN POC]`:** Tốc độ sinh khóa xác định `UUIDv5` kết hợp chuẩn hóa chuỗi GUID và suy diễn kiểu Registry đạt **$> 200,000\text{ events/s}$** trên CPU đơn luồng; thời gian nạp và kiểm định bộ mẫu thực nghiệm 8 bản ghi PoC (`process.json`, `file.json`, `registry.json`, `network.json`) vào DuckDB mất **$< 15\text{ ms}$**.
   * **`[DESIGN TARGET W05-W08 - MỤC TIÊU HIỆU NĂNG]`:**
     * Mức chiếm dụng tài nguyên trên máy trạm: CPU trung bình **$< 3\%$**, bộ nhớ RAM của tiến trình pipeline **$< 150\text{ MB}$**.
     * Thông lượng nạp theo lô nhỏ (Micro-batch 5 giây): Xử lý mượt mà tốc độ sinh sự kiện đỉnh điểm (burst) lên tới **$1,000\text{ events/s}$**.
     * Độ trễ truy vấn tạo đặc trưng cửa sổ trượt (Sliding Window Query Latency) trên tập dữ liệu 24 giờ ($~500,000$ sự kiện): **$< 500\text{ ms}$**.

---

## 5. Hợp Đồng Dữ Liệu Tầng Feature Store & Gold / Alert Layer

Tầng Feature Store và Gold được định nghĩa ở mức **Hợp đồng Dữ liệu (Data Contract)** để nhóm Data cung cấp đầu vào chuẩn cho nhóm Cyber (Detection Engine) và mô hình AI ở Giai đoạn 2.

### 5.1. Hợp đồng bảng Feature Store: `gold_process_features`
Mỗi dòng trong bảng `gold_process_features` đại diện cho vector đặc trưng hành vi tổng hợp của một thực thể tiến trình (`process_guid`) tại một mốc cửa sổ đánh giá:

| Tên Cột Đặc Trưng | Kiểu DuckDB | Công Thức Tính Toán / Nguồn Dữ Liệu Silver | Mục Đích Phục Vụ Detection & AI |
| :--- | :--- | :--- | :--- |
| `feature_record_id` | `VARCHAR(36)` | `PRIMARY KEY` – $\text{UUIDv5}(\text{process\_guid} \mid \text{window\_end\_utc})$. | Định danh duy nhất của bản ghi vector đặc trưng. |
| `process_guid` | `VARCHAR(36)` | Khóa thực thể lấy từ `silver_process_events.process_guid`. | Khóa liên kết chính để truy vết tiến trình. |
| `hostname` | `VARCHAR(64)` | `silver_process_events.hostname`. | Định danh máy trạm. |
| `window_start_utc` | `TIMESTAMPTZ` | Thời điểm bắt đầu cửa sổ quan sát. | Phục vụ phân tích chuỗi thời gian. |
| `window_end_utc` | `TIMESTAMPTZ` | Thời điểm kết thúc cửa sổ quan sát. | Phục vụ phân tích chuỗi thời gian. |
| `tree_depth` | `INTEGER` | Đếm đệ quy số bậc tổ tiên qua `parent_guid = process_guid` (gốc = `1`). | Phát hiện chuỗi spawn bất thường nhiều tầng (Office $\rightarrow$ CMD $\rightarrow$ PowerShell $\rightarrow$ Drop.exe). |
| `child_process_count_10s`| `INTEGER` | Số tiến trình con có `parent_guid = process_guid` sinh ra trong $10\text{ s}$. | Phát hiện hành vi recon hàng loạt (`whoami`, `ipconfig`, `net`). |
| `cmd_length` | `INTEGER` | `LENGTH(command_line)`. | Phát hiện câu lệnh mã hóa dài bất thường. |
| `cmd_shannon_entropy`| `DOUBLE` | $H(X) = -\sum P(x_i)\log_2 P(x_i)$ tính trên chuỗi `command_line`. | Phát hiện câu lệnh bị làm rối (Obfuscation / Base64 EncodedCommand, ngưỡng thường $> 4.5$). |
| `is_temp_execution` | `BOOLEAN` | `TRUE` nếu `image_path` chứa `\Temp\`, `\Downloads\`, `\AppData\`. | Phát hiện thực thi binary rơi (Drop-and-Execute) như trong mẫu `record_id: 184`. |
| `file_create_count_5s`| `INTEGER` | Đếm bản ghi `silver_file_events` (`FILE_CREATE`) cùng `process_guid` trong $5\text{ s}$. | Phát hiện hành vi mã hóa/ghi tệp hàng loạt (Ransomware / Dropper). |
| `file_delete_count_5s`| `INTEGER` | Đếm bản ghi `silver_file_events` (`FILE_DELETE`) cùng `process_guid` trong $5\text{ s}$. | Phát hiện hành vi xóa tệp gốc hoặc xóa dấu vết. |
| `reg_set_value_count_10s`| `INTEGER` | Đếm bản ghi `silver_registry_events` (`SetValue`) cùng `process_guid` trong $10\text{ s}$. | Phát hiện thiết lập Persistence hoặc sửa đổi cấu hình hệ thống. |
| `net_outbound_count_30s`| `INTEGER` | Đếm bản ghi `silver_network_events` (`OUTBOUND`) cùng `process_guid` trong $30\text{ s}$. | Phát hiện C2 Beaconing hoặc quét mạng. |
| `unique_dest_ip_count_60s`| `INTEGER` | `COUNT(DISTINCT dest_ip)` của cùng `process_guid` trong $60\text{ s}$. | Phát hiện quét cổng/mạng ngang (Lateral Movement). |
| `dns_query_count_60s`| `INTEGER` | Đếm sự kiện `DNS_QUERY` (Event ID 22) của `process_guid` trong $60\text{ s}$. | Phát hiện DNS Tunneling hoặc DGA (Domain Generation Algorithms). |
| `source_event_ids` | `VARCHAR[]` | Mảng `ARRAY_AGG(DISTINCT event_id)` của mọi sự kiện Silver cấu thành vector. | **Liên kết truy vết bắt buộc** từ Feature ngược về các sự kiện Silver gốc. |
| `ground_truth_label` | `VARCHAR(32)` | Nhãn từ `silver_lab_test_runs` (ví dụ: `'T1059.001'` hoặc `'BENIGN'`). | Chỉ dùng trong môi trường Lab để huấn luyện/đánh giá độ chính xác mô hình. |

### 5.2. Hợp đồng bảng Cảnh báo Gold: `gold_security_alerts`
Khi Cyber Detection Engine (khớp luật `DET-001` $\rightarrow$ `DET-010`) hoặc mô hình AI phát hiện hành vi độc hại, kết quả được ghi vào bảng `gold_security_alerts`:

| Tên Cột | Kiểu DuckDB | Bắt Buộc | Ý Nghĩa Nghiệp Vụ & Điều Tra (Investigation) |
| :--- | :--- | :---: | :--- |
| `alert_id` | `VARCHAR(36)` | **Có** | `PRIMARY KEY` – $\text{UUIDv5}(\text{rule\_id} \mid \text{process\_guid} \mid \text{first\_seen\_utc})$. |
| `created_at_utc` | `TIMESTAMPTZ` | **Có** | Thời điểm sinh cảnh báo tại tầng Gold. |
| `first_seen_utc` | `TIMESTAMPTZ` | **Có** | Thời điểm của sự kiện sớm nhất cấu thành cảnh báo. |
| `last_seen_utc` | `TIMESTAMPTZ` | **Có** | Thời điểm của sự kiện muộn nhất cấu thành cảnh báo. |
| `detection_source` | `VARCHAR(32)` | **Có** | `'CYBER_RULE_ENGINE'`, `'AI_ANOMALY_MODEL'`, hoặc `'HYBRID_CORRELATION'`. |
| `rule_id` | `VARCHAR(32)` | **Có** | Mã luật phát hiện (ví dụ: `'DET-001'`, `'DET-004'`, `'AI-IF-01'`). |
| `rule_name` | `VARCHAR` | **Có** | Tên mô tả cảnh báo (ví dụ: `'Suspicious Binary Drop and Execution in Temp'`). |
| `severity` | `VARCHAR(16)` | **Có** | Mức độ nghiêm trọng: `'LOW'`, `'MEDIUM'`, `'HIGH'`, `'CRITICAL'`. |
| `confidence_score` | `DOUBLE` | **Có** | Điểm tin cậy chuẩn hóa trong đoạn $[0.0, 1.0]$. |
| `mitre_tactic` | `VARCHAR(64)` | Không | Chiến thuật MITRE ATT&CK (ví dụ: `'Execution'`, `'Persistence'`, `'Command and Control'`). |
| `mitre_technique_id` | `VARCHAR(32)` | Không | Mã kỹ thuật MITRE ATT&CK (ví dụ: `'T1059.001'`, `'T1547.001'`). |
| `hostname` | `VARCHAR(64)` | **Có** | Máy trạm phát sinh cảnh báo (`'DESKTOP-IDEMGQU'`). |
| `process_guid` | `VARCHAR(36)` | **Có** | GUID của tiến trình trung tâm gây ra cảnh báo. |
| `parent_guid` | `VARCHAR(36)` | Không | GUID của tiến trình cha trực tiếp. |
| `image_path` | `VARCHAR` | **Có** | Đường dẫn tệp thực thi chính. |
| `command_line` | `VARCHAR` | Không | Chuỗi dòng lệnh thực thi của tiến trình gây cảnh báo. |
| `user_name` | `VARCHAR` | Không | Tài khoản người dùng thực thi tiến trình. |
| `feature_record_ids` | `VARCHAR[]` | Không | Danh sách khóa `feature_record_id` từ bảng `gold_process_features` (nếu có). |
| `contributing_event_ids`| `VARCHAR[]` | **Có** | **Mảng các `event_id` tầng Silver** trực tiếp kích hoạt cảnh báo. |
| `bronze_raw_references` | `JSON` | **Có** | Mảng đối tượng `[{"event_id": "...", "channel": "...", "record_id": 184}]` trỏ thẳng về Bronze. |
| `investigation_summary`| `JSON` | Không | Tóm tắt ngữ cảnh đóng gói sẵn (cây tiến trình rút gọn, các file/registry/IP liên quan). |