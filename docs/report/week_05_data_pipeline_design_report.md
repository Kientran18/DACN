# Báo Cáo Tiến Độ Tuần 5: Thiết Kế Kiến Trúc Data Pipeline Bronze/Silver/Gold, Hợp Đồng Dữ Liệu v1.1, Chất Lượng Và Lineage

**Dự án:** Hệ thống Giám sát & Phát hiện Xâm nhập Điểm cuối Cục bộ (Local EDR)  
**Vai trò phụ trách:** Huỳnh Hữu Nhật (Data Engineer Lead / Pipeline & Storage)  
**Issue phụ trách:** `[W05][Data] Thiết kế Bronze/Silver/Gold, schema, chất lượng và lineage dữ liệu #27`  
**Issue tổng hợp nhóm:** `[W05][Team] Thống nhất thiết kế Data Pipeline và nghiệm thu các hợp đồng dữ liệu #26`  
**Thời gian thực hiện:** Tuần 5 (21/10/2026 | Kế hoạch 12 tuần ĐACN – Hướng tới mốc thiết kế lõi M2 ở cuối Tuần 8)  
**Trạng thái:** HOÀN THÀNH (Definition of Done: 100%)

---

## 1. Mục Tiêu & Phạm Vi Công Việc Tuần 5

Trong kế hoạch 12 tuần của dự án Local EDR, Tuần 5 là tuần bản lề chuyển giao từ giai đoạn khảo sát công cụ (Tuần 3–4) sang giai đoạn thiết kế tổng thể **Data Pipeline End-to-End** do nhóm Data chủ trì:
* **Rà soát và đối chiếu kế thừa Tuần 3 – Tuần 4:** Kiểm tra chéo toàn bộ tài liệu `Endpoint Event Schema v1`, ma trận ánh xạ `Sysmon Raw to Silver Mapping v1`, `Data Dictionary v1` với bộ mẫu thực nghiệm thu thập trên máy trạm `DESKTOP-IDEMGQU` (`process.json`, `file.json`, `registry.json`, `network.json`, `poc_run_20261018_021142.json`, `sysmon-config.xml`). Liệt kê minh bạch mọi điểm bất nhất và nâng cấp lên **Schema v1.1**.
* **Thiết kế kiến trúc và hợp đồng dữ liệu 7 tầng:** Đặc tả chi tiết luồng dữ liệu từ `Endpoint Collector` $\rightarrow$ `Raw/Bronze (JSONL + Manifest)` $\rightarrow$ `Validation & Quarantine DLQ` $\rightarrow$ `Normalized/Silver (DuckDB)` $\rightarrow$ `Feature Engineering` $\rightarrow$ `Detection/AI` $\rightarrow$ `Gold/Alert`.
* **Đặc tả Kiểm định Chất lượng (Validation), Chống trùng lặp (Deduplication) & Truy vết (Lineage):** Thiết lập bộ quy tắc kiểm định riêng cho từng loại Event ID (đặc biệt là DNS Event ID 22 và Process Terminate Event ID 5), cơ chế xử lý khi kênh log bị xóa/reset, chính sách lưu trữ (Retention) và bảo mật dữ liệu nhạy cảm.
* **Kiểm chứng thực nghiệm qua PoC (`validator_poc.py` & Unit Tests):** Tách bạch rõ ràng giữa những gì **đã chạy kiểm chứng thực nghiệm (`[TESTED POC]`)** trên bộ mẫu thật + mẫu lỗi có nhãn với các **hợp đồng thiết kế cho Giai đoạn 2 (`[PHASE 2 PLAN]`)**.

---

## 2. Tóm Tắt Các Kết Quả Thiết Kế Trọng Tâm Tuần 5

### 2.1. Giải quyết triệt để 8 điểm bất nhất giữa tài liệu Tuần 3 và dữ liệu thực tế (Schema v1.1)
Qua rà soát thực nghiệm (xem chi tiết tại `docs/architecture/w5/schema_reconciliation_and_dictionary_v1_1.md` và `ADR 0006`), nhóm Data đã phát hiện và xử lý 8 vấn đề:
1. **Đồng nhất tên trường:** Chốt dùng `hostname` (thay vì `host_id` trong mapping cũ), `src_ip`/`src_port` và `dest_ip`/`dest_port` (thay vì `source_ip`), và `details` (hợp nhất trường thừa `new_data_str` trong `registry.json`).
2. **Xử lý khuyết trường `operation` trong `file.json`:** Bộ nạp Silver tự động suy diễn `operation` từ `event_type` khi đối tượng `data` của Collector không truyền khóa này.
3. **Thiết lập Trục Thời Gian Kép (`timestamp` vs `event_utc_time`):** Phát hiện trong mẫu thật `network.json` (`record_id: 194`) có độ lệch **$12.38\text{ s}$** giữa `System.TimeCreated.SystemTime` (`09:11:59.464Z`) và `EventData.UtcTime` (`09:12:11.850`). Schema v1.1 chốt lấy `SystemTime` làm cột `timestamp` chuẩn và lưu `UtcTime` vào cột `event_utc_time` để giám sát độ trễ.
4. **Validation phụ thuộc `sysmon_event_id` cho DNS ID 22 và Process ID 5:** Cho phép các cột 4-tuple IP/Port nhận giá trị `NULL` khi `sysmon_event_id = 22` (`DNS_QUERY`) và cho phép `ppid`/`parent_guid` nhận `NULL` khi `sysmon_event_id = 5` (`PROCESS_TERMINATE`).
5. **Mở rộng hỗ trợ đầy đủ `sysmon-config.xml`:** Bổ sung cột `imphash`, `rule_name` và hỗ trợ các Event ID `15` (`FILE_STREAM_HASH`), `26` (`FILE_DELETE`), `29` (`FILE_EXECUTABLE_DETECTED`).

### 2.2. Kiến trúc Medallion Cục bộ, Quarantine DLQ và Truy vết Lineage
* **Tầng Bronze (`ADR 0005`):** Lưu trữ bất biến theo định dạng `.jsonl` kèm tệp kiểm kê `.manifest.json` (chứa `file_sha256`, `min_record_id`, `max_record_id`). Áp dụng giao thức chuyển giao nguyên tử `.jsonl.tmp` $\rightarrow$ `.jsonl` giữa Software Collector và Data Ingestor.
* **Tầng Validation & Quarantine:** Áp dụng nguyên tắc **Zero Data Fabrication** (tuyệt đối không tự chế dữ liệu giả khi thiếu trường bắt buộc). Các bản ghi lỗi được cô lập vào `data/quarantine/` và bảng `silver_quarantine_dlq` kèm mã lỗi chuẩn hóa để phục vụ Replay.
* **Tầng Silver & Enriched Views (DuckDB):** Tổ chức thành 4 bảng sự kiện chuẩn hóa có khóa chính `event_id` (UUIDv5) chống trùng lặp, đi kèm các SQL Views làm giàu ngữ cảnh (`v_silver_file_enriched`, `v_silver_registry_enriched`, `v_silver_network_enriched`, `v_process_tree_lineage`) giúp Cyber Team truy vấn mọi sự kiện phụ kèm sẵn `command_line` và `parent_image`.
* **Tầng Feature Store & Gold Alert Contracts:** Định nghĩa bảng `gold_process_features` (chứa độ sâu cây tiến trình `tree_depth`, bộ đếm cửa sổ trượt nhân quả $5\text{ s}/10\text{ s}/30\text{ s}$, `cmd_shannon_entropy`, và mảng truy vết `source_event_ids[]`) cùng bảng `gold_security_alerts` (liên kết ngược về Silver và Bronze qua `contributing_event_ids[]`).

---

## 3. Kết Quả Kiểm Chứng Thực Nghiệm PoC (`validator_poc.py` & Unit Tests)

Nhóm Data đã xây dựng bộ kiểm định thực thi `src/pipeline/validator_poc.py`, tập dữ liệu kiểm thử `references/samples/w5_negative_and_edge_samples.jsonl` và bộ kiểm thử tự động `tests/test_validator_poc_w5.py`:

| Nhóm Kịch Bản Kiểm Thử | Số Lượng Mẫu | Kết Quả Thực Thi Thực Tế | Minh Chứng Kỹ Thuật |
| :--- | :---: | :--- | :--- |
| **1. Positive Real Samples (W03)** (`process.json`, `file.json`, `registry.json`, `network.json`) | $8\text{ bản ghi}$ (`ID: 1, 3, 11, 13`) | **PASS 100%** ($8/8$ nạp vào DuckDB Silver) | Mã `event_id` UUIDv5 sinh ra khớp chính xác tuyệt đối với cả 8 bản ghi mẫu Tuần 3; tự động phát hiện cảnh báo lệch giờ `UtcTime` trên `record_id: 194`. |
| **2. Positive Edge Samples (W05)** (DNS ID 22, Process Terminate ID 5, ADS Stream ID 15) | $3\text{ bản ghi}$ (`ID: 22, 5, 15`) | **PASS 100%** ($3/3$ nạp vào DuckDB Silver) | Sự kiện DNS ID 22 (`cloudflare.com`) nạp thành công vào `silver_network_events` với IP/Port = `NULL`; sự kiện ID 5 nạp thành công với `parent_guid = NULL`. |
| **3. Idempotent Deduplication Replay** (Nạp lặp lại các bản ghi đã tồn tại) | $2\text{ bản ghi}$ (`record_id: 185, 182`) | **PASS 100%** (`duplicates_dropped = 2`) | Nhờ khóa xác định `UUIDv5` và `INSERT OR IGNORE`, số lượng bản ghi trong DuckDB không bị nhân đôi khi chạy lại. |
| **4. Labeled Negative Samples (Quarantine DLQ)** (Thiếu `process_guid`, hỏng `record_id`, sai `timestamp`, sai IP, sai Hive) | $5\text{ bản ghi}$ (`TC-NEG-01..05`) | **PASS 100%** ($5/5$ cô lập vào Quarantine) | Bắt đúng 5 mã lỗi mục tiêu (`ERR_MISSING_PROCESS_GUID`, `ERR_INVALID_RECORD_ID`, `ERR_INVALID_TIMESTAMP`, `ERR_NET_INVALID_IP_OR_PORT`, `ERR_REG_INVALID_TARGET`). |

---

## 4. Biên Bản Rà Soát Liên Nhóm (Cross-Functional Review & Alignment)

| Bộ Phận | Đại Diện | Nội Dung Rà Soát & Quyết Định Thống Nhất | Trạng Thái |
| :--- | :--- | :--- | :---: |
| **Cyber Team** | Detection Lead | Đồng thuận với Schema v1.1 (bổ sung `imphash`, `rule_name`, `dns_query_*` và hỗ trợ Event ID 15, 22, 23/26, 29). Xác nhận các SQL Views `v_silver_*_enriched` và bảng `gold_security_alerts` đáp ứng 100% đầu vào cho 10 nhóm luật `DET-001` $\rightarrow$ `DET-010`. | **APPROVED** |
| **Software Team** | Collector Lead | Đồng thuận giữ nguyên định dạng JSON xuất ra của Collector Tuần 3; thống nhất áp dụng cơ chế ghi tệp tạm `.jsonl.tmp` và đổi tên nguyên tử sang `.jsonl` kèm `.manifest.json` ở Tuần 6. | **APPROVED** |
| **Data Team** | Data Lead | Hoàn thiện toàn bộ kiến trúc Bronze/Silver/Gold, từ điển dữ liệu v1.1, quy tắc Validation/Quarantine, DDL DuckDB và bộ kiểm thử PoC. | **APPROVED** |

---

## 5. Bảng Nghiệm Thu Tiêu Chí Hoàn Thành (Definition of Done Verification)

| STT | Tiêu Chí Hoàn Thành (Theo Issue #27) | Tài Liệu / Code Minh Chứng Trong Repository | Trạng Thái |
| :---: | :--- | :--- | :---: |
| 1 | Bốn nhóm sự kiện (Process, File, Registry, Network/DNS) có mapping, điều kiện validate và ví dụ biến đổi Raw $\rightarrow$ Silver | `docs/architecture/w5/data_pipeline_architecture_and_contracts_v1.md` (Mục 4) & `docs/architecture/w5/schema_reconciliation_and_dictionary_v1_1.md` (Mục 4) | **Đạt (100%)** |
| 2 | Các bất nhất hoặc khoảng trống dữ liệu từ Tuần 3 được liệt kê minh bạch, có phương án xử lý, migration SQL và chủ sở hữu | `docs/architecture/w5/schema_reconciliation_and_dictionary_v1_1.md` (Mục 1 & Mục 2 – Bảng 8 vấn đề `INC-01` $\rightarrow$ `INC-08`) & `ADR 0006` | **Đạt (100%)** |
| 3 | Các tầng Bronze, Quarantine, Silver, Feature, Gold có dữ liệu vào/ra, khóa liên kết truy vết (Lineage) và lựa chọn lưu trữ DuckDB rõ ràng | `docs/architecture/w5/data_pipeline_architecture_and_contracts_v1.md` (Mục 2, 3, 5) & `src/pipeline/sql/silver_gold_schema_and_views_v1_1.sql` | **Đạt (100%)** |
| 4 | Có kịch bản kiểm thử Positive/Negative validation, Deduplication và Replay cùng kết quả mong đợi; phân biệt rõ phần đã chạy PoC và kế hoạch Phase 2 | `docs/architecture/w5/validation_quality_lineage_and_governance_v1.md` (Mục 4), `references/samples/w5_negative_and_edge_samples.jsonl`, `src/pipeline/validator_poc.py` & `tests/test_validator_poc_w5.py` | **Đạt (100%)** |
| 5 | Đặc tả chính sách lưu trữ (Retention), bảo mật che giấu mật khẩu trên `command_line`, dọn dẹp dữ liệu thử nghiệm và được Cyber/Software review | `docs/architecture/w5/validation_quality_lineage_and_governance_v1.md` (Mục 6 & Mục 7) & Biên bản Mục 4 báo cáo này | **Đạt (100%)** |

---

## 6. Kế Hoạch Bàn Giao Sang Tuần 6 (Preparation for Week 6 Implementation)

1. **Triển khai Worker Nạp Tự Động Bronze $\rightarrow$ Silver DuckDB:** Nâng cấp `src/pipeline/validator_poc.py` thành dịch vụ đọc theo lô từ thư mục `data/bronze/sysmon/` và thực thi bộ khung SQL `src/pipeline/sql/silver_gold_schema_and_views_v1_1.sql`.
2. **Tích hợp Pipeline Trích xuất Đặc trưng (Feature Engineering Pipeline):** Chạy tự động các truy vấn tính toán `tree_depth`, `cmd_shannon_entropy` và các bộ đếm cửa sổ trượt nhân quả ($5\text{ s}, 10\text{ s}, 30\text{ s}, 60\text{ s}$) để điền dữ liệu vào bảng `gold_process_features`.
3. **Phối hợp kiểm thử tích hợp với Cyber & Software:** Kết nối đầu ra của Software Collector với Silver DuckDB và chạy thử nghiệm các luật phát hiện `DET-001` $\rightarrow$ `DET-010` của Cyber trên các Enriched SQL Views.