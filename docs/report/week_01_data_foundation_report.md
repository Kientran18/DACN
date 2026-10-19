# Báo Cáo Tiến Độ Tuần 1: Nền Tảng Dữ Liệu EDR Cục Bộ (Local EDR Data Foundation)

> **Cập nhật 2026-10-19:** Báo cáo lịch sử. Các kết quả code pipeline/DuckDB, số đo và số test bên dưới chưa có đủ mã nguồn/log tương ứng trong main để tái lập; không coi là bằng chứng nghiệm thu. Kế hoạch tiếp theo được thay bằng [backlog 12 tuần](../project/research-backlog-12-weeks.md); tuần 3 tập trung schema/mẫu/collector, tuần 4 đánh giá công cụ. Trạng thái đồng thuận theo [review chung](../project/week-01-03-review-and-ownership.md).


**Dự án:** Hệ thống Giám sát & Phát hiện Xâm nhập Điểm cuối Cục bộ (Local EDR)  
**Vai trò phụ trách:** Data Engineer / Pipeline & Storage  
**Thời gian hoàn thành:** Tuần 1 (Kế hoạch 12 tuần ĐACN)  
**Trạng thái:** REVIEW

---

## 1. Mục Tiêu & Phạm Vi Kỹ Thuật
Xây dựng pipeline dữ liệu chuẩn hóa theo kiến trúc Medallion chạy hoàn toàn trên môi trường cục bộ Windows, phục vụ việc thu thập, kiểm định (validation) và lưu trữ nhật ký sự kiện bảo mật (Sysmon) làm đầu vào cho mô hình AI và luật phát hiện ở các giai đoạn sau.

---

## 2. Kiến Trúc & Công Nghệ Đã Hiện Thực

### Tech Stack
* **Ngôn ngữ & Quản trị gói:** Python (chạy trên `.venv` bằng `uv`), pytest.
* **Xác thực Schema:** Pydantic v2 (Silver schemas).
* **Cơ sở dữ liệu cục bộ:** DuckDB (OLAP storage dạng nhúng, hỗ trợ truy vấn vectorized tốc độ cao).
* **Thu thập dữ liệu:** `pywin32` (`win32evtlog`), `xml.etree.ElementTree`.
* **Định dạng dữ liệu:** JSONL (Bronze raw events), DuckDB/Parquet (Silver/Gold layers).

### Cấu Trúc Thư Mục Chuẩn
```text
ĐACN/
├── requirements.txt                         # Quản lý dependencies (pydantic, duckdb, pyarrow,...)
├── pytest.ini                               # Cấu hình PYTHONPATH cho testing
├── data/                                    # Dữ liệu cục bộ (.gitignore)
│   ├── bronze/                              # Raw Sysmon JSONL & Validation Error log
│   ├── silver/                              # endpoint_silver.duckdb (4 bảng chuẩn)
│   └── gold/                                # Sẵn sàng cho feature store & alerts
├── docs/                                    # Đặc tả kỹ thuật & Báo cáo tiến độ
│   ├── edr_data_requirements_architecture.md
│   └── week_01_data_foundation_report.md
├── experiments/                             # Lưu trữ mã nguồn thử nghiệm (POC Rust Agent cũ)
└── pipeline/                                # Mã nguồn pipeline Python chính
    ├── schemas/events.py                    # Định nghĩa Silver Schemas (Pydantic)
    ├── ingestion/collector.py               # Thu thập đa chế độ (Live Sysmon, Dataset, Mock)
    ├── storage/db.py                        # Quản lý DuckDB (DDL, Bulk Insert, Query)
    ├── process_pipeline.py                  # Bronze -> Validation -> Silver Pipeline
    └── tests/                               # Bộ kiểm thử tự động (E2E & Schema tests)

```

---

## 3. Các Thành Phần Đã Triển Khai

### 3.1. Silver Data Schemas (`pipeline/schemas/events.py`)
Định nghĩa 4 schema Pydantic kế thừa từ `BaseEvent` (`event_id`, `timestamp`, `source`, `event_type`, `host_id`, `process_guid`):
1. **`ProcessEvent` (Sysmon ID 1,5):** `pid`, `ppid`, `parent_guid`, `image_path`, `command_line`, `user_name`, `file_sha256`, `current_working_directory`.
2. **`FileEvent` (Sysmon ID 11):** `file_path`, `file_size_bytes`, `file_extension`.
3. **`RegistryEvent` (Sysmon ID 12, 13, 14):** `target_object`, `details`.
4. **`NetworkEvent` (Sysmon ID 3):** `protocol`. `direction` (INBOUND/OUTBOUND), `source_ip`, `source_port`, `dest_ip`, `dest_port`.

### 3.2. Storage Layer DuckDB (`pipeline/storage/db.py`)
- Thiết kế 4 bảng DDL tương ứng: `silver_process_events`, `silver_file_events`, `silver_registry_events`, `silver_network_events`.
- Sử dụng khoá chính `PRIMARY KEY (event_id)` và kiểu dữ liệu chuẩn (`TIMESTAMP`, `INTEGER`, `VARCHAR`).
- Hiện thực cơ chế `_bulk_insert` dùng tham số liên kết (`executemany`) giúp nạp hàng loạt tối ưu bộ nhớ.

### 3.3. Ingestion & Transformation Pipeline
1. **`pipeline/ingestion/collector.py`:**
- Hỗ trợ chế độ `--mode live` đọc trực tiếp kênh `Microsoft-Windows-System/Operational` từ Windows Event Log qua quyền Administrator.
- Hỗ trợ chế độ `--mode file` nạp dataset an ninh mạng bên ngoài (JSONL).
- Hỗ trợ chế độ `--mode mock` sinh chuỗi hành vi tấn công giả lập phục vụ kiểm thử cô lập.
2. **`pipeline/process_pipeline.py`:**
- Parse trường `UtcTime` chuẩn ISO/UTC, bóc tách `SHA256` hash an toàn.
- Tách luồng ghi log lỗi độc lập tại `data/bronze/validation_errors.jsonl`, không làm dừng pipeline khi dữ liệu gặp lỗi.

---

## 4. Kết Quả Kiểm Thử & Dữ Liệu Thực Tế

### 4.1. Kết Quả Testing Tự Động
1. **Unit Test Schema (`test_schema.py`):** 3/3 test PASSED (kiểm tra parse dữ liệu chuẩn, chặn trường bắt buộc thiếu, chặn sai enum).
2. **End-to-End Pipeline Test (`test_pipeline_e2e.py`):** 19/19 tests PASSED.
- Xác thực tính toàn vẹn số lượng đọc/ghi qua DuckDB.
- Xác thực bộ lọc chuỗi tấn công (PowerShell, file Temp, Registry Run Key, Outbound Network).
- Xác thực cơ chế cô lập lỗi dữ liệu JSON hỏng và schema sai lệch.

### 4.2. Dữ Liệu Vận Hành Thực Tế Trong Silver DuckDB
Dữ liệu đã được nạp thành công từ kênh Sysmon thật của máy trạm và ánh xạ vào database `data/silver/endpoint_silver.duckdb`:
- **`silver_process_events`:** 141 bản ghi (ghi nhận chính xác các lệnh PowerShell mã hóa Base64 `-enc`, Assembly Reflection).
- **`silver_file_events`:** 105 bản ghi.
- **`silver_registry_events`:** 105 bản ghi.
- **`silver_network_events`:** 121 bản ghi.
- **Tỷ lệ lỗi kiểm thực (Validation errors):** 0%.

---

## 5. Bàn Giao & Kế Hoạch Tiếp Theo (Tuần 2)
1. **Tuần 1 chính thức đóng lại:** Tầng dữ liệu Silver Layer hoạt động ổn định và sẵn sàng cung cấp dữ liệu sạch cho phân tích.
2. **Nhiệm vụ trọng tâm Tuần 2:**
- Lập bảng ma trận ánh xạ kỹ thuật tấn công **MITRE ATT&CK &rarr; Telemetry Table**.
- Thiết kế module trích xuất đặc trưng `pipeline/features/extractor.py` gom nhóm theo cửa sổ trượt (Sliding Window / Process Tree).
- Xuất tập đặc trưng sang Tầng Gold dưới dạng file `data/gold/feature_store.parquet` phục vụ huấn luyện mô hình AI.
