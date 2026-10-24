# Integration Feasibility / Open Issues cho review W05

**Issue:** [W05][Team] #26 · **Đầu vào:** #16 (PoC), #22 (đánh giá công cụ), `data_pipeline_phase_1_scope.md` · **Trạng thái:** DRAFT chờ review Data và Cyber · **Phân biệt:** thực nghiệm đã có / giả định thiết kế / kế hoạch Phase 2 (mục 1).

## 1. Thực nghiệm đã có, giả định thiết kế, kế hoạch Phase 2

| Loại | Nội dung |
|---|---|
| **Thực nghiệm đã có** | (a) PoC Tuần 3: 13 test đạt trên **sự kiện giả lập**; (b) Tuần 5: 9 test hợp đồng và 2 test môi trường (24 test tổng, chạy trên Linux) trên cùng dữ liệu giả lập; (c) kiểm chứng hành vi thư viện trong **container Linux** (mục 3). **Chưa có** lần chạy nào trên VM Windows, chưa có JSON/mẫu thật được đối chiếu |
| **Giả định thiết kế** | Segment JSONL + manifest, giao thức checkpoint, quarantine, layout thư mục, ACL, phương án truy cập Silver, chỉ số và kịch bản benchmark (file 01 đến 04) |
| **Phase 2** | Queue/IPC, ETW, đọc nhiều nguồn, API REST, tự động hóa benchmark và Atomic Red Team định kỳ |

## 2. Review phương án Python / Pydantic / DuckDB / Parquet

| Thành phần | Vai trò | Khả năng chạy trên Windows VM | Phụ thuộc và rủi ro | Cần kiểm chứng |
|---|---|---|---|---|
| Python 3.11 | Ngôn ngữ chung (theo scope) | Có bản cài Windows; container chạy Python 3.12 nên kết quả [X] chưa phải môi trường đích | Hai phiên bản khác nhau | Chạy lại 22 test và các thử nghiệm [X] trên VM 3.11 |
| Pydantic v2 | Validate Silver | [X] đọc chuỗi thời gian 7 chữ số (cắt xuống µs); `UUID4` **từ chối** GUID có chữ số phiên bản khác 4 | Không dùng kiểu `UUID4` cho `process_guid` | Thử với GUID Sysmon thật |
| DuckDB | Silver (OLAP nhúng) | [T] một process đọc-ghi hoặc nhiều process chỉ đọc **[T:D1]**; [X] khóa file gây lỗi cho reader; `INSERT OR IGNORE` hoạt động | Truy cập từ Detection/UI (file 03 mục 5); tối ưu cho thao tác hàng loạt | Khóa file trên Windows; hiệu năng nạp theo lô so với `executemany` |
| Parquet / pyarrow | Gold (feature store) | Chưa kiểm chứng trên VM [?] | Ghi tạm + `os.replace`; trên Windows file đang mở có thể chặn đổi tên | Thử ghi khi Streamlit đang đọc |
| pywin32 (`>=306`) | Đọc Event Log | Chưa kiểm chứng [?]; tên hàm bookmark/subscribe cần xác nhận | Cài bản khớp phiên bản Python; cần quyền Admin để đọc channel | Chạy `--mode live` trên VM |
| psutil | Snapshot, đo tài nguyên | Chưa kiểm chứng [?] | Một số thông tin cần quyền Admin | Thử trên VM |
| Streamlit, plotly, networkx | UI, cây tiến trình | Ngoài phạm vi tài liệu này | Đọc Gold/snapshot chứ không giữ khóa Silver | W06+ |
| uv, pytest | Môi trường, test | Dùng theo báo cáo Tuần 1 | `requirements.txt` dùng `>=` chưa khóa phiên bản | Tạo file khóa; thêm `jsonschema`, YAML nếu cần |

## 3. Kiểm chứng đã thực hiện (container Linux; Python 3.12.3, Pydantic 2.14.1, DuckDB 2.0.0)

| # | Câu hỏi | Kết quả [X] | Hệ quả |
|---|---|---|---|
| 1 | Pydantic `datetime` đọc `2026-10-14T02:15:30.1234567Z`? | Đọc được, **cắt thành 123456 µs** (mất chữ số thứ 7), có múi giờ UTC | Giữ chuỗi gốc ở Bronze (M-09) |
| 2 | DuckDB ép `CAST(... AS TIMESTAMP)` cho chuỗi trên? | Được, cắt thành µs | Như trên |
| 3 | `read_json_auto` suy kiểu cột thời gian? | `TIMESTAMP WITH TIME ZONE` | Có thể nạp Bronze bằng SQL nếu Data muốn |
| 4 | Insert trùng khóa chính? | `ConstraintException` | Loader phải dùng cú pháp bỏ qua trùng |
| 5 | `INSERT OR IGNORE` / `ON CONFLICT DO NOTHING`? | Hoạt động, giữ dòng cũ | Replay idempotent (file 03 mục 4) |
| 6 | `uuid.UUID` và `UUID4` với GUID kiểu Sysmon? | `UUID` đọc và chuyển chữ thường; `UUID4` **từ chối** (GUID thử có chữ số phiên bản khác 4) | M-08: không dùng `UUID4` |
| 7 | Hai process cùng mở file DuckDB (một ghi, một chỉ đọc)? | Reader lỗi `Could not set lock on file`; mở được sau khi writer đóng | File 03 mục 5 |

Giới hạn: GUID dùng ở mục 6 là GUID giả lập; cần GUID Sysmon thật. Hành vi khóa file trên Windows chưa kiểm chứng.

## 4. Quyết định thiết kế đề xuất (chờ review)

| Mã | Quyết định | Chủ đề xuất | Trạng thái |
|---|---|---|---|
| D-01 | Bàn giao collector → Bronze bằng **segment JSONL + manifest**, không gọi hàm/ghi thẳng DuckDB | Software | Đề xuất |
| D-02 | **Silver transform là nơi duy nhất ánh xạ ngữ nghĩa**; Bronze chỉ chứa `event_data` gốc và `raw_xml` | Software + Data | Đề xuất |
| D-03 | **At-least-once + idempotent**: checkpoint sau khi ghi bền; khử trùng bằng `event_id` | Software + Data | Đề xuất |
| D-04 | Silver chỉ có **một process ghi**; Detection cùng process, UI đọc Gold/snapshot (cần thử trên VM) | Data | Đề xuất, cần thử |
| D-05 | `host_id = uuid5(NS, lower(hostname))` cho Phase 1 (một host) | Software, **Data xác nhận** | Đề xuất |
| D-06 | Giữ `time_created` dạng chuỗi gốc ở Bronze; Silver chọn một nguồn `timestamp` (M-09) | Data | Chờ quyết định |
| D-07 | Mọi bản ghi bị loại phải vào quarantine có `reason_code` và được đếm; không xóa âm thầm | Software + Data | Đề xuất |
| D-08 | Silver có cột truy vết `_bronze_segment`, `_bronze_line`, `_ingest_run_id` | Data | Đề xuất |

## 5. Vấn đề còn mở và người xử lý

Chủ là **đề xuất**, cần người đó chấp nhận. Mức: **Cao** chặn thiết kế, **Trung** cần trước W06, **Thấp** có thể làm sau.

| Mã | Vấn đề | Chủ | Mức | Cần trước |
|---|---|---|---|---|
| O-01 | Chưa có mẫu/JSON thật được đối chiếu: chạy `contract_check.py` trên `references/samples` và cập nhật file 02 | Software | Cao | W05 |
| O-02 | Mismatch M-01, M-05, M-06, M-08, M-09, M-10, M-11, M-13, M-14 (file 02 mục D) | Data (+ Cyber cho M-06, M-10) | Cao | W05 |
| O-03 | Chọn phương án truy cập Silver (D-04) và thử khóa file DuckDB trên VM | Data | Cao | W05 |
| O-04 | Xác nhận API bookmark/subscribe của `pywin32` trên VM, viết thử `--mode live` | Software | Trung | W06 |
| O-05 | Kiểm chứng V1 đến V4 (file 03 mục 8) trên VM | Software | Trung | W06 |
| O-06 | Ngân sách tài nguyên: hai mức RAM và hai mức CPU trong tài liệu (Q-D5), có tính cả Sysmon không | Data + Software | Trung | W06 |
| O-07 | Windows 10 hay 11 cho VM chung (Sysmon v15.22 liệt kê Windows 11+ **[T:S1]**) | Software + Cyber | Trung | W05 |
| O-08 | Khóa phiên bản `requirements.txt`; thêm `jsonschema` (test hợp đồng) | Data | Trung | W06 |
| O-09 | Nơi lưu Scheduled Task, Service, Image-load event (Q-X1) và Event 4/15/16/29 (Q-D8) | Data + Cyber | Trung | W06 |
| O-10 | Sự kiện nào Cyber cần ở Bronze mà collector chưa thu (DET-004/007/008 phủ một phần) | Cyber | Trung | W06 |
| O-11 | Định nghĩa chính sách giữ Bronze, ngưỡng dung lượng, kích thước segment | Software + Data | Thấp | Sau benchmark |
| O-12 | Quyết định Event 23 hay 26 và chi phí đĩa của `C:\Sysmon` (Q-C2) | Cyber | Thấp | W06 |

## 6. Tương thích collector hiện tại với hợp đồng

| Khả năng của PoC | Hợp đồng v1 | Trạng thái |
|---|---|---|
| Parse XML `Event` (live hoặc file) | Cần | Có [PoC, mẫu giả lập] |
| Giữ metadata `System` | Cần | **Chưa** (P-01; hợp đồng đã có hàm tham chiếu) |
| Giữ `raw_xml` | Cần | **Chưa** (P-01) |
| `event_id` xác định | Cần | Có |
| `host_id` | Cần | **Chưa** (P-07; hàm tham chiếu có) |
| Đọc xuôi thời gian + bookmark | Cần | **Chưa** (PoC đọc ngược, P-02) |
| Writer segment, manifest | Cần | **Chưa** (P-03) |
| Mã lỗi, quarantine | Cần | Một phần (C-001, C-002 trong hàm tham chiếu; chưa có ghi quarantine, P-04) |
| Trường ngữ nghĩa `data` | Không đưa vào Bronze | Có ở PoC; gỡ ra (P-06) |

**Kết luận:** PoC hiện tại **tương thích về nguyên lý** (đọc và parse đúng cấu trúc XML của Sysmon theo test giả lập) nhưng cần các thay đổi P-01 đến P-07 trước khi dùng làm collector bàn giao cho Bronze. Chưa xác nhận bằng mẫu thật.

## 7. Checklist review

**Data**
- [ ] Đồng ý D-01 đến D-08, đặc biệt D-02 (ánh xạ chỉ ở Silver) và D-04 (một process ghi)?
- [ ] Silver có thêm cột ở M-13 và cột lineage D-08?
- [ ] Chọn một tên cho `src_*`/`source_*` (M-01), nguồn `timestamp` (M-09), dạng GUID (M-08)?
- [ ] Sửa tên channel trong tài liệu và `collector.py` (M-14)?
- [ ] Dùng được `bronze-event.schema.json` và `contract_check.py` trong bước validation?

**Cyber**
- [ ] Danh sách trường theo từng event id ở file 02 đủ cho DET-001 đến DET-010?
- [ ] Bảng quy đổi event type (M-06, M-10)?
- [ ] Chấp nhận `quarantine` và `reason_code` cho dữ liệu bị loại?
- [ ] Sơ đồ ở file 03 mục 1 (có Network trong luồng) khớp kiến trúc sơ bộ?

**Biên bản review** (điền sau khi họp)

| Bên | Ngày | Người tham gia | Kết quả | Link |
|---|---|---|---|---|
| Data | | | | |
| Cyber | | | | |

## 8. Ghi chú interface cho W06

- **Ổn định (có thể dựa vào):** định dạng bản ghi Bronze (`bronze-event/1.0`), quy tắc UTF-8/JSONL, `event_id` xác định, khóa khử trùng, mã lỗi C-xxx/V-xxx, định dạng bản ghi quarantine.
- **Còn mở (không được hard-code):** tên trường Silver (M-01), từ vựng `event_type` và `operation` (M-06, M-10), nguồn `timestamp` (M-09), cách Detection/UI đọc Silver (D-04), các ngưỡng số (kích thước segment, retry, giữ dữ liệu).
- **Việc W06 có thể bắt đầu:** P-01 đến P-07 (collector), bộ nạp theo lô và `_ingest_ledger` (Data), mẫu vàng và mẫu âm cho test hợp đồng (chung), khung chỉ số và `run_manifest.json`.
- **Đầu vào cần có:** kết quả `contract_check.py` trên mẫu thật; quyết định cho các mục O-02 và O-03; kết quả thử khóa DuckDB trên Windows.

## 9. Tiêu chí hoàn thành

- [x] Có interface/format/metadata rõ ràng *(bản nháp; dựa trên mã PoC và dữ liệu giả lập, chưa dựa trên JSON thật)*
- [x] Mismatch được liệt kê (M-01 đến M-22) và có chủ đề xuất *(chờ người được giao chấp nhận)*
- [x] Có giải pháp dự kiến cho restart, retry và lưu raw không mất dữ liệu *(thiết kế, chưa cài đặt, chưa chạy)*
- [ ] Data và Cyber đã review
- [ ] Tài liệu được commit và liên kết tới #26

## 10. Nguồn

- D1: DuckDB, "Handling Concurrency": https://duckdb.org/docs/current/connect/concurrency
- E1: Microsoft Learn, "Bookmarking Events": https://learn.microsoft.com/en-us/windows/desktop/WES/bookmarking-events
- S1: Microsoft Learn, Sysmon: https://learn.microsoft.com/en-us/sysinternals/downloads/sysmon
- Nội bộ: `data_pipeline_phase_1_scope.md`, `phase_1_local_data_architecture_mapping.md`, `sysmon_to_silver_schema_mapping.md`, `week_01_data_foundation_report.md`, `edr_data_requirements_architecture.md`, file 04 Week 2, tài liệu Week 3 và Week 4 của Software.

Liên kết #26 trong mô tả Pull Request; mở dạng Draft cho đến khi Data và Cyber review.
