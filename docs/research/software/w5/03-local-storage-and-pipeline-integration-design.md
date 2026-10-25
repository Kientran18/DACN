# Local Storage & Pipeline Integration Design

**Trạng thái:** DRAFT thiết kế cho review W05 (#26). **Không có phần nào ở đây đã chạy trên VM Windows.** Nhãn bằng chứng như file 01: **[X]** kiểm chứng trong container Linux, **[T]** tài liệu, **[N]** giả định thiết kế, **[?]** cần VM hoặc mẫu thật.

## 1. Luồng và ranh giới sở hữu

```text
Windows endpoint
  Sysmon ──► Event Log (Sysmon/Operational)
                 │  (Collector: Software)
                 ▼
          ┌─────────────────┐   segment sealed + manifest
          │  BRONZE (JSONL) │ ─────────────────────────────────┐
          └─────────────────┘                                  │ (Pipeline: Data)
              ▲ quarantine/collector                           ▼
                                                  Validation ──► quarantine/validation
                                                       │
                                                       ▼
                                          SILVER (DuckDB, một process ghi)
                                                       │
                                          Feature Engineering ──► GOLD (Parquet, đổi tên nguyên tử)
                                                       │
                                          Detection / AI ──► Alert (Gold)
                                                       │
                                          UI (Streamlit, chỉ đọc Gold / snapshot)
```

| Vùng | Người ghi | Người đọc | Ghi chú |
|---|---|---|---|
| `bronze/` | Collector | Pipeline | Append-only; segment sealed bất biến |
| `quarantine/collector` | Collector | Operator, Data | Sự kiện không hình thành được envelope |
| `quarantine/validation`, `quarantine/segments` | Pipeline | Operator, Software | Bản ghi/segment bị loại, kèm lý do |
| `silver/` | **Pipeline (process ghi duy nhất)** | Pipeline; reader khác xem mục 5 | DuckDB |
| `gold/` | Pipeline | Detection, UI | Parquet, ghi tạm rồi `os.replace` |
| `checkpoints/` | Collector | Collector | Bookmark |
| `logs/` | Mỗi thành phần ghi file riêng | Operator | JSONL |

## 2. Layout thư mục và cấu hình đường dẫn

```text
<EDR_HOME>\                         mặc định C:\EDR; đổi bằng biến môi trường EDR_HOME hoặc edr.yaml
  config\        edr.yaml, collector.yaml, rules\            (rules: chỉ đọc với pipeline)
  data\
    bronze\sysmon\<host_id>\<YYYY>\<MM>\<DD>\
                 sysmon_<YYYYMMDDTHHMMSSZ>_<seq>.jsonl(.part)  +  <segment>.manifest.json
    quarantine\collector\   quarantine\validation\   quarantine\segments\
    silver\endpoint_silver.duckdb
    gold\feature_store.parquet     gold\alerts\
    snapshots\silver_snapshot_<run_id>.duckdb          (tùy chọn, chỉ đọc)
    checkpoints\collector_sysmon.bookmark.json
  logs\          collector.jsonl   pipeline.jsonl   metrics.jsonl
  run\           collector.lock    pipeline.lock
```

- **Ánh xạ với repo:** `data/bronze|silver|gold` trong repo (đã `.gitignore`) tương ứng `data_root`. Khi phát triển, `data_root` trỏ vào `data/` của repo; trên VM lab trỏ tới `C:\EDR\data`. Mọi đường dẫn đọc từ cấu hình, **không** viết cứng trong mã.
- **Ràng buộc Windows [N, ?]:** giữ đường dẫn ngắn (`C:\EDR`) vì giới hạn 260 ký tự mặc định; tránh khoảng trắng; không đặt dữ liệu trong thư mục đồng bộ đám mây (OneDrive); `Bronze` và nơi đổi tên phải **cùng ổ đĩa** để `os.replace` nguyên tử; hệ thống tệp không phân biệt hoa/thường nên tên file không được khác nhau chỉ ở chữ hoa/thường.
- **Giới hạn lab:** một VM, một host. Ngưỡng dung lượng trống để dừng collector, thời gian giữ Bronze, kích thước segment: **TBD sau benchmark**. Thư mục lưu bản sao file của Sysmon Event 23 (`C:\Sysmon` mặc định **[T:S1]**) nằm ngoài Bronze và cần theo dõi riêng (TR-04).

### Quy ước ghi file trên Windows (bắt buộc cho mọi writer) [N, kiểm bằng `verify_windows_env.py`]

| Quy ước | Lý do |
|---|---|
| `open(path, "w", encoding="utf-8", newline="\n")` cho JSONL, manifest, log | Chế độ văn bản trên Windows đổi `\n` thành `\r\n` nếu không đặt `newline` (kiểm tra W05) |
| Không ghi BOM; đọc chấp nhận UTF-8 BOM và UTF-16 (file xuất bằng PowerShell) | `Out-File` mặc định là UTF-16 |
| Tên file không chứa `:` và ký tự cấm; mốc thời gian dạng `20261014T021530Z` | Windows từ chối `:` trong tên file (kiểm tra W07) |
| Đóng handle ghi trước khi đổi tên `.part`; reader chỉ mở segment đã niêm phong và đóng ngay sau khi đọc | Windows chặn đổi tên/ghi đè file đang mở (kiểm tra W06) |
| Dùng `pathlib`, không nối chuỗi đường dẫn bằng `/` hay `\` thủ công | Tránh lỗi phân tách đường dẫn |
| `.gitattributes`: `* text=auto`, `*.py text eol=lf`, `*.md text eol=lf`, `*.json text eol=lf`, `*.xml text eol=lf`, `*.ps1 text eol=crlf`, `references/samples/** -text` | Git trên Windows không được tự đổi xuống dòng của mẫu thô (`raw_xml` phải nguyên văn) |

## 3. Phân quyền dữ liệu cục bộ (NTFS) [N, chưa chạy]

| Vai trò (tài khoản lab) | bronze | quarantine | silver, snapshots | gold | checkpoints, logs |
|---|---|---|---|---|---|
| Collector | Ghi/tạo | `collector`: ghi | Không | Không | Ghi (của mình) |
| Pipeline | Đọc | `validation`, `segments`: ghi | Ghi (`silver`) | Ghi | Ghi (log của mình) |
| UI / Detection (chỉ đọc) | Không | Không | Đọc `snapshots` | Đọc | Không |
| Administrators | Toàn quyền | Toàn quyền | Toàn quyền | Toàn quyền | Toàn quyền |

Gợi ý thực hiện (chưa chạy thử): tắt kế thừa quyền trên `data\`, cấp quyền theo bảng bằng `icacls`, đặt thuộc tính chỉ đọc cho segment sau khi niêm phong, giữ `prev_manifest_sha256` (chuỗi băm) để phát hiện sửa/xóa (TR-08). **Giới hạn:** tài khoản Administrator vẫn sửa được mọi thứ; các biện pháp này chỉ giảm sai sót và tampering ở quyền thấp.

## 4. Nạp batch (ingestion) từ Bronze vào Silver

1. Liệt kê segment đã niêm phong có manifest và chưa ở trạng thái `done` trong bảng `_ingest_ledger`.
2. Với mỗi segment: kiểm `sha256` và `record_count` của manifest (V-007).
3. Mở **một transaction**; đọc từng dòng → kiểm envelope (V-001) → kiểm `event_data` (V-002…V-004) → ánh xạ sang bản ghi Silver theo bảng ở file 02.
4. Gom theo bảng đích và nạp **theo lô** với `INSERT OR IGNORE` / `ON CONFLICT DO NOTHING` **[X]**; không thêm từng dòng một. Tài liệu DuckDB lưu ý hệ này tối ưu cho thao tác hàng loạt, không phải nhiều transaction nhỏ **[T:D1]**. Báo cáo Tuần 1 đang dùng `executemany`; cần đo xem có đủ không (ở mục benchmark, file 04).
5. Ghi dòng bị loại vào quarantine; cập nhật ledger (`inserted`, `duplicates`, `rejected`); commit.
6. Sau một số segment (ngưỡng TBD): chạy bước đặc trưng và phát hành Gold bằng ghi file tạm rồi đổi tên.

```sql
-- đề xuất; chủ sở hữu: Data
CREATE TABLE IF NOT EXISTS _ingest_ledger (
  segment_id VARCHAR PRIMARY KEY, manifest_sha256 VARCHAR, record_count BIGINT,
  status VARCHAR,                    -- in_progress | done | failed
  run_id VARCHAR, started_at TIMESTAMP, finished_at TIMESTAMP,
  inserted BIGINT, duplicates BIGINT, rejected BIGINT, error VARCHAR);
```

**Truy vết (lineage):** thêm vào mỗi bảng Silver các cột `_bronze_segment`, `_bronze_line`, `_ingest_run_id` để từ một alert truy ngược tới dòng Bronze và XML gốc (M-22).

## 5. Truy cập Silver từ Detection và UI: ràng buộc DuckDB

- **Tài liệu DuckDB [T:D1]:** ở chế độ trong tiến trình, một process được đọc-ghi **hoặc** nhiều process chỉ đọc; ghi từ nhiều process không được hỗ trợ cho định dạng file gốc.
- **Kiểm chứng [X, Linux]:** khi một process mở file DuckDB ở chế độ ghi, process thứ hai mở `read_only=True` bị lỗi `Could not set lock on file … Conflicting lock is held`; sau khi process ghi đóng, process đọc mở được. Hành vi trên Windows **cần kiểm chứng trên VM [?]**.
- **Hệ quả cho thiết kế:** `phase_1_local_data_architecture_mapping.md` ghi "Detection Engine query trực tiếp vào DuckDB" và UI dựng cây tiến trình từ Silver. Nếu pipeline giữ file mở để ghi thì Detection/UI ở process khác sẽ bị chặn.

| Phương án | Mô tả | Ưu | Nhược |
|---|---|---|---|
| **A. Detection chạy trong process pipeline; UI đọc Gold/snapshot** | Pipeline mở DuckDB ghi, chạy luật ngay sau mỗi batch; UI chỉ đọc Parquet Gold và `snapshots` | Không tranh chấp khóa; đơn giản | UI không thấy Silver "sống"; độ trễ theo chu kỳ phát hành |
| **B. Mở–ghi–đóng theo batch; reader thử lại khi gặp khóa** | Pipeline chỉ giữ file mở trong lúc nạp | Reader thấy Silver gần mới | Có khoảng thời gian bị chặn; phải xử lý retry ở UI/Detection |
| **C. Phát hành snapshot chỉ đọc sau mỗi batch** | Sao chép `silver` sang `snapshots\` (hoặc xuất Parquet) cho reader | Reader không bao giờ bị chặn | Tốn đĩa; có độ trễ; cần dọn snapshot cũ |

**Đề xuất tạm:** A kết hợp C (Detection cùng process; UI đọc Gold và snapshot). Quyết định cuối thuộc Data lead và cần thử trên VM trước khi chốt.

## 6. Giao diện thực thi giữa các thành phần

| Giao diện | Hình thức | Ghi chú |
|---|---|---|
| Collector → Bronze | File JSONL + manifest (file 01) | Hợp đồng v1 |
| Bronze → Validation | Hàm đọc segment trả về lần lượt từng bản ghi + metadata (`segment_id`, `line_no`) | Data sở hữu; có thể dùng `bronze_contract.validate_record` |
| Validation → Silver | Bản ghi đã ánh xạ theo lô | Data sở hữu |
| Pipeline → Gold | Parquet ghi tạm + `os.replace` | Reader không bao giờ thấy file dở dang |
| Điều khiển | Tệp khóa trong `run\` (một collector, một pipeline) | Tránh hai instance ghi cùng thư mục |

## 7. Phụ thuộc cần cập nhật

`requirements.txt` của Data dùng các ràng buộc `>=` chưa ghim phiên bản; đề xuất khóa phiên bản (ví dụ file khóa của `uv`) để VM lab tái lập được. Thiếu: `jsonschema` (test hợp đồng), thư viện đọc YAML (cho `edr.yaml`) nếu chọn YAML. Chi tiết đánh giá ở file 05 mục 2.

## 8. Điều chưa kiểm chứng (phải thử trên VM)

| Mã | Điều cần kiểm | Cách làm |
|---|---|---|
| V1 | `os.replace` của `.part` → `.jsonl` có thất bại khi Defender hoặc reader đang giữ file | Thử khi quét thời gian thực đang bật |
| V2 | Khóa file DuckDB giữa hai process trên Windows | Lặp lại thử nghiệm [X] trên VM |
| V3 | Đường dẫn dài, ký tự đặc biệt trong tên máy | Tên máy thật có thể chứa ký tự cần xử lý trong thư mục `host_id` (đã dùng UUID, tránh được) |
| V4 | `icacls` theo bảng ở mục 3 và khả năng chạy collector bằng tài khoản không phải Administrator | Xem quyền đọc channel ở file 09 Week 3 (E10) |
