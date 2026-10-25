# Collector-to-Bronze Interface Contract v1

> **Đối chiếu W05 (#26/#27/#29):** Hợp đồng `bronze-event/1.0` trong file này được chọn làm **canonical Bronze proposal**, xem [hợp đồng chung, schema, ví dụ input/output và adapter](../../../architecture/w5/contracts/README.md). Các đường dẫn cũ dạng `contracts/bronze-event.schema.json` trong nội dung lịch sử phải hiểu theo path thực tế `poc/sysmon-collector/bronze-event.schema.json`; mã `bronze_contract.py` đã được đồng bộ. Data/Software **chưa ký xác nhận**; các đề xuất segment/manifest/Windows live vẫn chưa thành phần chạy production.


**Issue:** W05 (#26) · **Trạng thái:** DRAFT chờ review Data và Cyber · **Phụ thuộc:** #16 (PoC), #22 (đánh giá công cụ)

## 0. Mức bằng chứng (đọc trước)

| Nhãn | Ý nghĩa |
|---|---|
| **[PoC]** | Dựa trên mã collector PoC Tuần 3 và test của nó. Test chạy trên **sự kiện giả lập**, chưa chạy live trên Windows |
| **[X]** | Đã kiểm chứng trong container Linux (Python 3.12.3, Pydantic 2.14.1, DuckDB 2.0.0); **chưa** chạy trên VM Windows (Python 3.11) |
| **[T]** | Từ tài liệu chính thức (nguồn ở file 05 mục 10) |
| **[N]** | Giả định thiết kế, chưa kiểm chứng |
| **[?]** | Cần mẫu thật hoặc VM để xác nhận |

**Mẫu thật chưa được đưa vào để đối chiếu.** Người viết tài liệu này chưa xem `references/samples/` hay JSON thật của Tuần 3. Hợp đồng dựa trên mã PoC, Sysmon docs và schema/mapping của Data. Công cụ `contract_check.py` (mục 10) chạy trên mẫu thật để thay các giả định bằng số liệu, và kết quả sẽ cập nhật file 02.

## 1. Nguyên tắc

1. **Bronze không mất dữ liệu:** mỗi bản ghi giữ nguyên văn XML gốc (`raw_xml`) cùng tên trường gốc (`event_data`).
2. **Collector không ánh xạ ngữ nghĩa.** Việc đổi tên, ép kiểu, chuẩn hóa sang Silver thuộc **Silver transform của Data**. PoC hiện có hai nơi làm việc này (trường `data` của PoC và Silver) → hai nguồn sự thật; quyết định D-02 gỡ `data` khỏi Bronze.
3. **Append-only, bất biến:** segment đã niêm phong không sửa. Đọc lại (replay) luôn khả thi.
4. **At-least-once + idempotent:** có thể trùng bản ghi, nhưng `event_id` xác định để Silver khử trùng.
5. **Có phiên bản:** `schema_version` trong mỗi bản ghi; consumer bỏ qua trường lạ.

## 2. Cơ chế bàn giao: file segment (D-01)

| Phương án | Ưu | Nhược | Đánh giá |
|---|---|---|---|
| **A. Segment JSONL + manifest trên đĩa** | Tách miền lỗi (collector và pipeline chạy độc lập); replay; khớp Medallion và Bronze JSONL của Data | Độ trễ theo chu kỳ đóng segment; cần quản lý rotate/retention | **Đề xuất** |
| B. Gọi hàm trong cùng process | Đơn giản, độ trễ thấp | Lỗi một bên kéo sập cả hai; khó replay; DuckDB chỉ một process ghi (mục 5 file 03) | Chỉ dùng cho test |
| C. Queue/IPC (pipe, socket) | Gần real-time | Mất dữ liệu khi consumer chết nếu không có đệm bền; thêm phụ thuộc | Để Phase 2 |
| D. Collector ghi thẳng DuckDB | Ít bước | Mất Bronze; không replay; tranh chấp khóa file [X] | Loại |

## 3. Định dạng bản ghi

- **JSON Lines**, UTF-8 **không BOM**, kết thúc dòng `\n` (LF, **không CRLF**), một đối tượng/dòng, không dòng trống, không NaN/Infinity.
- **Quy tắc ghi file trên Windows:** Python ghi ở chế độ văn bản trên Windows mặc định đổi `\n` thành `\r\n`, nên writer phải mở bằng `open(path, "w", encoding="utf-8", newline="\n")`. Đã sửa ở PoC (`--output`) và có test; kiểm bằng `verify_windows_env.py` (W05).
- Schema: `contracts/bronze-event.schema.json` (JSON Schema 2020-12). Mã tham chiếu: `bronze_contract.py` (`build_bronze_record`, `validate_record`) **[PoC]**.

| Trường | Kiểu | Bắt buộc | Nguồn trong XML / quy tắc |
|---|---|---|---|
| `schema_version` | chuỗi hằng `bronze-event/1.0` | ✔ | Hợp đồng |
| `event_id` | UUID chữ thường | ✔ | `uuid5(NS, "<Computer>|<Channel>|<EventRecordID>")`; ổn định khi xuất lại |
| `source` | enum `SYSMON`, `WINDOWS_SECURITY_LOG`, `PSUTIL_SNAPSHOT`, `COLLECTOR_INTERNAL` | ✔ | Hằng theo nguồn (enum chờ Q-X3) |
| `channel` | chuỗi | ✔ | `System/Channel` |
| `provider.name`, `provider.guid` | chuỗi | ✔ / tùy chọn | `System/Provider@Name`, `@Guid` |
| `sysmon_event_id` | số nguyên | ✔ | `System/EventID` |
| `event_version`, `level`, `task`, `opcode`, `keywords` | số / chuỗi | tùy chọn | `System/Version`, `Level`, `Task`, `Opcode`, `Keywords` |
| `record_id` | số nguyên | ✔ | `System/EventRecordID` |
| `time_created` | chuỗi UTC `…Z`, tối đa 9 chữ số thập phân | ✔ | `System/TimeCreated@SystemTime`, **giữ nguyên chuỗi** |
| `writer_process_id`, `writer_thread_id` | số nguyên | tùy chọn | `System/Execution@ProcessID`, `@ThreadID`: process **ghi log** (Sysmon), không phải process bị giám sát |
| `log_writer_sid` | chuỗi | tùy chọn | `System/Security@UserID`: tài khoản ghi log (thường SYSTEM), **không** phải người dùng của process bị giám sát |
| `hostname` | chuỗi | ✔ | `System/Computer` |
| `host_id` | UUID | ✔ | `uuid5(NS_host, lower(hostname))` (D-05) |
| `event_data` | đối tượng chuỗi → chuỗi | ✔ | `EventData/Data[@Name]` đúng tên và giá trị gốc, không ép kiểu |
| `raw_xml` | chuỗi | ✔ | Nguyên văn XML của sự kiện |
| `ingest.collector.{name,version}` | chuỗi | ✔ | Định danh collector |
| `ingest.mode` | `live` hoặc `file` | ✔ | Chế độ đọc |
| `ingest.collected_at` | UTC | ✔ | Thời điểm collector đọc |
| `ingest.source_file`, `batch_id`, `seq` | tùy chọn | | Truy vết nguồn và thứ tự trong batch |

**Lưu ý đặt tên.** `writer_*` và `log_writer_sid` được đặt tên rõ để không bị nhầm với `pid`/`user_sid` của process bị giám sát (một nhầm lẫn dễ xảy ra vì `System/Security@UserID` là SID của dịch vụ ghi log).

## 4. Segment và manifest

- **Đường dẫn:** `bronze\sysmon\<host_id>\<YYYY>\<MM>\<DD>\sysmon_<YYYYMMDDTHHMMSSZ>_<seq>.jsonl` (chi tiết file 03). Tên file **không chứa `:`** và các ký tự cấm của Windows (`< > : " / \ | ? *`), nên mốc thời gian viết liền kiểu `20261014T021530Z`.
- **Vòng đời:** ghi vào `*.jsonl.part`; khi đóng (theo số bản ghi, kích thước hoặc thời gian; **ngưỡng TBD sau benchmark**) → flush, fsync, ghi manifest, đổi tên thành `.jsonl`. Pipeline **chỉ đọc segment đã niêm phong** (có manifest) [N].
- **Manifest** (`<segment>.manifest.json`): `schema_version`, `segment_id`, `host_id`, `channel`, `first_record_id`, `last_record_id`, `record_count`, `first_time_created`, `last_time_created`, `bytes`, `sha256` (của file `.jsonl`), `prev_manifest_sha256` (chuỗi băm, hỗ trợ TR-08), `sealed_at`, `collector_version`, `closed_cleanly`.
- **Quy tắc đọc:** pipeline kiểm `sha256` và `record_count` trước khi nạp; sai lệch → segment vào `quarantine/segments` (mã V-007).

## 5. Định danh, thứ tự, trùng lặp

- **Khóa khử trùng:** `event_id` (xác định từ `Computer|Channel|EventRecordID`) **[PoC]**. `INSERT OR IGNORE` / `ON CONFLICT DO NOTHING` hoạt động đúng với `PRIMARY KEY` trong DuckDB, trong khi insert trùng thường bị `ConstraintException` **[X]**. Vì vậy loader phải dùng cú pháp bỏ qua trùng, không chỉ `executemany` thường.
- **Thứ tự:** trong một segment tăng dần theo `record_id` (thứ tự thời gian). **PoC hiện đọc mới nhất trước** (`EvtQueryReverseDirection`, hợp để lấy mẫu) nên cần đổi sang đọc xuôi kèm bookmark khi làm collector thật (P-02).
- Consumer không được giả định thứ tự giữa các segment ngoài `last_record_id` và `time_created` của manifest.

## 6. Thời gian và mã hóa

- `time_created` giữ nguyên chuỗi UTC có hậu tố `Z`, độ phân giải 100 ns. `EventData/UtcTime` của Sysmon là chuỗi không có múi giờ, độ phân giải mili-giây (chuẩn UTC) và nằm trong `event_data` **[PoC, T:S1]**.
- **Bằng chứng [X]:** Pydantic v2 và DuckDB đều đọc được chuỗi 7 chữ số thập phân và **cắt âm thầm xuống micro giây** (mất chữ số thứ 7); `read_json_auto` của DuckDB suy ra cột là `TIMESTAMP WITH TIME ZONE`. Vì Bronze giữ chuỗi gốc nên không mất gì ở Bronze; mất ở Silver là chấp nhận được nếu Data xác nhận (M-09).
- Mã hóa: Bronze **UTF-8 không BOM**. Xuất bằng PowerShell `Out-File` mặc định là UTF-16; PoC đọc được UTF-16 và UTF-8 BOM nhưng **chưa thử trên file thật** **[PoC, ?]**.

## 7. Phiên bản và tương thích

- `bronze-event/<major>.<minor>`. Thêm trường tùy chọn = minor, consumer bỏ qua trường lạ (schema không đặt `additionalProperties: false`) **[PoC]**.
- Đổi tên/xóa trường, đổi ý nghĩa = major và thư mục mới `bronze/<schema>/…`.
- Mỗi bản ghi mang `ingest.collector.version`; Silver ghi lại `mapping_version` (phía Data) để truy vết reprocess.

## 8. Giao diện giữa collector và bước validation

```text
Collector (Software)                         Validation (Data)
  đọc Event Log ─► build record ─► segment ─►  đọc segment sealed ─► [1] kiểm envelope ─► [2] kiểm event_data ─► map Silver
        │ lỗi C-xxx                                   │ lỗi V-001..V-003                │ lỗi V-004..V-006
        ▼                                             ▼                                  ▼
  quarantine/collector                         quarantine/validation                (Silver insert)
```

| Mã | Lỗi | Bên phát hiện | Xử lý |
|---|---|---|---|
| C-001 | XML không hợp lệ | Collector | Ghi nguyên văn vào `quarantine/collector`, tăng bộ đếm, tiếp tục |
| C-002 | Thiếu `Channel`, `Computer`, `EventRecordID`, `EventID` hoặc `TimeCreated` | Collector | Như C-001 |
| C-003 | Lỗi giải mã văn bản/BOM | Collector | Như C-001 |
| C-004 | Ghi đĩa thất bại (đầy ổ, từ chối quyền) | Collector | Dừng nạp, **không** nâng checkpoint, cảnh báo |
| C-005 | Bookmark hỏng, hoặc mất bản ghi (stale) | Collector | Bắt đầu từ bản ghi cũ nhất còn lại, ghi sự kiện `COLLECTOR_INTERNAL` về khoảng hở |
| C-006 | Không có quyền đọc channel (access denied) | Collector | Dừng, báo lỗi rõ ràng |
| V-001 | Envelope sai schema, `schema_version` major lạ | Validation | `quarantine/validation`, giữ nguyên dòng gốc |
| V-002 | `event_data` thiếu trường bắt buộc của loại sự kiện | Validation | Như V-001 |
| V-003 | Ép kiểu thất bại (ví dụ `ProcessId` không phải số) | Validation | Như V-001 |
| V-004 | Giá trị ngoài enum Silver | Validation | Như V-001 |
| V-005 | Trùng `event_id` | Validation | Bỏ qua, **đếm**; không phải lỗi |
| V-006 | Insert Silver thất bại | Validation | Rollback segment, retry (file 04) |
| V-007 | Manifest sai (`sha256`, `record_count`) | Validation | Cô lập cả segment |

- **Bản ghi cô lập** (cả hai bên): `{quarantined_at, stage, reason_code, message, segment_id, line_no, payload, tool_version}`, với `payload` là dòng JSON gốc hoặc XML gốc.
- **Nguyên tắc trách nhiệm:** lỗi hình thành envelope là của collector; lỗi ý nghĩa dữ liệu so với Silver là của validation. **Không bên nào được xóa âm thầm**: mọi bản ghi bị loại phải có dòng trong quarantine và được đếm.
- **Khả năng test bằng mẫu:** cùng một bộ mẫu vàng (XML thật + JSON kỳ vọng) chạy cho cả hai bên; bộ mẫu âm (XML hỏng, thiếu trường, `schema_version` lạ, dòng bị cắt) kiểm từng mã lỗi **[N]**. Ví dụ hiện có: `test_bronze_contract.py` (9 test, mẫu giả lập) và `contract_check.py` (mục 10).

## 9. Cấu hình collector (chưa có giá trị số)

```yaml
# edr.yaml (ví dụ; mọi ngưỡng số để TBD sau benchmark)
data_root: C:\EDR\data
channels:
  - name: Microsoft-Windows-Sysmon/Operational
    source: SYSMON
segment:
  max_records: TBD
  max_age_seconds: TBD
checkpoint_dir: C:\EDR\data\checkpoints
quarantine_dir: C:\EDR\data\quarantine\collector
free_disk_stop_percent: TBD
```

## 10. Thay đổi cần làm ở PoC (truy vết)

| Mã | Thay đổi | Chủ | Mục tiêu |
|---|---|---|---|
| P-01 | Giữ `raw_xml` (tách `<Event>…</Event>` bằng `split_event_xml`; chế độ live dùng chuỗi `EvtRender`) | Software | W06 |
| P-02 | Đọc xuôi theo thời gian + bookmark (`EvtSubscribe` kiểu kéo với `EvtNext`) thay cho đọc ngược | Software | W06 |
| P-03 | Writer segment: `.part` → fsync → manifest → đổi tên; phục hồi `.part` | Software | W06 |
| P-04 | Mã lỗi C-xxx và quarantine collector | Software | W06 |
| P-05 | Đọc cấu hình từ `edr.yaml` (cần thêm phụ thuộc YAML) | Software | W06 |
| P-06 | Gỡ `data`/`event_type`/`process_guid` khỏi đầu ra Bronze; giữ cờ `--emit-normalized` cho đối chiếu, đổi `src_*` thành `source_*` (M-01) | Software | W06 |
| P-07 | Thêm `host_id`; `jsonschema` vào dev dependencies | Software | W06 |

**Chạy trên mẫu thật** (cặp lệnh để đối chiếu ngay khi có mẫu):

```powershell
cd poc\sysmon-collector
python contract_check.py --samples ..\..\references\samples --out coverage_report.md
python -m pytest -q
```
Báo cáo `coverage_report.md` liệt kê theo từng Sysmon event id: trường có/thiếu/rỗng, trường lạ chưa ánh xạ, cột Silver chưa tồn tại.

## 11. Trạng thái kiểm chứng

| Hạng mục | Trạng thái |
|---|---|
| Schema, builder, validator, bộ kiểm trường | 24 test đạt (13 PoC + 9 contract + 2 kiểm tra môi trường), mẫu giả lập, chạy trên Linux |
| Giữ nguyên văn XML | Test đạt: `raw_xml` là chuỗi con nguyên bản của file |
| Chạy live, bookmark, segment writer | **Chưa viết/chưa chạy** (thiết kế ở file 03, 04) |
| Đối chiếu với mẫu và JSON thật | **Chưa thực hiện** |
