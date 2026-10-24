# Error/Recovery & Operational Notes

**Trạng thái:** DRAFT thiết kế. Chưa có phần nào được chạy trên VM Windows; không có số đo hiệu năng. Nhãn: **[T]** tài liệu, **[X, Linux]** kiểm chứng trong container Linux (xác nhận lại bằng `verify_windows_env.py`, file 06), **[N]** giả định, **[?]** cần xác minh.

## 1. Nền tảng từ Windows Event Log

- Bookmark định danh một sự kiện trong channel; có thể đọc tiếp từ đó khi truy vấn hoặc đăng ký (`EvtSubscribe` với bookmark và cờ `EvtSubscribeStartAfterBookmark`). Bookmark được kết xuất thành **chuỗi XML để lưu bền**; khi chưa lưu bookmark thì bắt đầu từ sự kiện kế tiếp theo quy ước của API **[T:E1]**.
- Nếu không dùng callback, gọi `EvtNext` trong vòng lặp để lấy sự kiện (chế độ kéo); với cờ `EvtSubscribeStrict`, hệ thống báo lỗi `ERROR_EVT_QUERY_RESULT_STALE` khi channel đã mất bản ghi **[T:E1]**. Đây là cơ chế phát hiện khoảng hở, thay vì suy ra từ số `EventRecordID`: khi lọc theo EventID thì `EventRecordID` không liên tục là bình thường.
- Tên hàm và chữ ký tương ứng trong `pywin32` (`EvtCreateBookmark`, `EvtUpdateBookmark`, `EvtSeek`, `EvtSubscribe` dạng kéo) **chưa kiểm chứng trên VM [?]**; kiểm tra trước khi viết collector thật bằng kiểm tra W08 của `verify_windows_env.py` (liệt kê tên hàm còn thiếu và thử đọc channel Sysmon).

## 2. Giao thức checkpoint (at-least-once)

1. `EvtNext` lấy một lô sự kiện (kích thước lô TBD).
2. Với mỗi sự kiện: dựng bản ghi Bronze; lỗi → quarantine (C-001…C-003), tiếp tục.
3. Ghi lô vào `*.jsonl.part` (mở với `newline="\n"`, UTF-8 không BOM), **flush và `os.fsync`** trên file. Windows không có `fsync` cho thư mục; thao tác đổi tên dựa vào tính nhất quán metadata của NTFS **[N]**.
4. Cập nhật bookmark trong bộ nhớ theo sự kiện cuối lô.
5. **Sau khi bước 3 bền vững**, ghi bookmark XML ra file tạm rồi `os.replace` lên `checkpoints\…bookmark.json`. Trên Windows `os.replace` có thể bị chặn (`PermissionError`, sharing violation) khi Defender hoặc tiến trình khác đang giữ file: **thử lại với thời gian chờ tăng dần**, hết lần thử thì cảnh báo và **không** coi checkpoint đã lưu **[N]**.
6. Khi đủ điều kiện (số bản ghi/kích thước/thời gian, TBD): **đóng handle ghi**, rồi niêm phong segment (manifest, đổi tên `.part` → `.jsonl`). Windows chặn đổi tên file đang mở (kiểm tra W06).

**Thứ tự này bảo đảm:** chết trước bước 5 thì sự kiện sẽ được đọc lại (trùng, vô hại nhờ `event_id` xác định); chết sau bước 5 thì dữ liệu đã bền. Không bao giờ nâng checkpoint trước khi ghi bền.

## 3. Ma trận lỗi và phục hồi

| Tình huống | Phát hiện | Xử lý | Mất dữ liệu? |
|---|---|---|---|
| Collector chết giữa chừng khi đang ghi dòng | Khởi động lại thấy `.part` có dòng cuối thiếu `\n` hoặc JSON hỏng | Quét `.part`, **cắt phần sau dòng hợp lệ cuối**, ghi manifest, niêm phong; dòng bị cắt vào `quarantine/collector` kèm lý do | Không: sự kiện vẫn ở Event Log (sau bookmark cũ) trừ khi đã bị ghi đè |
| Chết giữa bước 3 và 5 (đã ghi, chưa lưu bookmark) | Bookmark cũ hơn dữ liệu | Đọc lại từ bookmark; bản ghi trùng bị khử bởi `event_id` | Không; có trùng |
| Bookmark hỏng hoặc không đọc được | Lỗi giải XML bookmark | Bắt đầu từ bản ghi cũ nhất còn lại, ghi sự kiện `COLLECTOR_INTERNAL` mô tả khoảng hở | Có thể có sự kiện cũ đã bị ghi đè |
| Channel bị ghi đè khi collector chậm/dừng lâu | `ERROR_EVT_QUERY_RESULT_STALE` (cờ Strict) **[T:E1]** | Ghi khoảng hở, tiếp tục từ bản ghi cũ nhất | **Có**: giảm thiểu bằng tăng kích thước channel (TR-01) |
| Xóa log (`wevtutil cl`, Security 1102) | Sự kiện 1102/104, hoặc bookmark không còn hợp lệ | Như bookmark hỏng; cảnh báo (liên quan T1562) | Có thể |
| Đầy đĩa / từ chối quyền khi ghi | Lỗi ghi (C-004) | Dừng nạp, **không nâng checkpoint**, cảnh báo; event vẫn nằm trong Event Log tới khi bị ghi đè | Không nếu xử lý kịp |
| `PermissionError` / sharing violation khi đổi tên hoặc ghi checkpoint (Defender hoặc reader giữ file) **[?]** | Lỗi hệ điều hành lúc `os.replace` | Thử lại với thời gian chờ tăng dần; reader chỉ mở segment đã niêm phong và đóng ngay; hết lần thử → cảnh báo, không nâng checkpoint | Không |
| Tên file/đường dẫn không hợp lệ hoặc quá dài (lỗi Windows) | Lỗi tạo file lúc khởi động hoặc xoay segment | Dừng với thông báo cấu hình rõ ràng; kiểm `C:\EDR` ngắn và tên file không chứa ký tự cấm (W07) | Không |
| Máy tắt/khởi động lại (Windows Update, shutdown) | Collector nhận tín hiệu dừng, hoặc chết đột ngột | Tín hiệu dừng: niêm phong và lưu bookmark rồi thoát; chết đột ngột: như dòng "chết giữa chừng" ở trên. Khi khởi động chờ Sysmon chạy trước (`Get-Service Sysmon64`) | Không (nếu channel chưa bị ghi đè) |
| Giờ hệ thống hoặc múi giờ bị đổi | `time_created` nhảy lùi so với bản ghi trước | Dùng `record_id` và bookmark để xác định thứ tự, không dùng đồng hồ máy; ghi cảnh báo `COLLECTOR_INTERNAL` | Không |
| XML hỏng/giải mã lỗi | C-001, C-003 | Quarantine nguyên văn, tiếp tục (không dừng cả luồng) | Không: lưu ở quarantine |
| Pipeline chết giữa transaction | Segment ở trạng thái `in_progress` trong `_ingest_ledger` | DuckDB hoàn tác transaction chưa commit; chạy lại segment từ đầu | Không |
| Insert trùng khi replay | `ConstraintException` nếu dùng insert thường **[X, Linux]** | Dùng `INSERT OR IGNORE`/`ON CONFLICT DO NOTHING` **[X, Linux]**; đếm số trùng | Không |
| Bản ghi "độc" (poison) lặp lại gây lỗi | Cùng dòng thất bại sau N lần thử (N TBD) | Cô lập dòng (V-xxx), **không** chặn cả segment | Không |
| Segment lỗi toàn bộ (manifest sai, file hỏng) | V-007 | `quarantine/segments`, cảnh báo, các segment khác tiếp tục | Không: file gốc còn |
| Schema/mapping đổi | `mapping_version` khác | **Reprocess từ Bronze**: dựng lại Silver từ segment (ledger đặt lại cho phiên bản mới) | Không |

## 4. Retry, replay, backpressure

- **Retry:** lỗi tạm thời (khóa file, Defender giữ file, từ chối quyền ngắn hạn) thử lại với **thời gian chờ tăng dần**, số lần tối đa TBD; hết lần thử → cô lập và báo (không lặp vô hạn).
- **Replay:** vì Bronze bất biến và Silver nạp idempotent, replay = chạy lại bộ nạp trên tập segment (toàn bộ hoặc theo dải `record_id`/thời gian). Cần cờ chọn phạm vi và `run_id` mới.
- **Backpressure:** mô hình **kéo** (`EvtNext`) cho phép collector dừng đọc khi hàng đợi ghi đầy mà không rơi sự kiện, vì sự kiện vẫn nằm trong Event Log. Rủi ro là độ trễ vượt thời gian lưu giữ channel (bị ghi đè). Do đó: hàng đợi có giới hạn, đo **độ trễ** (tuổi của sự kiện chưa đọc) và cảnh báo khi tiến gần giới hạn channel. Với chế độ đẩy (callback) hàng đợi đầy sẽ phải bỏ hoặc chặn: **không dùng** cho collector chính.
- **Một process, một nhiệm vụ:** collector và pipeline chạy độc lập; pipeline chậm không làm collector dừng (Bronze là đệm).

## 5. Logging và observability

**Nhật ký có cấu trúc** (JSONL, mỗi thành phần một file): `ts` (UTC), `level`, `component`, `run_id`, `batch_id`, `segment_id`, `event`, `reason_code`, `message`, số đếm liên quan.

| Thành phần | Chỉ số (mỗi batch/segment, ghi vào `metrics.jsonl`) |
|---|---|
| Collector | `events_read`, `events_written`, `events_quarantined` (theo `reason_code`), `bytes_written`, `segments_sealed`, `bookmark_commits`, `gap_detected`, `lag_seconds` (tuổi sự kiện cũ nhất chưa đọc), `loop_duration` |
| Pipeline | `segments_ingested`, `records_read`, `records_validated`, `records_rejected` (theo `reason_code`), `records_inserted` theo bảng, `duplicates_ignored`, `transform_errors` theo loại, `batch_duration`, `insert_duration`, `snapshot_published` |
| Hệ thống | dung lượng trống, kích thước từng thư mục dữ liệu, kích thước file DuckDB |

- **Dấu vết thực thi:** mỗi lần chạy sinh `run_manifest.json` gồm `run_id`, thời gian, danh sách segment, phiên bản collector/schema/mapping, hash `edr.yaml` và `sysmon-config.xml`, commit git. Silver mang cột lineage (file 03 mục 4) để truy ngược một alert tới dòng Bronze và `raw_xml`.
- **Tiêu chí tự kiểm tra:** `events_read = events_written + events_quarantined` trong mỗi lô; `records_read = validated + rejected`; `validated = inserted + duplicates` (chênh lệch là lỗi cần điều tra).

## 6. Mục tiêu tài nguyên và kế hoạch benchmark (không có số đo)

**Đây là mục tiêu cần xác nhận, không phải kết quả đã đạt.**

| Mục tiêu | Nguồn | Trạng thái |
|---|---|---|
| RAM của pipeline Phase 1 | `data_pipeline_phase_1_scope.md`: < 200 MB; `phase_1_local_data_architecture_mapping.md`: < 150 MB (hai tài liệu không khớp, Q-D5) | Chưa đo |
| CPU | Scope: spike không quá 5% trên máy lab | Chưa đo |
| Độ trễ truy vấn Silver | Scope: dưới 100 ms (báo cáo Tuần 2 của Data ghi POC dưới 50 ms, chưa rõ khối lượng dữ liệu) | Chưa đo ở môi trường này |
| Đúng đắn (định tính) | Không mất sự kiện khi kill collector/pipeline; mọi sự kiện đọc đều có mặt ở Bronze hoặc quarantine; không trùng ở Silver | Cần thử nghiệm B5 |

| Kịch bản | Mục đích | Chỉ số |
|---|---|---|
| B1 Nhàn rỗi (khoảng thời gian TBD) | Đường cơ sở | CPU, RAM của Sysmon, collector, pipeline riêng; số sự kiện/giờ theo event id |
| B2 Sử dụng bình thường | Khối lượng thực tế | Như B1; `lag_seconds` |
| B3 Chạy bộ test (PoC scripts, Atomic Red Team tập con) | Độ phủ và tải đỉnh | Sự kiện/giây, độ trễ từ sự kiện đến Silver |
| B4 Replay Bronze tốc độ tối đa | Thông lượng pipeline | Bản ghi/giây, RAM đỉnh, kích thước DuckDB |
| B5 Kill collector/pipeline ngẫu nhiên | Đúng đắn của checkpoint | Mất/trùng sự kiện (mục tiêu: không mất, không trùng ở Silver) |
| B6 Collector dừng lâu hơn thời gian lưu giữ channel | Phát hiện khoảng hở | Có ghi `gap_detected` đúng không |
| B7 Chạy kéo dài (số giờ TBD) | Rò rỉ bộ nhớ, tăng trưởng đĩa | RAM theo thời gian, dung lượng |
| B8 Đầy đĩa | Hành vi dừng an toàn | Không hỏng segment, không nâng checkpoint |

**Phương pháp:** ghi lại cấu hình môi trường (VM, build Windows, phiên bản Sysmon và hash cấu hình, Python và thư viện, commit); lấy mẫu CPU/RAM từng process theo chu kỳ (ví dụ bằng `psutil`, Performance Monitor hoặc `Get-Counter` của Windows); đo Sysmon tách riêng; mỗi số liệu ghi kèm kịch bản và thời gian đo. Bảng kết quả để trống cho đến khi đo.

## 7. Ghi chú vận hành

| Hạng mục | Nội dung |
|---|---|
| Khởi động | Sysmon → collector → pipeline; kiểm `Get-Service Sysmon64` đang chạy và `run\*.lock` để tránh hai instance |
| Cách chạy nền | Dịch vụ Windows hay Scheduled Task: **TBD**; tài khoản chạy cần quyền đọc channel Sysmon (thí nghiệm E10 Tuần 3, kiểm tra W08) |
| Dừng | Dừng collector trước (niêm phong segment hiện tại, lưu bookmark; xử lý cả tín hiệu dừng dịch vụ và tắt máy), rồi pipeline hoàn tất batch |
| Kiểm tra hằng ngày | Số bản ghi ở quarantine theo `reason_code`; `lag_seconds`; dung lượng trống; segment `failed` |
| Sau khi đổi `sysmon-config.xml` | Ghi hash vào `run_manifest.json`; Event 16 sẽ xuất hiện trong Event Log |
| Dọn dẹp | Chỉ quản trị viên xóa Bronze theo chính sách giữ (TBD); không xóa segment chưa nạp xong |
| Khi mất dữ liệu nghi ngờ | Kiểm `gap_detected`, Event 1102/104, kích thước channel |

## 8. Nguồn

- E1: Microsoft Learn, "Bookmarking Events": https://learn.microsoft.com/en-us/windows/desktop/WES/bookmarking-events
- D1: DuckDB, "Handling Concurrency": https://duckdb.org/docs/current/connect/concurrency
