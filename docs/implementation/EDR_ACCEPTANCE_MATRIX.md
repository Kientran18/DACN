# EDR — Ma trận nghiệm thu

> PROPOSAL (2026-11-08). Dùng để xác định dự án đã thật sự sẵn sàng nghiệm thu chưa. **Trạng thái ban đầu: hầu hết `NOT RUN`/`PLANNED`**. Không điền `PASS` khi chưa có bằng chứng thật. Phân biệt rõ môi trường: **Linux/fixture** ≠ **Windows VM thật**.

Quy ước trạng thái: `PASS` · `FAIL` · `NOT RUN` · `N/A`. Cột *Mức bằng chứng*: `F` fixture/giả lập · `L` chạy Linux với dữ liệu mẫu · `W` chạy trên Windows VM thật.

## 1. Yêu cầu EDR → module → hiện thực → test → bằng chứng → trạng thái

| ID | Yêu cầu (từ mục tiêu MVP) | Module | Hiện thực | Test chính | Bằng chứng | Trạng thái |
|---|---|---|---|---|---|---|
| R-01 | Thành phần Windows thu thập telemetry Sysmon liên tục | `src/agent/` | PH2 (Linux: nguồn giả/tệp; live Windows chưa kiểm chứng) | AT-01…AT-05 | Báo cáo nghiệm thu mức L; live Windows `UNKNOWN` | 3 NOT RUN, 2 PASS |
| R-02 | Pipeline tiếp nhận, chuẩn hóa, kiểm tra, lưu sự kiện | `src/pipeline/` | PH3 (DuckDB bền vững, replay; L) | AT-06…AT-10 | Báo cáo nghiệm thu mức L | 5 PASS |
| R-03 | Detection Engine phát hiện hành vi/IOC/mẫu test | `src/detection/` | PH4 | AT-11…AT-16 | Báo cáo nghiệm thu mức L | 1 NOT RUN, 5 PASS |
| R-04 | Cảnh báo có thông tin và bằng chứng | `src/alerts/` | PH6 | AT-17…AT-20 | Báo cáo nghiệm thu mức L | 4 PASS |
| R-05 | Phản ứng có kiểm soát (terminate/quarantine thử nghiệm khi được phép) | `src/response/` | PH7 | AT-21…AT-26 | Báo cáo nghiệm thu mức L | 2 NOT RUN, 4 PASS |
| R-06 | Backend API kết nối module | `src/api/` | PH8 | AT-27…AT-29 | Báo cáo nghiệm thu mức L | 3 PASS |
| R-07 | Dashboard giám sát endpoint/sự kiện/phát hiện/cảnh báo/phản ứng | `src/dashboard/` | PH9 | AT-30…AT-33 | Báo cáo nghiệm thu mức L | 1 NOT RUN, 2 PARTIAL, 1 PASS |
| R-08 | Cài đặt/khởi động toàn hệ thống theo quy trình tài liệu hóa | `src/edr_ctl.py`, tài liệu | PH10 | AT-34, AT-35 | Báo cáo nghiệm thu mức L | 2 NOT RUN |
| R-09 | Bộ kiểm thử end-to-end trên Windows 10 VM | `tests/e2e/`, `scripts/lab/` | PH5, PH10, PH11 | AT-36…AT-40 | Báo cáo nghiệm thu mức L | 5 NOT RUN |
| R-10 | Tài liệu kỹ thuật, hướng dẫn, báo cáo nghiệm thu | `docs/` | PH12 | AT-41 | Kiểm tra liên kết; user guide/báo cáo cuối thuộc PH12 | 1 PARTIAL |
| R-11 | Hợp đồng dữ liệu không bị phá vỡ (Bronze 1.0, UUIDv5, raw preservation) | contract tests | Có test (L) | AT-42 | Test contract chạy lại mức L, xem báo cáo | 1 PASS |
| R-12 | Khả năng thêm ML mà không viết lại engine | `src/detection/ml/` | PH4-T10 | AT-43 | Báo cáo nghiệm thu mức L | 1 PARTIAL |

**Điều kiện sẵn sàng nghiệm thu MVP:** R-01…R-09 đều `PASS` ở mức bằng chứng `W` (hoặc `L` cho R-06 phần logic), chuỗi `Telemetry → Pipeline → Detection → Alert → Investigation → Safe Response → Dashboard` được chạy thật ít nhất một kịch bản (SC-01 hoặc SC-03) và lặp lại được.

## 2. Mẫu một test nghiệm thu

| Trường | Nội dung |
|---|---|
| ID | AT-xx |
| Preconditions | trạng thái hệ thống, dữ liệu, phiên bản, snapshot |
| Steps | lệnh/thao tác đánh số |
| Expected | kết quả kỳ vọng cụ thể |
| Actual | đầu ra thực tế (dán/đường dẫn tệp) |
| Status | PASS / FAIL / NOT RUN |
| Evidence | lệnh, đầu ra, ảnh chụp (đã che định danh), commit/PR |
| Known limitations | giới hạn của test |

## 3. Danh sách test nghiệm thu (rút gọn; Preconditions/Steps đầy đủ viết ở PH11-T01)

Mức: `F/L/W`. Tất cả `Actual` hiện **chưa có**; Status = `NOT RUN`.

| ID | Req | Mức | Mục tiêu / Expected chính | Known limitations (dự kiến) |
|---|---|---|---|---|
| AT-01 | R-01 | L | Nguồn giả → segment sealed, manifest đúng hash | Không chứng minh đọc Event Log thật |
| AT-02 | R-01 | L | Dừng/chết giữa chừng → khởi động lại không mất bản ghi (có thể trùng) | Giả lập |
| AT-03 | R-01 | W | Agent live nhận sự kiện mới và khớp `wevtutil` export | Một VM, một phiên bản Sysmon |
| AT-04 | R-01 | W | Không có quyền đọc channel → lỗi `C-006` rõ ràng | |
| AT-05 | R-01 | W | Kill agent giữa chừng trên Windows → phục hồi | |
| AT-06 | R-02 | L | Segment hỏng 1 byte → quarantine segment, segment khác vẫn nạp | |
| AT-07 | R-02 | L | Nạp hai lần → không trùng; tổng đọc = valid + dedup + DLQ | |
| AT-08 | R-02 | L | Replay từ Bronze dựng lại Silver trùng bản gốc | |
| AT-09 | R-02 | L | Bản ghi thiếu field bắt buộc → DLQ `ERR_*`, không điền mặc định | |
| AT-10 | R-02 | L | Alert/Silver → Bronze → `raw_xml` truy vết được | |
| AT-11 | R-03 | L | DET-001 dương/lành tính/thiếu dữ liệu đúng kỳ vọng | Fixture, chưa phải telemetry live |
| AT-12 | R-03 | L | DET-003 như trên | Không có mẫu Run thật trước PH5 |
| AT-13 | R-03 | L | DET-010 chuỗi đủ → `MATCH`; thiếu Event 26 → `PENDING_LATE_EVENTS` | |
| AT-14 | R-03 | L | IOC khớp hash tệp thử nghiệm; allowlist không bị gắn cờ | Hash không chứng minh độc hại |
| AT-15 | R-03 | L | Replay không sinh `DetectionResult` trùng | |
| AT-16 | R-03 | W | SC-01…SC-04 phát hiện trên VM, ghi nguồn phát hiện (EDR/Defender) | Chỉ trên tập kịch bản đã chạy |
| AT-17 | R-04 | L | `MATCH` → alert đủ trường, severity có lý do | |
| AT-18 | R-04 | L | Máy trạng thái alert chặn chuyển sai | |
| AT-19 | R-04 | L | Dedup alert; `INSUFFICIENT_TELEMETRY` thành "coverage gap", không phải alert đe dọa | |
| AT-20 | R-04 | L | Timeline + cây tiến trình đúng với mẫu | |
| AT-21 | R-05 | L | Mặc định `dry_run`: không đổi hệ thống | |
| AT-22 | R-05 | L | Thiếu approval → từ chối | |
| AT-23 | R-05 | L | Mục tiêu thuộc allowlist bảo vệ → từ chối | |
| AT-24 | R-05 | L | PID tái sử dụng → phát hiện và từ chối | Giả lập |
| AT-25 | R-05 | W | Terminate tiến trình thử nghiệm (chỉ marker lab) khi `execute` + audit | Chỉ tiến trình thử nghiệm |
| AT-26 | R-05 | W | Quarantine tệp thử nghiệm rồi restore, hash khớp | Chỉ thư mục lab |
| AT-27 | R-06 | L | Xác thực: thiếu/sai token → 401/403 | |
| AT-28 | R-06 | L | Validate input: tham số sai/quá lớn → lỗi mã ổn định | |
| AT-29 | R-06 | L | Endpoint events/detections/alerts/response trả đúng schema | |
| AT-30 | R-07 | L | Dashboard hiển thị dữ liệu từ API, có tìm/lọc/chi tiết | Fixture phải gắn nhãn "DỮ LIỆU MẪU" |
| AT-31 | R-07 | L | Trạng thái loading/lỗi/rỗng | |
| AT-32 | R-07 | L | Chi tiết alert hiển thị nguồn bằng chứng + kết quả response | |
| AT-33 | R-07 | W | Dashboard trên VM hiển thị cảnh báo thật của SC-01 | |
| AT-34 | R-08 | W | `edr_ctl start/status/stop` khởi động/dừng sạch, không tiến trình mồ côi | |
| AT-35 | R-08 | W | Làm theo hướng dẫn cài từ VM sạch tới hệ thống chạy | |
| AT-36 | R-09 | W | Chuỗi đầy đủ SC-01 từ snapshot sạch | |
| AT-37 | R-09 | W | Chuỗi đầy đủ SC-03 → alert → duyệt response → terminate/quarantine | |
| AT-38 | R-09 | W | Kiểm soát lành tính SC-06 không sinh alert đe dọa | Cỡ mẫu nhỏ |
| AT-39 | R-09 | W | Trường hợp thiếu telemetry SC-07 → `INSUFFICIENT/PENDING`, không báo giả | |
| AT-40 | R-09 | W | Lặp lại demo lần 2 từ snapshot sạch cho kết quả tương đương | |
| AT-41 | R-10 | — | Tài liệu cài đặt/user guide/báo cáo đầy đủ, liên kết hợp lệ | |
| AT-42 | R-11 | L | Toàn bộ test contract/identity xanh; UUIDv5 từ Silver tái dựng được | Phụ thuộc quyết định hostname (D-07) |
| AT-43 | R-12 | L | Tắt ML = hành vi không đổi; detector giả hoạt động | |

## 4. Tình trạng tổng hợp (sinh từ `scripts/acceptance/run_acceptance.py`)

Chạy lúc 2026-11-08T13:19:43Z (UTC), commit `da94bd4`, mức bằng chứng **L** (Linux). Chi tiết từng AT: [acceptance/ACCEPTANCE_REPORT.md](acceptance/ACCEPTANCE_REPORT.md); việc cho người dùng trên VM: [acceptance/WINDOWS_ACCEPTANCE_CHECKLIST.md](acceptance/WINDOWS_ACCEPTANCE_CHECKLIST.md).

| Trạng thái | Số test nghiệm thu (AT) |
|---|---|
| PASS | 25 |
| PARTIAL (test đạt, còn khoảng trống ghi trong báo cáo) | 4 |
| FAIL | 0 |
| NOT RUN (cần Windows VM) | 14 |

Ghi chú: các AT PASS ở mức L dùng dữ liệu synthetic/giả lập; các mục đã thay đổi so với bản đầu: R-11 không còn FAIL vì lỗi mã `C-002` đã được sửa và chạy lại. Điều kiện sẵn sàng nghiệm thu MVP (mục 1) **chưa đạt**: R-01, R-05, R-07, R-08, R-09 còn AT mức W chưa chạy.

Giới hạn chung: kết quả `L`/`F` không thay cho kiểm chứng trên Windows; tỷ lệ phát hiện chỉ có nghĩa trên tập kịch bản đã chạy; không suy rộng sang malware ngoài thực tế.
