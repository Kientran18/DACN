# EDR — Ma trận nghiệm thu

> PROPOSAL (2026-11-08). Dùng để xác định dự án đã thật sự sẵn sàng nghiệm thu chưa. **Trạng thái ban đầu: hầu hết `NOT RUN`/`PLANNED`**. Không điền `PASS` khi chưa có bằng chứng thật. Phân biệt rõ môi trường: **Linux/fixture** ≠ **Windows VM thật**.

Quy ước trạng thái: `PASS` · `FAIL` · `NOT RUN` · `N/A`. Cột *Mức bằng chứng*: `F` fixture/giả lập · `L` chạy Linux với dữ liệu mẫu · `W` chạy trên Windows VM thật.

## 1. Yêu cầu EDR → module → hiện thực → test → bằng chứng → trạng thái

| ID | Yêu cầu (từ mục tiêu MVP) | Module | Hiện thực | Test chính | Bằng chứng | Trạng thái |
|---|---|---|---|---|---|---|
| R-01 | Thành phần Windows thu thập telemetry Sysmon liên tục | `src/agent/` | PH2 (chưa có). Hiện có `poc/sysmon-collector/` file mode (L) | AT-01…AT-05 | Chưa có (live mode `UNKNOWN`) | NOT RUN |
| R-02 | Pipeline tiếp nhận, chuẩn hóa, kiểm tra, lưu sự kiện | `src/pipeline/` | PoC trong bộ nhớ (L); bền vững: PH3 | AT-06…AT-10 | Chạy 18 sự kiện mẫu → 16 Silver / 2 DLQ (L, 2026-11-08, ngoài test suite) | NOT RUN (bền vững) |
| R-03 | Detection Engine phát hiện hành vi/IOC/mẫu test | `src/detection/` | PH4 | AT-11…AT-16 | Chưa có | NOT RUN |
| R-04 | Cảnh báo có thông tin và bằng chứng | `src/alerts/` | PH6 | AT-17…AT-20 | Chưa có | NOT RUN |
| R-05 | Phản ứng có kiểm soát (terminate/quarantine thử nghiệm khi được phép) | `src/response/` | PH7 | AT-21…AT-26 | Chưa có | NOT RUN |
| R-06 | Backend API kết nối module | `src/api/` | PH8 | AT-27…AT-29 | Chưa có | NOT RUN |
| R-07 | Dashboard giám sát endpoint/sự kiện/phát hiện/cảnh báo/phản ứng | `src/dashboard/` | PH9 | AT-30…AT-33 | Chưa có | NOT RUN |
| R-08 | Cài đặt/khởi động toàn hệ thống theo quy trình tài liệu hóa | `src/edr_ctl.py`, tài liệu | PH10 | AT-34, AT-35 | Chưa có | NOT RUN |
| R-09 | Bộ kiểm thử end-to-end trên Windows 10 VM | `tests/e2e/`, `scripts/lab/` | PH5, PH10, PH11 | AT-36…AT-40 | Chưa có | NOT RUN |
| R-10 | Tài liệu kỹ thuật, hướng dẫn, báo cáo nghiệm thu | `docs/` | PH12 | AT-41 | Bộ kế hoạch này (chỉ là kế hoạch) | NOT RUN |
| R-11 | Hợp đồng dữ liệu không bị phá vỡ (Bronze 1.0, UUIDv5, raw preservation) | contract tests | Có test (L) | AT-42 | 3 + 10 test contract chạy trên Linux; 1 test fail (C-002) | FAIL (1 test) |
| R-12 | Khả năng thêm ML mà không viết lại engine | `src/detection/ml/` | PH4-T10 | AT-43 | Chưa có | NOT RUN |

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

## 4. Tình trạng tổng hợp (cập nhật khi có bằng chứng)

| Trạng thái | Số test nghiệm thu (AT) |
|---|---|
| PASS | 0 |
| FAIL | 0 |
| NOT RUN | 43 |

Ghi chú: yêu cầu R-11 hiện có bằng chứng một test **hiện có** của repository đang fail (`test_collector_errors_use_reason_codes`, đo 2026-11-08) nên yêu cầu mang trạng thái FAIL; test nghiệm thu AT-42 chưa chạy.

Giới hạn chung: kết quả `L`/`F` không thay cho kiểm chứng trên Windows; tỷ lệ phát hiện chỉ có nghĩa trên tập kịch bản đã chạy; không suy rộng sang malware ngoài thực tế.
