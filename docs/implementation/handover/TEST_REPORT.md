# EDR — Báo cáo kiểm thử (PH12-T03)

> Tổng hợp từ [../acceptance/ACCEPTANCE_REPORT.md](../acceptance/ACCEPTANCE_REPORT.md) (sinh tự động; số liệu chi tiết lấy từ đó). Không sao chép số liệu tay vào các tài liệu khác.

## 1. Phạm vi và môi trường

- Môi trường duy nhất đã chạy: **Linux container**, Python 3.13, pytest 9.2, DuckDB 2.0, FastAPI 0.162, dữ liệu **synthetic/giả lập**. Phiên bản chính xác ở đầu báo cáo sinh tự động.
- **Windows 10 VM: chưa chạy bất kỳ test nào.**

## 2. Kết quả

| Hạng mục | Kết quả (2026-11-08; chạy lại 2026-11-09 sau `36ee751`; chạy lại 2026-11-18 và 2026-11-22 sau audit) |
|---|---|
| Toàn bộ pytest | **428 pass, 1 skipped, 0 fail** khi có `lightgbm` (395 trước khi thêm `tests/test_install_guide_flags.py`, 15 ca); **389 pass, 2 skipped** khi không có (Linux, 2026-11-22, đo trước khi thêm 15 test, chưa đo lại; skipped = test cần Windows thật và, khi thiếu `lightgbm`, test nạp mô hình EMBER2024). Lịch sử: 201 → 213 sau `36ee751` → 233 (2026-11-09) → 251 sau ML → 260 sau audit đợt 1 → 284 sau sửa U2–U8 → 322 sau merge issue #40 và sửa `same_time` → 395 sau audit đợt 2 (2026-11-22) |
| Nghiệm thu AT-01…43 mức L | 28 PASS · 1 PARTIAL · 0 FAIL · 14 NOT RUN (chạy lại 2026-11-22, không đổi) |
| Hai lỗi baseline của PH1 | Đã sửa và chạy lại (`C-002`; entropy test dùng giá trị đã biết) |

PARTIAL: AT-31 (thiếu kiểm tra loading), AT-32 (thiếu kiểm tra kết quả response trên màn chi tiết), AT-41 (mới kiểm liên kết nội bộ), AT-43 (chưa có detector giả). NOT RUN: các AT mức W (AT-03/04/05/16/25/26/33/34…40).

## 3. Lỗi thật phát hiện nhờ kiểm thử

- Agent và launcher dùng hai đường dẫn khác nhau cho tệp dừng (chỉ lộ khi chạy tiến trình thật).
- `edr_ctl status/stop` phụ thuộc tham số của `start`.
- `[object HTMLElement]` hiển thị trong dashboard, chỉ thấy qua ảnh chụp; nay có test chặn.
- Hai nhánh làm việc song song có thể hỏng khi gộp dù git không báo xung đột: việc dọn import `List` ở `src/api/app.py` làm 2 test fail sau khi merge mã #40 (mã mới dùng `List`); chỉ lộ khi chạy lại toàn bộ test sau merge.
- Lỗi phụ thuộc múi giờ máy chỉ lộ khi đặt `TZ` khác UTC: `same_time` (response) và hạn IOC; nay có test chạy ở nhiều múi giờ.
- Dashboard ẩn tiến trình con khi thiếu Event 1 của tiến trình gốc, chỉ thấy khi chạy Playwright trên fixture có alert như vậy; một kiểm tra ban đầu cho kết quả "đạt" giả vì `goto` tới đúng hash cũ không dựng lại trang.
- Nhiều lỗi nhỏ khác ghi trong nhật ký phiên của `EDR_PROGRESS.md`.

## 4. Điều kết quả này KHÔNG chứng minh

- Đọc Event Log thật, `WinProcessApi`, script lab PowerShell, cấu hình Sysmon và hướng dẫn cài đặt trên Windows. Các nhánh Windows của `edr_ctl.pid_alive`, `verify_windows_env.py` (B-03/B-04), script lab và `same_time` chỉ được kiểm bằng giả lập hoặc kiểm tĩnh trên Linux.
- Phần issue #40: tác giả (BuiCuongTuan) báo đã chạy trên Windows host (Python 3.12.8, gồm test khóa tệp thật), **không phải** Windows 10 VM với Sysmon live; chưa tái lập trong báo cáo này.
- Chất lượng phát hiện: các rule đều `synthetic_only`; không có tỷ lệ TP/FP/FN, không có số liệu hiệu năng (CPU/RAM trên VM 2 GB chưa đo).
- Khả năng phát hiện malware thật.

## 5. Tái tạo

```bash
python -m pytest -q
python scripts/acceptance/run_acceptance.py
```

## Kết quả trên Windows (2026-11-23)

Windows 10 (Python 3.14, múi giờ máy Asia/Bangkok), người test chạy `python -m pytest -q` lần đầu: 269 pass, 89 fail, 35 error, 13 skipped, 18 phút 5 giây. Nguyên nhân đã xác định từ log: thiếu `tzdata` (DuckDB không đọc được TIMESTAMPTZ; khoảng 94 ca), tệp chính sách đọc không chỉ định mã hóa trong test, `stdout` của `validator_poc.py` không in được tiếng Việt qua ống dẫn, thu hồi token phụ thuộc mtime thô, test ghi đè `SystemRoot`/tạo symlink/dò cờ CLI không chạy được trên Windows. Đã sửa trên Linux (412 pass); chưa chạy lại trên Windows.

**Lần chạy 2 trên Windows (2026-11-23, sau khi thêm `tzdata` và sửa):** 382 pass, 12 fail, 14 skipped, 4 phút 59 giây (lần 1: 18 phút). Toàn bộ lỗi múi giờ đã hết, xác nhận nguyên nhân là thiếu `tzdata`. 12 ca còn lại: `--help` của `edr_ctl`, `agent`, `core`, `pipeline.retention`, `static_scorer` bị `UnicodeEncodeError` khi stdout là ống dẫn (cp1252) và một test ghi tệp chính sách thiếu `encoding`. Đã sửa trên Linux (419 pass, 1 skipped): `common/console.py::force_utf8_stdio` gọi ở đầu `main()` của 7 CLI; chưa chạy lại trên Windows.

**Lần chạy 3 trên Windows (2026-11-23):** 401 pass, 14 skipped, 0 fail, 12 phút 13 giây. Bộ test tự động không còn lỗi trên Windows. Agent live (bước 8.1) vẫn FAIL, xem `EDR_PROGRESS.md` dòng 2026-11-23; các sửa cho agent live chưa chạy lại trên Windows.

**Bước 5–10 trên Windows (2026-11-24, sau sửa agent live):** agent live đọc được Sysmon thật (9.099 sự kiện, không lỗi; một `EventRecordID` đối chiếu khớp `wevtutil`), C-006 khi không có quyền (mã thoát 1), kill/khởi động lại và `edr_ctl stop` sạch. Script lab (bước 10) lỗi encoding trên PowerShell 5.1, đã sửa (BOM), chưa chạy lại. Chi tiết: `EDR_PROGRESS.md` dòng 2026-11-24.
