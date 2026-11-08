# EDR — Kịch bản demo và diễn tập (PH11-T03)

> Trạng thái: **chưa diễn tập**. Claude không chạy được trên Windows; người dùng thực hiện trên VM lab. Kịch bản gốc và ranh giới an toàn: [EDR_DEMO_PLAN.md](../EDR_DEMO_PLAN.md). Cài đặt: [EDR_INSTALL_GUIDE.md](../EDR_INSTALL_GUIDE.md).

## 1. Chuẩn bị (trước giờ demo)

| Việc | Cách kiểm | Trạng thái |
|---|---|---|
| VM Windows 10 có snapshot `clean` | VirtualBox | _(người dùng)_ |
| `verify_windows_env.py` chạy xong, gửi `verify_report.json` | tệp báo cáo | _(người dùng)_ |
| Sysmon chạy; cấu hình đã đối chiếu với bảng Event ID của `scripts/lab/README.md` | `Get-Service Sysmon64` | _(người dùng)_ |
| Đọc từng dòng `scripts/lab/dacn_lab_scenarios.ps1`, chạy thử `-WhatIf` | đầu ra `-WhatIf` | _(người dùng)_ |
| Token API tạo bằng `python -m api.auth --config <edr.yaml> --role <vai trò> --actor <tên>` (không để trong repo) | `/me` trả đúng vai trò | _(người dùng)_ |
| Bản dự phòng dữ liệu lưu sẵn (xem mục 4) | thư mục `fallback/` | _(người dùng)_ |

## 2. Kịch bản (≈ 15 phút)

| # | Bước | Mong đợi (từ `tests/e2e/scenarios.yaml`) | Nói rõ khi trình bày |
|---|---|---|---|
| 1 | Giới thiệu kiến trúc, ranh giới an toàn (2') | — | Response mặc định `dry-run`; chỉ nhắm mục tiêu có marker lab |
| 2 | `edr_ctl start`, mở `/ui`, xem Overview (1') | agent/core sống | Số liệu là số đo, không phải số mẫu |
| 3 | SC-06 lành tính (1') | không có alert đe dọa | cỡ mẫu nhỏ |
| 4 | SC-01 PowerShell mã hóa (3') | alert DET-001; mở bằng chứng tới `raw_xml` | nguồn phát hiện: EDR/Defender/BOTH |
| 5 | SC-03 drop→execute→delete (3') | DET-010 MATCH; timeline + cây tiến trình | cửa sổ 300 s chưa hiệu chỉnh |
| 6 | SC-08 response: duyệt terminate/quarantine (3') | `dry_run` trước; `execute` chỉ khi người dùng tự bật; audit; restore | chỉ tiến trình/tệp lab |
| 7 | SC-07 thiếu telemetry (1') | `PENDING_LATE_EVENTS`/coverage gap, không báo giả | trung thực về giới hạn cấu hình Sysmon |
| 8 | Tổng kết phạm vi và giới hạn (1') | — | không suy ra tỷ lệ phát hiện phổ quát |

## 3. Diễn tập hai lần liên tiếp (AT-40)

Với mỗi lượt: khôi phục snapshot `clean` → chạy đủ mục 2 → lưu Bronze/Silver/log → điền bảng:

| Lượt | run_id | giờ UTC | SC | DetectionResult thực tế | alert | nguồn phát hiện | response | PASS/FAIL | ghi chú |
|---|---|---|---|---|---|---|---|---|---|
| 1 | | | | | | | | | |
| 2 | | | | | | | | | |

Có thể dùng `python tests/e2e/compare_expected.py --manifest <lab_manifest.json> --silver <silver.duckdb> [--bronze D] [--ioc F] [--out report.md]` để so với kỳ vọng; kết quả `NOT RUN` cho kịch bản chưa chạy là bình thường, không đổi thành PASS.

## 4. Phương án dự phòng (dữ liệu lưu sẵn)

- Nếu VM sự cố: chạy API trên dữ liệu từ lượt trước hoặc `python -m core --config <edr.yaml> --sample-data`; trên màn hình phải hiện nhãn **DỮ LIỆU MẪU / `FIXTURE`**, và người trình bày nói rõ đây không phải kết quả chạy trực tiếp.
- Dữ liệu `--sample-data` là synthetic của dự án, không phải telemetry thật.

## 5. Dọn dẹp

`edr_ctl stop` → script cleanup của kịch bản → khôi phục snapshot. Che tên máy/tên người dùng trong mọi ảnh chụp đính kèm báo cáo.
