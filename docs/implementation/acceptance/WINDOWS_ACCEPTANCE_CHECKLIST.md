# Danh sách nghiệm thu trên Windows VM (người dùng chạy — PH11-T02)

> Sinh tự động từ `tests/acceptance/at_catalog.yaml`. Claude **không** chạy được các mục này. Người dùng chạy trên VM lab (snapshot `clean`), điền cột Actual/Status rồi gửi lại cùng đầu ra lệnh.
> Chỉ điền `PASS` khi có đầu ra/ảnh chụp làm bằng chứng. Che tên máy, tên người dùng trước khi gửi.
> Chạy trước: `python scripts/windows/verify_windows_env.py` và làm theo `EDR_INSTALL_GUIDE.md`.

## AT-03 · Agent live nhận sự kiện mới và khớp wevtutil export

- Preconditions: Windows 10 VM, Sysmon chạy, quyền đọc channel Sysmon/Operational
- Steps:
  1. $env:PYTHONPATH=...; python -m agent run --config C:\dacn_edr\edr.yaml --live --follow (hoặc edr_ctl start --live)
  2. Sinh sự kiện (mở notepad)
  3. wevtutil qe ... /f:xml so với raw_xml trong Bronze
- Expected: raw_xml trong Bronze trùng EventRecordID/nội dung với wevtutil
- Actual: _(điền)_
- Status: PASS / FAIL / NOT RUN _(chọn)_
- Evidence: _(lệnh, đầu ra, ảnh chụp đã che định danh)_
- Known limitations: Một VM, một phiên bản Sysmon

## AT-04 · Không có quyền đọc channel -> lỗi C-006 rõ ràng

- Preconditions: Windows, chạy agent bằng tài khoản không có quyền
- Steps:
  1. Chạy python -m agent run --config C:\dacn_edr\edr.yaml --live bằng user thường
  2. Xem tệp collector_errors.jsonl trong thư mục errors của Bronze (đường dẫn thực tế do agent ghi, kiểm bằng dir)
- Expected: Mã lỗi C-006, agent không crash âm thầm
- Actual: _(điền)_
- Status: PASS / FAIL / NOT RUN _(chọn)_
- Evidence: _(lệnh, đầu ra, ảnh chụp đã che định danh)_
- Known limitations: Phần logic ánh xạ lỗi đã có test Linux (test_access_denied_maps_to_c006) nhưng đó không phải bằng chứng trên Windows

## AT-05 · Kill agent giữa chừng trên Windows -> phục hồi

- Preconditions: Windows VM, agent live đang chạy
- Steps:
  1. taskkill /F /PID <pid của tiến trình agent> (lấy PID từ edr_ctl status)
  2. Khởi động lại
  3. Kiểm tra recover và không mất sự kiện
- Expected: recover_dir niêm phong .part, checkpoint tiếp tục
- Actual: _(điền)_
- Status: PASS / FAIL / NOT RUN _(chọn)_
- Evidence: _(lệnh, đầu ra, ảnh chụp đã che định danh)_
- Known limitations: —

## AT-16 · SC-01..SC-04 phát hiện trên VM, ghi nguồn phát hiện (EDR/Defender)

- Preconditions: VM lab, Sysmon, script lab đã được người dùng đọc
- Steps:
  1. Chạy dacn_lab_scenarios.ps1 SC01-SC04
  2. python tests/e2e/compare_expected.py
- Expected: Báo cáo so khớp scenarios.yaml
- Actual: _(điền)_
- Status: PASS / FAIL / NOT RUN _(chọn)_
- Evidence: _(lệnh, đầu ra, ảnh chụp đã che định danh)_
- Known limitations: Chỉ trên tập kịch bản đã chạy

## AT-25 · Terminate tiến trình thử nghiệm (marker lab) khi execute + audit

- Preconditions: VM, người dùng bật execute_unlocked và mode execute
- Steps:
  1. Chạy tiến trình thử nghiệm nằm trong thư mục lab (%TEMP%\dacn_lab; tên marker KHÔNG đủ)
  2. Yêu cầu và duyệt terminate (người duyệt khác người yêu cầu)
  3. Kiểm tra Task Manager và audit
- Expected: Tiến trình bị kết thúc; audit trước/sau đủ
- Actual: _(điền)_
- Status: PASS / FAIL / NOT RUN _(chọn)_
- Evidence: _(lệnh, đầu ra, ảnh chụp đã che định danh)_
- Known limitations: Chỉ tiến trình thử nghiệm

## AT-26 · Quarantine tệp thử nghiệm rồi restore, hash khớp

- Preconditions: VM, tệp trong thư mục lab
- Steps:
  1. Duyệt quarantine
  2. Restore
  3. So sha256
- Expected: Hash khớp, không ghi đè, không xóa vĩnh viễn
- Actual: _(điền)_
- Status: PASS / FAIL / NOT RUN _(chọn)_
- Evidence: _(lệnh, đầu ra, ảnh chụp đã che định danh)_
- Known limitations: Chỉ thư mục lab. Logic đã có test Linux (quarantine/restore) nhưng không thay cho Windows

## AT-33 · Dashboard trên VM hiển thị cảnh báo thật của SC-01

- Preconditions: Hệ thống chạy trên VM
- Steps:
  1. Chạy SC-01
  2. Mở /ui
- Expected: Alert DET-001 hiển thị với bằng chứng
- Actual: _(điền)_
- Status: PASS / FAIL / NOT RUN _(chọn)_
- Evidence: _(lệnh, đầu ra, ảnh chụp đã che định danh)_
- Known limitations: —

## AT-34 · edr_ctl start/status/stop khởi động/dừng sạch, không tiến trình mồ côi trên Windows

- Preconditions: Windows VM
- Steps:
  1. python -m edr_ctl start/status/stop --config C:\dacn_edr\edr.yaml (đã đặt $env:PYTHONPATH)
  2. Kiểm tra tasklist
- Expected: Không còn tiến trình mồ côi
- Actual: _(điền)_
- Status: PASS / FAIL / NOT RUN _(chọn)_
- Evidence: _(lệnh, đầu ra, ảnh chụp đã che định danh)_
- Known limitations: Đã có test Linux (tests/test_edr_ctl.py, tests/e2e/test_edr_ctl_real_processes.py) - không thay cho Windows

## AT-35 · Làm theo hướng dẫn cài từ VM sạch tới hệ thống chạy

- Preconditions: VM snapshot sạch
- Steps:
  1. Làm từng bước EDR_INSTALL_GUIDE.md
- Expected: Hệ thống chạy; ghi lại bước nào sai
- Actual: _(điền)_
- Status: PASS / FAIL / NOT RUN _(chọn)_
- Evidence: _(lệnh, đầu ra, ảnh chụp đã che định danh)_
- Known limitations: —

## AT-36 · Chuỗi đầy đủ SC-01 từ snapshot sạch

- Preconditions: VM snapshot sạch
- Steps:
  1. Theo EDR_DEMO_PLAN mục 4
- Expected: SC-01 -> alert -> bằng chứng -> dashboard
- Actual: _(điền)_
- Status: PASS / FAIL / NOT RUN _(chọn)_
- Evidence: _(lệnh, đầu ra, ảnh chụp đã che định danh)_
- Known limitations: —

## AT-37 · Chuỗi đầy đủ SC-03 -> alert -> duyệt response -> terminate/quarantine

- Preconditions: VM, execute bật bởi người dùng
- Steps:
  1. SC-03
  2. SC-08
- Expected: Alert, duyệt, thực thi, audit
- Actual: _(điền)_
- Status: PASS / FAIL / NOT RUN _(chọn)_
- Evidence: _(lệnh, đầu ra, ảnh chụp đã che định danh)_
- Known limitations: —

## AT-38 · Kiểm soát lành tính SC-06 không sinh alert đe dọa

- Preconditions: VM
- Steps:
  1. SC-06
- Expected: NO_MATCH
- Actual: _(điền)_
- Status: PASS / FAIL / NOT RUN _(chọn)_
- Evidence: _(lệnh, đầu ra, ảnh chụp đã che định danh)_
- Known limitations: Cỡ mẫu nhỏ

## AT-39 · Thiếu telemetry SC-07 -> INSUFFICIENT/PENDING, không báo giả

- Preconditions: VM
- Steps:
  1. SC-07
- Expected: PENDING_LATE_EVENTS hoặc INSUFFICIENT_TELEMETRY
- Actual: _(điền)_
- Status: PASS / FAIL / NOT RUN _(chọn)_
- Evidence: _(lệnh, đầu ra, ảnh chụp đã che định danh)_
- Known limitations: —

## AT-40 · Lặp lại demo lần 2 từ snapshot sạch cho kết quả tương đương

- Preconditions: VM
- Steps:
  1. Khôi phục snapshot
  2. Chạy lại demo
- Expected: Kết quả tương đương lần 1
- Actual: _(điền)_
- Status: PASS / FAIL / NOT RUN _(chọn)_
- Evidence: _(lệnh, đầu ra, ảnh chụp đã che định danh)_
- Known limitations: —
