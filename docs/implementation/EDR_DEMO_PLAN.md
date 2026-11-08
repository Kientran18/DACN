# EDR — Kế hoạch kiểm thử mô phỏng malware an toàn và Demo

> PROPOSAL (2026-11-08). Chưa kịch bản nào được viết hay chạy. **Claude không chạy các kịch bản này**; người dùng đọc, đồng ý và chạy trên VM lab. Không sử dụng malware thật; không tải mã độc từ Internet.

## 1. Ranh giới an toàn

- Chỉ trên **Windows 10 VM trong VirtualBox**, có **snapshot "clean"**, khôi phục sau mỗi lượt. Không chạy trên máy dùng hằng ngày hoặc máy của người khác.
- Không tắt Windows Defender, UAC, audit hay bất kỳ biện pháp bảo vệ nào để phục vụ demo. Nếu cần loại trừ một thư mục lab cho mục đích thử nghiệm (ví dụ EICAR), **người dùng tự quyết định và tự thực hiện trên VM**; Claude không thực hiện và không viết lệnh làm việc đó.
- Mọi kịch bản chỉ ghi trong `%TEMP%\dacn_lab\` và khóa `HKCU` thử nghiệm; mọi chuỗi kích hoạt chứa marker `DACN_LAB_<run_id>`; có tham số `-WhatIf`; có cleanup đầy đủ; không truy cập mạng ngoài; không duy trì quyền truy cập; không phá dữ liệu.
- Script phải được người dùng đọc từng dòng trước khi chạy (D-10). Hành động response thật chỉ nhắm tiến trình/tệp mang marker lab (D-12).
- Xem `docs/research/cyber/w4/03-detection-hunting-response-va-ke-hoach-test.md` mục 3 (quy trình Atomic Red Team an toàn đề xuất): nếu dùng Atomic Red Team, duyệt từng `atomic_test_guid`, xem YAML, executor, dependency và cleanup trước; không chạy cả technique.

## 2. Phân biệt nguồn phát hiện (ghi trong mọi kết quả)

| Nhãn | Ý nghĩa |
|---|---|
| `EDR` | Rule/IOC của EDR tạo `DetectionResult` và alert từ telemetry Sysmon thật |
| `DEFENDER` | Windows Defender phát hiện/chặn (xem Windows Security hoặc nhật ký Defender); EDR có thể vẫn ghi sự kiện |
| `BOTH` | Cả hai |
| `FIXTURE` | Chỉ chạy trên dữ liệu lưu sẵn, chưa xác minh trên endpoint |
| `NONE` | Không ai phát hiện (false negative trên tập này) |

Phân biệt thêm: **detection** (EDR phát hiện và cảnh báo), **prevention** (chặn trước khi thực thi — EDR MVP không làm; Defender có thể), **response sau phát hiện** (terminate/quarantine do EDR sau khi được duyệt).

## 3. Danh mục kịch bản

| ID | Tên | Hành vi mô phỏng (vô hại) | Telemetry kỳ vọng | Rule / kết quả kỳ vọng | MITRE (chỉ gán khi có căn cứ) |
|---|---|---|---|---|---|
| SC-01 | PowerShell mã hóa | `powershell.exe -NoProfile -ExecutionPolicy Bypass -EncodedCommand <base64 của lệnh in ra marker>` | Sysmon 1 (Image, CommandLine, ProcessGuid) | `DACN-DET-001` → `MATCH` | T1059.001 (theo danh sách 13 technique) |
| SC-02 | Persistence Run key | Ghi giá trị `DACN_LAB_<id>` vào `HKCU\...\CurrentVersion\Run` trỏ tới lệnh in marker; xóa ngay; **không khởi động lại** | Sysmon 13 (TargetObject, Details), 12 khi xóa | `DACN-DET-003` → `MATCH` | T1547.001 |
| SC-03 | Drop → execute → delete | Sao chép tệp thực thi vô hại đã ký (ví dụ `whoami.exe`) vào `%TEMP%\dacn_lab\`, chạy, xóa (đã có bước tương tự trong `run-poc-activities.ps1`) | Sysmon 11 → 1 → 26/23 | `DACN-DET-010` → `MATCH` khi đủ chuỗi | T1070.004 (một phần chuỗi) |
| SC-04 | IOC hash | Tệp thực thi **duy nhất do nhóm tự tạo** (ví dụ chương trình 1 dòng in chuỗi, tự biên dịch trên VM bằng công cụ có sẵn); SHA-256 nằm trong kho IOC của đội; chạy | Sysmon 1 (`Hashes` SHA256) / 29 | IOC match → `MATCH` | — (IOC của đội, không phải technique) |
| SC-05 | EICAR (tùy chọn, D-11) | Tạo tệp văn bản EICAR trong `%TEMP%\dacn_lab\` | Sysmon 11 (không có hash trong Event 11); hash cần bước băm tệp (P1) | Có thể chỉ `DEFENDER` phát hiện và xóa tệp; ghi nhận trung thực | — |
| SC-06 | Kiểm soát lành tính | `powershell -NoProfile -Command Get-Date`; tạo rồi xóa tệp trong Temp **không chạy**; ghi registry ngoài khóa Run | Sysmon 1, 11, 26, 13 | Không có alert đe dọa (`NO_MATCH`) | — |
| SC-07 | Thiếu telemetry | Xóa tệp ở vị trí **không** nằm trong `FileDeleteDetected include` của cấu hình Sysmon (sau khi đối chiếu cấu hình) | Có 11, 1; thiếu 26 | `DACN-DET-010` → `PENDING_LATE_EVENTS`/partial, không `MATCH` đầy đủ | — |
| SC-08 | Response thử nghiệm | Chạy tiến trình thử nghiệm sống lâu mang marker (bản sao tệp vô hại đã đổi tên, ví dụ ping vòng lặp tới localhost); sau cảnh báo, người vận hành **duyệt** terminate; và quarantine tệp drop của SC-03 rồi restore | Sysmon 1, 5 | Response: `dry_run` trước; `execute` chỉ khi người dùng bật; audit đủ | — |

Điều kiện bổ sung: các Event ID cần có trong `sysmon-config.xml` phải được đối chiếu trước (PH2-T08). Kịch bản nào phụ thuộc Event chưa bật → ghi `blocked`, không giả vờ chạy.

## 4. Quy trình chạy một kịch bản (người dùng)

1. Khôi phục snapshot clean; khởi động VM; xác nhận Sysmon chạy (`Get-Service Sysmon64`) và đồng hồ đúng.
2. `python -m edr_ctl start`; mở Dashboard; xác nhận Overview báo agent/pipeline/engine đang sống (heartbeat).
3. Ghi `run_id` và giờ UTC bắt đầu. Chạy script kịch bản với `-WhatIf` để xem dự kiến; đọc đầu ra.
4. Chạy thật. Quan sát Dashboard: sự kiện, `DetectionResult`, alert, bằng chứng.
5. (SC-08) Duyệt hoặc từ chối hành động response trên Dashboard; xác nhận kết quả bằng Task Manager / thư mục quarantine / nhật ký audit.
6. Chạy cleanup; `edr_ctl stop`; lưu Bronze/Silver/log; ghi bảng kết quả.
7. Khôi phục snapshot.

**Bảng ghi kết quả (mỗi lượt):** `run_id · kịch bản · giờ UTC · sự kiện Sysmon quan sát (EventRecordID) · DetectionResult thực tế · alert · nguồn phát hiện (EDR/DEFENDER/BOTH/FIXTURE/NONE) · response (dry_run/execute, kết quả) · PASS/FAIL · ghi chú`.

## 5. Kịch bản demo lặp lại (≈ 15 phút, đề xuất)

1. Giới thiệu kiến trúc và ranh giới an toàn (2 phút).
2. Khởi động hệ thống, Overview (1 phút).
3. SC-06 (lành tính): không có alert đe dọa (1 phút).
4. SC-01: alert PowerShell, mở bằng chứng nguồn đến `raw_xml` (3 phút).
5. SC-03: chuỗi drop→execute→delete, timeline + cây tiến trình (3 phút).
6. SC-08: duyệt terminate/quarantine ở `execute` (lab), xem audit và restore (3 phút).
7. SC-07: trình bày trung thực trường hợp thiếu telemetry (1 phút).
8. Tổng kết: phạm vi chứng minh và giới hạn (1 phút).

**Dự phòng:** nếu VM sự cố, dùng Bronze/Silver đã lưu từ lần chạy trước, **ghi rõ trên màn hình là dữ liệu lưu sẵn (`FIXTURE`)**.

## 6. Báo cáo kết quả phát hiện

- Chỉ nêu số lượt TP/FP/FN trên **các kịch bản đã chạy**, kèm cỡ mẫu và phiên bản rule/IOC; không nêu tỷ lệ phổ quát; không suy ra khả năng phát hiện malware ngoài thực tế.
- Tách thống kê theo nguồn phát hiện; trường hợp `DEFENDER` hoặc `FIXTURE` không tính là EDR phát hiện.
- Ghi các giới hạn: telemetry Sysmon không có file write/entropy (không chứng minh được phát hiện mã hóa tệp), DET-004/007/008 bị chặn, cửa sổ tương quan chưa hiệu chỉnh.

## 7. Dữ liệu cho huấn luyện (nhánh ML)

Các lượt chạy có marker `run_id` có thể làm dữ liệu có nhãn nội bộ, nhưng **marker không được dùng làm đặc trưng** (rò rỉ nhãn). Xem [AI_TRAINING_GUIDE.md](AI_TRAINING_GUIDE.md).
