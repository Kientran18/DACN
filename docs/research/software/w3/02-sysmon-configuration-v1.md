# Sysmon Configuration v1

**File cấu hình:** `configs/sysmon/sysmon-config.xml` · **Schema:** 4.90 (Sysmon 15.x) · **Trạng thái:** viết xong, **chưa cài thử trên máy thật**.

## 1. Thiết kế

Cấu hình phục vụ PoC: ưu tiên thấy được đủ 4 nhóm telemetry cho 13 kỹ thuật MITRE và DET-001 đến DET-010, **chưa tối ưu volume**. HashAlgorithms: `SHA256,IMPHASH`. `DnsLookup=False` để Sysmon không tự phân giải ngược IP (giảm tải, tránh sinh thêm DNS).

| Event | Rule v1 | Phục vụ | Rủi ro volume | Điểm còn mở |
|---|---|---|---|---|
| 1 ProcessCreate | exclude rỗng (ghi tất cả) | DET-001/002/003/004/005/009/010; T1059, T1218, T1053 | Trung bình–cao | Đo volume rồi mới thêm exclude (TR-07) |
| 5 ProcessTerminate | exclude rỗng | `end_time`, T1562.001 | Trung bình–cao | Như trên |
| 3 NetworkConnect | exclude loopback | DET-005/006; T1105, T1071.001 | Cao | Định dạng IPv6 loopback (`0:0:0:0:0:0:0:1`) cần xác nhận |
| 22 DnsQuery | exclude rỗng | DET-006; correlate với Event 3 | Cao | Thêm exclude khi cần |
| 11 FileCreate | include: `\Temp\`, `\Downloads\`, `\Desktop\`, `\AppData\Roaming\`, `\ProgramData\`, `\Users\Public\`, thư mục Startup | DET-005/010; T1204.002, T1105 | Trung bình | `\AppData\Roaming\` có thể ồn |
| 15 FileCreateStreamHash | include: `\Downloads\` và nội dung có `ZoneId=` | Mark-of-the-Web cho T1204.002 | Thấp | Cần file tải qua trình duyệt mới thấy |
| 26 FileDeleteDetected | include: `\Temp\`, `\Downloads\`, `\Desktop\` | DET-010, T1070.004 | Thấp | **Q-C2:** có chuyển Event 23 (có archive) cho thư mục nhạy cảm không |
| 29 FileExecutableDetected | include: `\Temp\`, `\Downloads\`, `\AppData\`, `\ProgramData\`, `\Users\Public\` | Hash của PE mới tạo (T1204.002, T1105) | Thấp–trung bình | Cần xác nhận Sysmon bản đang dùng có Event 29 |
| 12/13/14 RegistryEvent | include: `\CurrentVersion\Run*`, `\Winlogon\`, `\Image File Execution Options\`, `\Schedule\TaskCache\`, `\ImagePath` (cuối), `\Software\EDR_PoC` | DET-003/004, T1547.001, T1053.005 | Thấp–trung bình | **Q-C3:** danh sách key chờ Cyber chốt |
| 4, 16 | Luôn được ghi | DET-007, T1562.001 | Rất thấp | — |
| 7 ImageLoad, 23 FileDelete | **Chưa bật** | — | — | Chờ nhu cầu của Cyber; Event 23 tốn đĩa (TR-04) |

## 2. Điều cần xác minh khi cài thật

1. `Sysmon64.exe -s` chấp nhận `schemaversion="4.90"` và mọi tên phần tử trong config (đặc biệt `DnsLookup`, `FileExecutableDetected`).
2. Event 29 và 15 có xuất hiện trong thử nghiệm không (file 04, E8).
3. Giá trị `TargetObject` của HKCU (dự kiến dạng `HKU\<SID>\...`) có khớp rule `contains` không (file 05).
4. Số lượng sự kiện mỗi giờ khi máy nhàn rỗi (E9, file 09) để chốt exclude.

## 3. Quy trình thay đổi cấu hình

Nhánh `config/<mô-tả>` → sửa XML → thêm dòng CHANGELOG → Pull Request (theo `docs/06-sysmon-poc-config-storage.md` Week 1). Commit: `config(sysmon-config): <mô tả>`.

## 4. CHANGELOG

| Phiên bản | Ngày | Thay đổi | Lý do |
|---|---|---|---|
| 1.0 | (điền ngày) | Bản đầu cho PoC Issue #16 | Thu mẫu thật cho 4 nhóm telemetry |
| 1.1 | | (điền sau khi cài thử) | |
