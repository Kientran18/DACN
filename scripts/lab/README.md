# Kịch bản mô phỏng an toàn trên Windows 10 VM lab (PH5)

> **Trạng thái:** script và công cụ so sánh đã viết và kiểm tra trên Linux bằng dữ liệu SYNTHETIC. **Chưa chạy PowerShell trên máy thật.** Không có kết luận phát hiện nào được rút ra cho tới khi bạn chạy trên VM (PH5-T04).

## Quy tắc an toàn
- Chỉ chạy trên VM lab, **chụp snapshot "clean" trước khi chạy**; không chạy trên máy cá nhân.
- Script không tải mạng, không tắt Defender/Sysmon, không đổi chính sách, không khởi động lại, không xóa theo wildcard.
- Chỉ ghi `%TEMP%\dacn_lab\`, `%PUBLIC%\dacn_lab\`, giá trị Run `DACN_LAB_<runid>_SC02` (xóa ngay) và khóa `HKCU\Software\EDR_PoC`.
- **Đọc script trước, chạy `-WhatIf` trước.** Không chia sẻ thư mục `dacn_lab` công khai (đường dẫn có thể chứa tên người dùng).

## Các bước
```powershell
# 1. Xem sẽ làm gì mà không làm gì cả
powershell -ExecutionPolicy Bypass -File .\scripts\lab\dacn_lab_scenarios.ps1 -WhatIf
# 2. Chạy thật các kịch bản mặc định (SC01, SC02, SC03, SC06, SC07)
powershell -ExecutionPolicy Bypass -File .\scripts\lab\dacn_lab_scenarios.ps1
# 3. Tùy chọn: SC04 (tự biên dịch tệp thử nghiệm) / SC05 (EICAR, cần -Eicar)
powershell -ExecutionPolicy Bypass -File .\scripts\lab\dacn_lab_scenarios.ps1 -Scenario SC04
```
Sau đó: chạy agent live (PH2-T09) hoặc export `wevtutil` → Bronze → Silver, rồi:
```bash
python tests/e2e/compare_expected.py --manifest lab_run_<runid>.json --silver silver.duckdb --bronze <thư mục bronze> [--ioc ioc_candidate_<runid>.yaml] --out report.md
```
Cột "ai phát hiện" (EDR / Windows Defender / không ai) do người vận hành điền vào báo cáo.

## Danh mục kịch bản (đề xuất — chờ bạn/Cyber duyệt từng dòng)
| ID | Hành vi vô hại | Telemetry kỳ vọng | Kỳ vọng phát hiện | Cleanup |
|---|---|---|---|---|
| SC01 | `powershell -EncodedCommand` in marker | Event 1 | DACN-DET-001 `MATCH` | không có gì cần dọn |
| SC02 | Ghi/xóa giá trị Run `DACN_LAB_..._SC02` | Event 13 (12 khi xóa) | DACN-DET-003 `MATCH` | xóa ngay + dọn trong `finally` |
| SC03 | Copy `whoami.exe` vào Temp, chạy, xóa | Event 11 → 1 → 26 | DACN-DET-010 `MATCH` | xóa tệp |
| SC04 | Tệp C# tự biên dịch (hash duy nhất) | Event 1 (SHA256) | DACN-DET-101 `MATCH` khi nạp `ioc_candidate` | xóa tệp |
| SC05 | EICAR (tùy chọn) | Event 11 | chỉ quan sát (Defender có thể xóa) | xóa tệp |
| SC06 | Lành tính: `Get-Date`, tệp tạm không chạy, registry ngoài Run | Event 1, 11, 26, 13 | không rule nào có kết quả | xóa |
| SC07 | Drop+chạy ở `Users\Public`, xóa (không bị Sysmon theo dõi xóa) | Event 11, 1; **không** có 26 | DET-010 không `MATCH` đầy đủ | xóa tệp |

## Đối chiếu cấu hình Sysmon của repo với kịch bản (PH2-T08, đọc từ `sysmon-config.xml`; chưa áp dụng trên VM)
| Kịch bản | Event ID cần | Cấu hình repo bật? | Căn cứ |
|---|---|---|---|
| SC01, SC06, SC03/04/07 (chạy tiến trình) | 1, 5 | Có (log tất cả) | `ProcessCreate onmatch="exclude"` rỗng |
| SC03, SC07 (tạo tệp) | 11 | Có cho `\Temp\`, `\Users\Public\` | `FileCreate include` |
| SC03 (xóa) | 26 | Có cho `\Temp\` | `FileDeleteDetected include` |
| SC07 (xóa ở Public) | 26 | **Không** (chủ ý) | `\Users\Public\` không nằm trong `FileDeleteDetected` |
| SC02 | 13 | Có | `\CurrentVersion\Run` trong `RegistryEvent include` |
| SC04 | 1 + SHA256 | Có | `HashAlgorithms: SHA256,IMPHASH` |
| Mọi kịch bản | Event 23 | Không cấu hình (dùng 26) | quyết định Q-C2 còn mở |

## Rủi ro chưa kiểm chứng
- Đường dẫn dạng 8.3 (`USERNA~1`) hoặc `\Device\HarddiskVolumeN` có thể làm DET-010 trả `INSUFFICIENT_TELEMETRY` thay vì `MATCH`; chỉ biết sau khi chạy thật.
- Marker của SC01 nằm trong base64; công cụ so sánh tự giải mã UTF-16LE (đã kiểm trên dữ liệu synthetic).
- Defender có thể can thiệp ở SC04/SC05; ghi nhận trung thực, không tắt Defender.
