# Windows Telemetry Lab Setup Notes

> **Cập nhật 2026-10-19:** Đã có mẫu thật và kết quả file mode; thông tin chưa chạy/chưa cài bên dưới là ghi chú lịch sử trước lần lab. Trạng thái hiện hành và đường dẫn tái lập ở [index](00-index-and-dod.md). Python live mode vẫn chưa có bằng chứng. Không diễn giải mọi lệnh hướng dẫn là đã thử thành công.


**Phạm vi:** VM Windows 10/11 dùng chung của team (xem `docs/05-windows-lab-environment.md` của Week 1). Mọi lệnh dưới đây **chưa được chạy thử**; ghi kết quả thật vào mục 9.

## 1. Chuẩn bị

| Hạng mục | Yêu cầu |
|---|---|
| VM | Windows 10/11 64-bit (ARM64 dùng `Sysmon64a.exe`), tối thiểu 4 GB RAM, 2 core |
| Snapshot | Chụp **"clean-before-sysmon"** trước khi cài bất cứ thứ gì |
| Quyền | Tài khoản Administrator để cài Sysmon và xuất log |
| Mạng | Ra được Internet (cho thử nghiệm network tới `example.com`) |
| Python | 3.11 (theo `data_pipeline_phase_1_scope.md`); `pywin32` cho chế độ live |
| Windows Defender | **Giữ bật.** Các script chỉ làm việc vô hại |
| Đồng hồ | Đồng bộ thời gian; Sysmon ghi `UtcTime` theo UTC |

## 2. Lấy Sysmon

1. Tải Sysmon từ trang Sysinternals của Microsoft Learn.
2. Kiểm tra chữ ký trước khi chạy:
```powershell
Get-AuthenticodeSignature .\Sysmon64.exe | Format-List Status, SignerCertificate
```
Chỉ tiếp tục nếu `Status` là `Valid` và người ký là Microsoft.
3. Ghi lại phiên bản (`(Get-Item .\Sysmon64.exe).VersionInfo.FileVersion`) vào mục 9. Cần ghim cùng một phiên bản cho cả team.

## 3. Kiểm tra cấu hình trước khi cài

```powershell
.\Sysmon64.exe -s        # in schema mà phiên bản này hỗ trợ; so với schemaversion="4.90" trong config
```
Nếu Sysmon báo lỗi cấu hình khi cài, sửa `configs/sysmon/sysmon-config.xml` theo thông báo rồi ghi vào CHANGELOG (file 02).

## 4. Cài đặt

```powershell
.\Sysmon64.exe -accepteula -i ..\configs\sysmon\sysmon-config.xml
Get-FileHash ..\configs\sysmon\sysmon-config.xml -Algorithm SHA256     # ghi hash vào mục 9
```
Cập nhật cấu hình sau này: `.\Sysmon64.exe -c sysmon-config.xml`. Xem cấu hình đang chạy: `.\Sysmon64.exe -c`. Gỡ: `.\Sysmon64.exe -u`.

## 5. Xác minh hoạt động

```powershell
Get-Service Sysmon64                                   # Status = Running
Get-WinEvent -LogName 'Microsoft-Windows-Sysmon/Operational' -MaxEvents 10 |
  Format-Table TimeCreated, Id, Message -AutoSize
wevtutil sl Microsoft-Windows-Sysmon/Operational /ms:268435456   # tăng kích thước channel lên 256 MB (TR-01)
wevtutil gl Microsoft-Windows-Sysmon/Operational                 # kiểm tra maxSize
```
Kỳ vọng: có Event 4 (service started) và Event 16 (config change) ngay sau khi cài. Event Viewer: *Applications and Services Logs → Microsoft → Windows → Sysmon → Operational*.

## 6. Sinh hoạt động thử nghiệm

```powershell
powershell -ExecutionPolicy Bypass -File .\scripts\poc\run-poc-activities.ps1
# tùy chọn: -RunKeyTest (thử khóa Run, được xóa ngay)  -SkipNetwork
```
Script in ra `Marker for this run: EDR_POC_<timestamp>`; ghi lại marker này.

## 7. Xuất mẫu thô

```powershell
# PowerShell chạy bằng Administrator
.\scripts\poc\export-samples.ps1 -OutDir .\samples\raw -SinceMinutes 30 -Sanitize
```
Kết quả: một file XML cho mỗi loại sự kiện, `recent_events_all.xml` và `export_manifest.json` (có phiên bản Sysmon và Windows). `-Sanitize` thay SID, tên máy và tên người dùng bằng giá trị giả; hãy giữ một bản chưa che ngoài repo.

## 8. Điểm kiểm tra sau mỗi bước

| Bước | Sự kiện Sysmon cần thấy |
|---|---|
| Cài đặt | 4, 16 |
| 1. Process thường | 1 (`cmd.exe`, command line chứa marker), 5 |
| 2. Parent-child | 1 cho `cmd.exe`, `whoami.exe`, `hostname.exe`, `powershell.exe`; `ParentImage` đúng |
| 3. File | 11 (tạo, có thể cả ghi đè), 29 và 11 cho `_drop.exe`, 1 cho `_drop.exe` chạy từ Temp, 26 khi xóa |
| 4. Registry | 12 (CreateKey, DeleteKey), 13 (SetValue: chuỗi và DWORD) cho `\Software\EDR_PoC` |
| 5. Network | 22 (`example.com`), 3 (PowerShell, cổng 443) |

Nếu một loại không xuất hiện, ghi lại trong file 09 (đây cũng là kết quả hữu ích) rồi xem mục 10.

## 9. Ghi chép môi trường (điền sau khi cài)

| Mục | Giá trị |
|---|---|
| Ngày thực hiện / người thực hiện | 2026-10-18; người thực hiện cần nhóm xác nhận trong review |
| Windows build | 10.0.19045 (manifest) |
| Sysmon version | 15.22 (manifest) |
| Hash SHA256 của `sysmon-config.xml` | |
| Kích thước channel Sysmon | |
| Snapshot đã chụp | |
| Python / pywin32 version | Chưa có version trong evidence; không suy đoán từ lệnh hướng dẫn |

## 10. Xử lý sự cố

| Hiện tượng | Hướng xử lý |
|---|---|
| Cài đặt báo lỗi cấu hình | Chạy `Sysmon64.exe -s`, đối chiếu tên phần tử và `schemaversion`; xóa phần tử bị báo lỗi và ghi vào CHANGELOG |
| Không thấy sự kiện loại X | Kiểm tra rule có khớp không (đường dẫn thật, ví dụ `%TEMP%` có chứa `\Temp\`); xem `Sysmon64.exe -c` |
| `Get-WinEvent` báo access denied | Chạy PowerShell bằng Administrator |
| Quá nhiều sự kiện | Đếm theo ID: `Get-WinEvent -LogName 'Microsoft-Windows-Sysmon/Operational' | Group-Object Id | Sort-Object Count -Desc` rồi thu hẹp rule |
| Script bị chặn execution policy | Dùng `-ExecutionPolicy Bypass` cho riêng tiến trình đó |

## 11. Khôi phục

Quay về snapshot "clean-before-sysmon", hoặc gỡ bằng `Sysmon64.exe -u`. Xóa `%TEMP%\edr_poc` và khóa `HKCU\Software\EDR_PoC` nếu script dừng giữa chừng.
