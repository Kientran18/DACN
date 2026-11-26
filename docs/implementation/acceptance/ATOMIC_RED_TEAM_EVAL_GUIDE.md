# Đánh giá phát hiện bằng Atomic Red Team trên Windows 10 VM

> **Trạng thái: ĐỀ XUẤT, chưa chạy.** Tài liệu hướng dẫn người vận hành chạy một tập atomic test an toàn trên **một** Windows 10 VM
> và đối chiếu với kết quả phát hiện của DACN. Chưa có số liệu TP/FN nào; mọi con số chỉ được ghi sau khi chạy thật.
> Claude không chạy Atomic Red Team, script lab hay response thật; người vận hành chạy trên VM rồi gửi báo cáo đã che định danh.

## 1. Nguyên tắc

- Một VM lab có snapshot. **Không tắt Windows Defender**, không thêm exclusion. Test bị chặn ghi là "Defender chặn", không tìm cách né.
- Không tải mã độc hay payload: chỉ tải các tệp YAML trong `atomics/<technique>/<technique>.yaml`, ghim theo commit (mục 3).
- Response của DACN giữ `dry_run`. Điểm ML/điểm rủi ro không kích hoạt response.
- Mỗi test: chạy, chờ, rồi `-Cleanup`. Invoke-AtomicTest **không ghi log cho bước Cleanup**, nên phải cách lần chạy một khoảng.
- Không gửi log thô của Invoke-AtomicRedTeam: log Attire/CSV chứa hostname, username, IP, PATH và stdout.
  Chỉ gửi báo cáo do `tests/e2e/atomic_compare.py` sinh ra (công cụ đã bỏ các trường đó), sau khi tự kiểm tra lại.

## 2. Tập test và kỳ vọng

Nguồn sự thật: `tests/e2e/atomic_expected.yaml` (đề xuất, chờ Cyber duyệt). Tóm tắt:

| ID | Technique | Atomic | Quyền | Kỳ vọng | Lý do chính |
|---|---|---|---|---|---|
| C01 | T1082 | systeminfo | user | Đối chứng: không MATCH | lành tính |
| C02 | T1059.003 | echo/type | user | Đối chứng: không MATCH | DET-002 cần cha Office |
| A01 | T1059.001 | PowerShell `-e` (chỉ Write-Host) | user | DET-001 MATCH | ` -e ` trong command line; AMSI có thể chặn |
| A02 | T1059.001 | Fileless Script Execution | user | DET-001 MATCH | `FromBase64String`, `iex` trong command line |
| A03 | T1059.001 | Known Malicious Cmdlets (hàm giả) | admin | FN dự kiến (thiếu telemetry) | cần PowerShell 4104 |
| A04 | T1547.001 | Reg Key Run (HKCU) | user | DET-003 MATCH | Event 13 khóa Run |
| A05 | T1547.001 | SystemBC Registry (HKCU Run) | user | DET-003 MATCH | Event 13 khóa Run |
| A06 | T1547.001 | RunOnceEx (HKLM) | admin | DET-003 MATCH (từ v2) | v1 không nhận RunOnceEx (đo lần 1) |
| A07 | T1547.001 | Policies\Explorer\Run | admin | DET-003 MATCH (từ v3) | cần cấu hình Sysmon mới; v2 chưa gồm (đo lần 2) |
| A08 | T1053.005 | SCHTASKS /Create | user | DET-004 MATCH | |
| A09 | T1053.005 | Task base64 từ registry | user | DET-004 MATCH | |
| A10 | T1053.005 | Register-ScheduledTask | admin | FN dự kiến (chưa có rule) | không qua schtasks.exe |
| A11 | T1070.004 | Xóa một tệp | user | FN dự kiến (chưa có rule) | DET-010 cần đủ chuỗi; cần `-GetPrereqs` |

Không có atomic an toàn tương ứng: DET-002 (cần Office, NOT RUN), DET-010 và DET-101 (dùng SC03/SC04 của `scripts/lab/`).
Executor `powershell` của Invoke-AtomicRedTeam chạy `powershell.exe "& {<lệnh atomic>}"`, nên nội dung atomic nằm trong
CommandLine của Event 1. AMSI chặn script không ngăn Event 1, nên DET-001 có thể MATCH cả khi Defender đã chặn.

## 3. Chuẩn bị (chặng 1)

Windows PowerShell 5.1, **Run as Administrator**. Snapshot `dacn-ready-pre-art` trước.

```powershell
Set-ExecutionPolicy -Scope Process -ExecutionPolicy Bypass -Force
[Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12
Install-PackageProvider -Name NuGet -MinimumVersion 2.8.5.201 -Scope CurrentUser -Force
Install-Module -Name powershell-yaml, invoke-atomicredteam -Scope CurrentUser -Force
Import-Module invoke-atomicredteam -Force
Get-Module invoke-atomicredteam, powershell-yaml | Select-Object Name, Version
```

Chỉ tải YAML, ghim commit `a0e3f9bc69fed2fd711bd1f1aa87a40c33482fe6`, kiểm tra SHA-256:

```powershell
$commit = "a0e3f9bc69fed2fd711bd1f1aa87a40c33482fe6"
$want = @{
 "T1059.001"="54ebdbccfd6d5435a52bb048b3e8b9de541d8f0bd6c86f97ff982a15f1a76945"
 "T1059.003"="284489b27b8b125aae855da4555daeabb99bb2f8ba4a298fcb0aaf97859bf833"
 "T1547.001"="d5a38b78011ec61c7a1ded7f52b8896f67f4e3488da83291214be721d3533bd2"
 "T1053.005"="4e21312a2b23bf4b5945ef2e4b71c7e470b50b71b121bd8faddf8239c44411de"
 "T1070.004"="534149f33c0bb85caa1bf2b1185109a87925bef66228aa27c6ef6ca3ff8f8183"
 "T1082"    ="227c971954b4da7bcac0ebc5b6e04644298bc7aa62a5a56df96c0904c0eb3e06" }
foreach ($t in $want.Keys) {
  $d = "C:\AtomicRedTeam\atomics\$t"; New-Item -ItemType Directory $d -Force | Out-Null
  Invoke-WebRequest "https://raw.githubusercontent.com/redcanaryco/atomic-red-team/$commit/atomics/$t/$t.yaml" -OutFile "$d\$t.yaml" -UseBasicParsing
  $h = (Get-FileHash "$d\$t.yaml" -Algorithm SHA256).Hash.ToLower()
  "{0,-10} {1}" -f $t, $(if ($h -eq $want[$t]) {"OK"} else {"SAI HASH: $h"})
}
```

Xem chi tiết và kiểm tra tiền điều kiện (chỉ đọc) bằng bảng `$tests` ở mục 4, với `-ShowDetailsBrief` và `-CheckPrereqs`.
Snapshot `art-ready` khi mọi YAML đều OK.

## 4. Chạy đánh giá (chặng 3)

### 4.1. Cửa sổ A - DACN (Administrator)

```powershell
Set-ExecutionPolicy -Scope Process -ExecutionPolicy Bypass -Force
C:\dacn_venv\Scripts\Activate.ps1
cd C:\DACN
git pull --ff-only origin claude_implement          # lấy atomic_compare.py và atomic_expected.yaml
$env:PYTHONPATH = "C:\DACN\src;C:\DACN\src\pipeline;C:\DACN\poc\sysmon-collector"
python -m edr_ctl start --config C:\dacn_edr\edr.yaml --live
python -m edr_ctl status --config C:\dacn_edr\edr.yaml
```

Ghi lại thời điểm bắt đầu (UTC) để lọc cảnh báo Defender: `$since = Get-Date; $since.ToUniversalTime().ToString("o")`.

### 4.2. Cửa sổ B - Atomic Red Team (Administrator)

Dán khối sau (chỉ ký tự ASCII, tránh lỗi encoding của PowerShell 5.1):

```powershell
Set-ExecutionPolicy -Scope Process -ExecutionPolicy Bypass -Force
Import-Module invoke-atomicredteam -Force
$LOG = "C:\dacn_art\logs"; New-Item -ItemType Directory $LOG -Force | Out-Null
$since = Get-Date
$tests = @(
 @("C01","T1082","66703791-c902-4560-8770-42b8a91f7667"), @("C02","T1059.003","127b4afe-2346-4192-815c-69042bec570e"),
 @("A01","T1059.001","a538de64-1c74-46ed-aa60-b995ed302598"), @("A02","T1059.001","fa050f5e-bc75-4230-af73-b6fd7852cd73"),
 @("A03","T1059.001","49eb9404-5e0f-4031-a179-b40f7be385e3"), @("A04","T1547.001","e55be3fd-3521-4610-9d1a-e210e42dcf05"),
 @("A05","T1547.001","9dc7767b-30c1-4cc4-b999-50cab5e27891"), @("A06","T1547.001","554cbd88-cde1-4b56-8168-0be552eed9eb"),
 @("A07","T1547.001","a70faea1-e206-4f6f-8d9a-67379be8f6f1"), @("A08","T1053.005","42f53695-ad4a-4546-abb6-7d837f644a71"),
 @("A09","T1053.005","e895677d-4f06-49ab-91b6-ae3742d0a2ba"), @("A10","T1053.005","af9fd58f-c4ac-4bf2-a9ba-224b71ff25fd"),
 @("A11","T1070.004","861ea0b4-708a-4d17-848d-186c9c7f17e3") )
function Run-One($x) {
  $id, $tech, $guid = $x
  Write-Host ("==== {0} {1} start {2}" -f $id, $tech, (Get-Date).ToUniversalTime().ToString("o")) -ForegroundColor Cyan
  if ($id -eq "A11") { Invoke-AtomicTest $tech -TestGuids $guid -GetPrereqs }
  $stamp = (Get-Date).ToUniversalTime().ToString("yyyyMMddTHHmmssZ")
  Invoke-AtomicTest $tech -TestGuids $guid -LoggingModule "Attire-ExecutionLogger" -ExecutionLogPath "$LOG\$id-$stamp.json"
  Start-Sleep -Seconds 60
  Invoke-AtomicTest $tech -TestGuids $guid -Cleanup
  Start-Sleep -Seconds 10
}
```

Mỗi lần chạy ghi một tệp riêng `<ID>-<thời điểm UTC>.json`: Invoke-AtomicRedTeam 2.3.0 (PSGallery) **ghi đè** tệp Attire đã có
thay vì nối thêm (mã nguồn nhánh master mới hơn thì nối), nên dùng chung tên tệp sẽ mất log của lần chạy trước.
Executor và tên trường Attire của 2.3.0 giống bản đã dùng để viết `atomic_compare.py` (đối chiếu mã nguồn ngày 2026-11-26).

Chạy **từng test một** và quan sát (khuyến nghị cho lần đầu):

```powershell
Run-One $tests[0]      # C01; tiếp theo $tests[1] ... $tests[12]
```

Sau mỗi test, xem Defender có phản ứng không (không in đường dẫn hay tên người dùng):

```powershell
Get-MpThreatDetection | Where-Object { $_.InitialDetectionTime -gt $since } |
  Select-Object InitialDetectionTime, ThreatID, ActionSuccess
Get-MpThreat | Select-Object ThreatID, ThreatName
```

Ghi vào `ATOMIC_RED_TEAM_RESULTS_TEMPLATE.md` (bản sao): Defender có/không, ThreatName, cleanup có lỗi không.
Muốn chạy hết một lượt sau khi đã quen: `foreach ($x in $tests) { Run-One $x }` (khoảng 16 phút).

### 4.3. Thu kết quả

1. Agent chỉ niêm phong segment Bronze khi đủ 5000 bản ghi, 8 MB, hoặc segment đã mở 300 giây (kiểm tra khi có bản ghi mới), và khi dừng; core chỉ nạp segment đã niêm phong. Phiên ngắn hơn 5 phút thì segment chỉ được niêm phong lúc dừng và core không kịp nạp (quan sát lần 3, 2026-11-26). Vì vậy **luôn chạy công cụ với `--bronze`** (bước 3): công cụ nạp các segment còn thiếu vào bản sao Silver. Báo cáo ghi phạm vi thời gian của Silver và cảnh báo lần chạy nằm sau dữ liệu cuối. Tùy chọn: mở `http://127.0.0.1:8765/ui/` xem danh sách alert
   (nếu chụp ảnh, che hostname/username).
2. Dừng hệ thống ở cửa sổ A: `python -m edr_ctl stop --config C:\dacn_edr\edr.yaml`.
3. Đối chiếu (công cụ tự làm trên bản sao Silver, không sửa DB gốc):

```powershell
New-Item -ItemType Directory C:\dacn_results -Force | Out-Null
python tests\e2e\atomic_compare.py --silver C:\dacn_edr\silver\endpoint_silver.duckdb --bronze C:\dacn_edr\bronze `
  --logs C:\dacn_art\logs --out C:\dacn_results\atomic_report.md --json C:\dacn_results\atomic_report.json
Get-Content -Encoding UTF8 C:\dacn_results\atomic_report.md
```

4. Khôi phục snapshot `art-ready` nếu muốn chạy lại từ trạng thái sạch.

### 4.4. Gửi lại

- `atomic_report.md` (đã kiểm tra không có hostname/username/IP) và bảng Defender đã điền.
- Lỗi hoặc cảnh báo khi chạy (dán văn bản, che định danh).
- Không gửi `C:\dacn_art\logs\*.json`, `api_tokens.json` hay ảnh có định danh.

## 5. Cách công cụ phân loại

`atomic_compare.py` tìm Event 1 có `pid` bằng `process-id` trong log Attire, trong cửa sổ `[time-start - 5s, time-stop + 5s]`
(CSV mặc định không có `time-stop`: dùng `start + 125s`), lấy cây con cháu qua `parent_guid`, gom event Silver của cây đó và giao với
`contributing_event_ids` của `_detection_results`.

| Kết luận | Nghĩa |
|---|---|
| TP | TP_EXPECTED và rule mục tiêu MATCH trên cây tiến trình |
| FN | TP_EXPECTED nhưng rule mục tiêu không MATCH |
| FN_DU_KIEN | FN_NO_RULE/FN_NO_TELEMETRY và đúng là không có MATCH (khoảng trống đã biết) |
| MATCH_NGOAI_DU_KIEN | kỳ vọng FN nhưng có rule MATCH: cần xem lại kỳ vọng |
| TN / FP | đối chứng không có / có MATCH |
| KHONG_THAY_TIEN_TRINH_GOC | log có pid nhưng không thấy Event 1 khớp pid và thời điểm (mất telemetry hoặc core chưa nạp) |
| KHONG_KHOI_TAO_DUOC | log không có pid: Invoke-AtomicTest không tạo được tiến trình (ví dụ `Process.Start` báo "Access is denied" khi Defender chặn). Không tính TP/FN |

Exit code khác 0 và cờ "gợi ý Defender" (stderr có thông điệp kiểu AMSI) được báo riêng; kết luận Defender do người vận hành xác nhận.
Giới hạn: không gán được tiến trình do dịch vụ khởi tạo (Task Scheduler, WMI) vì chúng không là con cháu của tiến trình gốc;
Event 12/13 do `svchost.exe` ghi vào `TaskCache` không được tính cho test. Cỡ mẫu là số lần chạy trên một VM; không suy rộng.

## 6. Chạy lại sau khi sửa DET-003 v2 và cấu hình Sysmon (2026-11-26)

Thay đổi đã duyệt: DET-003 v2 nhận RunOnceEx; cấu hình Sysmon thêm `\Policies\Explorer\Run`. Chỉ cần chạy lại A06, A07 và hai đối chứng.

1. Cửa sổ A: `git pull --ff-only origin claude_implement`, rồi áp cấu hình Sysmon mới (Administrator):
   ```powershell
   C:\Windows\Sysmon64.exe -c C:\DACN\poc\sysmon-collector\configs\sysmon-config.xml
   ((C:\Windows\Sysmon64.exe -c | Out-String) -replace "`0", "") -split "`n" | Select-String "Policies|CurrentVersion\\Run"
   ```
   Lệnh thứ hai phải in ra cả `\CurrentVersion\Run` và `\Policies\Explorer\Run`. Không dùng thẳng `Sysmon64.exe -c | Select-String`:
   phần liệt kê rule trong output có ký tự NUL nên Select-String không khớp (quan sát trên VM, Sysmon v15.22, 2026-11-26). Sau đó `edr_ctl start --live` như mục 4.1.
2. Cửa sổ B: dán khối mục 4.2, rồi `Run-One $tests[0]`, `Run-One $tests[1]`, `Run-One $tests[7]` (A06), `Run-One $tests[8]` (A07).
3. Dừng core, chạy `atomic_compare.py` với `--logs` trỏ tới **thư mục mới** (hoặc chỉ các tệp của lần này) để không lẫn lần 1, ví dụ
   chuyển log cũ sang `C:\dacn_art\logs_run1` trước khi chạy.

Lưu ý: DET-003 đổi `rule_version` nên engine đánh giá lại toàn bộ Event 13 đã có; các alert DET-003 v1 cũ có thể xuất hiện thêm bản v2.

## 7. Chạy lại A07 sau DET-003 v3

Cấu hình Sysmon đã áp ở mục 6 thì không cần áp lại. `git pull`, start DACN, dán khối mục 4.2, chạy `Run-One $tests[8]` (A07),
dừng core rồi chạy `atomic_compare.py` với thư mục log mới (chuyển log lần 2 sang `C:\dacn_art\logs_run2` trước).
Kỳ vọng: A07 là TP với DACN-DET-003. DET-003 đổi `rule_version` lên 3 nên engine đánh giá lại Event 13 cũ một lần.
