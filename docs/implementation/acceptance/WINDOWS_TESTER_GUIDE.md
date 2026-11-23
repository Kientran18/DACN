# Hướng dẫn kiểm thử DACN EDR trên Windows 10 VM (dành cho người test)

> Tài liệu này dành cho người được nhờ chạy thử hệ thống trên máy ảo. Bạn **không cần hiểu code**: làm lần lượt từng bước, chạy đúng lệnh, ghi lại kết quả và chụp ảnh theo mục "Cần thu thập" của từng bước, rồi gửi lại.
> Hệ thống là một EDR thử nghiệm (đồ án). **Chưa từng được chạy trên Windows thật**, nên rất có thể một số bước sẽ lỗi. Lỗi là kết quả có giá trị: **đừng cố sửa, hãy ghi lại và gửi**.

## 0. Quy tắc an toàn (bắt buộc)

1. Chỉ chạy trên **máy ảo (VM) dùng để thử**, tuyệt đối không chạy trên máy cá nhân hay máy làm việc.
2. **Chụp snapshot tên `clean`** ngay sau khi cài xong Windows (trước mọi bước dưới đây). Có sự cố thì quay về snapshot này.
3. **Không tắt Windows Defender.** Nếu Defender chặn hoặc xóa tệp, đó là kết quả cần ghi lại, không phải lỗi.
4. Không dùng mã độc thật. Các kịch bản trong tài liệu này chỉ tạo hoạt động vô hại có gắn nhãn `DACN_LAB`.
5. Không chạy bước 11 (response thật) nếu người nhờ test chưa nói rõ là làm.
6. **Che thông tin cá nhân trước khi gửi:** tên máy, tên người dùng Windows, tên miền, địa chỉ email, và **token** (chuỗi dài hiện ra một lần ở bước 5). Chụp ảnh xong thì tô đen các phần đó. Không gửi token qua tin nhắn.
7. Nếu một bước lỗi: **dừng bước đó**, chụp màn hình lỗi, lưu toàn bộ đầu ra, ghi số bước, rồi làm tiếp bước kế tiếp nếu bước kế không phụ thuộc. Ghi vào bảng kết quả (mục 13).

## 1. Yêu cầu máy ảo

| Mục | Yêu cầu |
|---|---|
| Hệ điều hành | Windows 10 64-bit |
| RAM | Tối thiểu 2 GB chạy được thử; **khuyến nghị 3–4 GB nếu nâng được** |
| CPU / ổ đĩa | 2 CPU, trống ≥ 20 GB |
| Mạng | Cần internet để tải Python, Git, Sysmon, thư viện |
| Giờ hệ thống | Đúng giờ (kiểm tra đồng hồ) |
| Phần mềm | Python 3.11 trở lên (tick "Add python.exe to PATH"), Git, Sysmon (Sysinternals) |

Nếu chỉ có 2 GB RAM: đóng mọi ứng dụng khác, chỉ mở một trình duyệt. Nếu VM đơ hoặc có tiến trình bị Windows kết thúc, **ghi lại thời điểm và hiện tượng** (đó là một kết quả đo hợp lệ).

## 2. Chuẩn bị thư mục kết quả và ghi lại toàn bộ phiên làm việc

Mở **PowerShell** (không cần Administrator, trừ khi bước ghi chú). Tạo thư mục chứa mọi thứ cần gửi:

```powershell
mkdir C:\dacn_results
Start-Transcript -Path C:\dacn_results\transcript_buoc02.txt
```

`Start-Transcript` ghi lại mọi lệnh và đầu ra vào tệp. **Mỗi lần mở cửa sổ PowerShell mới** hãy chạy lại lệnh này với tên tệp khác (ví dụ `transcript_buoc06.txt`). Khi xong cửa sổ đó, gõ `Stop-Transcript`.

Chụp ảnh bằng `Win + Shift + S` rồi lưu vào `C:\dacn_results\anh\` với tên theo mẫu `B<số bước>_<mô tả>.png` (ví dụ `B04_sysmon_service.png`).

Ghi lại thông tin phiên bản (cần chụp hoặc dán đầu ra):

```powershell
Get-ComputerInfo | Select WindowsProductName, WindowsVersion, OsBuildNumber, OsArchitecture, CsTotalPhysicalMemory
python --version
git --version
```

**Cần thu thập:** ảnh hoặc `transcript_buoc02.txt` có đầu ra trên (che tên máy nếu có).

## 3. Lấy mã nguồn và cài thư viện

```powershell
git clone https://github.com/Kientran18/DACN.git C:\DACN
cd C:\DACN
git checkout claude_implement
git log --oneline -1
python -m venv C:\dacn_venv
Set-ExecutionPolicy -Scope Process -ExecutionPolicy Bypass
C:\dacn_venv\Scripts\Activate.ps1
pip install -r requirements.txt
pip freeze > C:\dacn_results\pip_freeze.txt
$env:PYTHONPATH = "C:\DACN\src;C:\DACN\src\pipeline;C:\DACN\poc\sysmon-collector"
```

Lưu ý: `$env:PYTHONPATH` phải đặt lại **mỗi lần mở cửa sổ PowerShell mới** (và phải `Activate.ps1` lại venv).

**Kết quả mong đợi:** `pip install` kết thúc không có chữ đỏ `ERROR`, kể cả thư viện `pywin32`.
**Cần thu thập:**
- Ảnh `B03_pip_install_xong.png`: phần cuối đầu ra của `pip install` (dòng "Successfully installed ...") hoặc ảnh lỗi nếu có.
- Tệp `C:\dacn_results\pip_freeze.txt`.
- Dòng `git log --oneline -1` (mã commit đang test).

## 4. Chạy toàn bộ bộ test tự động của dự án trên Windows

```powershell
cd C:\DACN
python -m pytest -q 2>&1 | Tee-Object C:\dacn_results\pytest_windows.txt
```

Mất vài phút. Một số test tự bỏ qua (skipped) nếu thiếu `node` hoặc `lightgbm`, đó là bình thường.
**Cần thu thập:**
- Tệp `C:\dacn_results\pytest_windows.txt` (đầy đủ).
- Ảnh `B04_pytest_tong_ket.png`: dòng cuối dạng `N passed, M skipped, K failed`. Nếu có `failed`, chụp thêm danh sách `FAILED ...` ở cuối.

## 5. Kiểm tra môi trường (chỉ đọc, không đổi cấu hình)

Chạy **hai lần**: một lần trong PowerShell thường, một lần trong PowerShell mở bằng **Run as administrator** (nhớ `Activate.ps1`, đặt lại `PYTHONPATH`, `cd C:\DACN`).

```powershell
python scripts\windows\verify_windows_env.py --out C:\dacn_results\verify_report_user.json
```
Rồi trong cửa sổ Administrator:
```powershell
python scripts\windows\verify_windows_env.py --out C:\dacn_results\verify_report_admin.json
```
**Cần thu thập:** hai tệp `verify_report_user.json` và `verify_report_admin.json`; ảnh `B05_verify_admin.png` đầu ra cuối của lần Administrator.

## 6. Cài Sysmon (Administrator)

Tải Sysmon từ trang Sysinternals của Microsoft, giải nén vào `C:\Sysmon`. Trong PowerShell **Administrator**:

```powershell
C:\Sysmon\Sysmon64.exe -accepteula -i C:\DACN\poc\sysmon-collector\configs\sysmon-config.xml
Get-Service Sysmon64
Get-WinEvent -LogName "Microsoft-Windows-Sysmon/Operational" -MaxEvents 3
notepad.exe
```
Đóng Notepad, rồi:
```powershell
Get-WinEvent -LogName "Microsoft-Windows-Sysmon/Operational" -MaxEvents 5 | Format-List TimeCreated, Id
```
**Kết quả mong đợi:** `Get-Service` hiện `Running`; có sự kiện mới `Id: 1` lúc mở Notepad.
**Cần thu thập:** ảnh `B06_sysmon_service.png` (service Running) và `B06_sysmon_events.png` (danh sách sự kiện). Nếu `-i` báo lỗi cấu hình, chụp ảnh lỗi và ghi lại.

## 7. Tạo cấu hình và token, rồi chạy thử bằng dữ liệu mẫu (chưa cần Sysmon)

```powershell
mkdir C:\dacn_edr
copy C:\DACN\config\edr.example.yaml C:\dacn_edr\edr.yaml
python -m api.auth --config C:\dacn_edr\edr.yaml --role analyst --actor tester_a
python -m api.auth --config C:\dacn_edr\edr.yaml --role approver --actor tester_b
```
Hai lệnh cuối in ra **token** (chỉ hiện một lần). **Chép vào ghi chú riêng của bạn, KHÔNG gửi, KHÔNG để lộ trong ảnh.**

Chạy thử bằng một tệp mẫu:
```powershell
python -m edr_ctl start --config C:\dacn_edr\edr.yaml --agent-input C:\DACN\references\samples\raw\raw_process_create_event1.xml
python -m edr_ctl status --config C:\dacn_edr\edr.yaml
```
Mở trình duyệt vào `http://127.0.0.1:8765/ui/`, dán token analyst. Xem trang Tổng quan (Overview). Dữ liệu mẫu có thể hiện nhãn "DỮ LIỆU MẪU", đó là đúng.
Dừng:
```powershell
python -m edr_ctl stop --config C:\dacn_edr\edr.yaml
```
**Kết quả mong đợi:** `status` hiện `running`; Dashboard mở được và báo agent/core hoạt động; `stop` dừng sạch.
**Cần thu thập:**
- Ảnh `B07_status.png`: đầu ra `edr_ctl status` (che tên máy nếu có).
- Ảnh `B07_dashboard_overview.png`: trang Overview (che token nếu có hiện ra).
- Ảnh `B07_stop.png`: đầu ra `edr_ctl stop`.
- Thư mục log: copy `C:\dacn_edr\logs\` vào `C:\dacn_results\logs_b07\`.

## 8. Agent đọc Event Log thật (live) — AT-03, AT-04, AT-05

### 8.1. AT-03: sự kiện thật khớp với bản export của Windows
```powershell
python -m edr_ctl start --config C:\dacn_edr\edr.yaml --live
```
Mở Notepad rồi đóng. Đợi khoảng 10 giây, rồi:
```powershell
wevtutil qe Microsoft-Windows-Sysmon/Operational /c:5 /rd:true /f:xml > C:\dacn_results\sysmon_export.xml
dir C:\dacn_edr\bronze
python -m edr_ctl status --config C:\dacn_edr\edr.yaml
```
Mở một tệp `*.jsonl` trong `C:\dacn_edr\bronze\` bằng Notepad, tìm `EventRecordID` và so với `sysmon_export.xml`. **Mong đợi:** có `EventRecordID` trùng nhau và nội dung `raw_xml` giống.
**Cần thu thập:** `sysmon_export.xml`; ảnh `B08_bronze_dir.png` (danh sách tệp trong `bronze`); ảnh `B08_so_khop.png` (hai cửa sổ cạnh nhau, cùng một EventRecordID); `C:\dacn_edr\agent\health.json` (copy vào kết quả).

### 8.2. AT-04: không đủ quyền đọc Event Log
Dừng hệ thống (`python -m edr_ctl stop --config C:\dacn_edr\edr.yaml`). Mở **PowerShell thường (không Administrator)** (activate venv, đặt PYTHONPATH):
```powershell
cd C:\DACN
python -m agent run --config C:\dacn_edr\edr.yaml --live
echo "Ma thoat: $LASTEXITCODE"
type C:\dacn_edr\bronze\errors\collector_errors.jsonl
type C:\dacn_edr\agent\health.json
```
**Mong đợi:** lỗi mã `C-006`, agent không treo âm thầm, mã thoát khác 0, `health.json` ở trạng thái lỗi. Nếu tài khoản của bạn vẫn đọc được log (ví dụ thuộc nhóm Event Log Readers), ghi rõ "đọc được, không tái hiện được C-006".
**Cần thu thập:** ảnh `B08_c006.png` (đầu ra gồm mã thoát và nội dung hai tệp trên).

### 8.3. AT-05: tắt đột ngột rồi khởi động lại
Mở PowerShell Administrator (hoặc thường, theo bước 8.1) và chạy:
```powershell
python -m edr_ctl start --config C:\dacn_edr\edr.yaml --live
python -m edr_ctl status --config C:\dacn_edr\edr.yaml
```
Chép PID của `agent`, rồi:
```powershell
tasklist | findstr python
taskkill /F /T /PID <pid_agent>
tasklist | findstr python
python -m edr_ctl start --config C:\dacn_edr\edr.yaml --live
python -m edr_ctl status --config C:\dacn_edr\edr.yaml
dir C:\dacn_edr\bronze
```
**Mong đợi:** sau `taskkill` không còn `python.exe` của agent; khi khởi động lại, agent chạy tiếp và không có tệp `.part` mồ côi bất thường.
**Cần thu thập:** ảnh `B08_tasklist_truoc_sau.png` (hai lần `tasklist`, kể cả có hai `python.exe` cho một thành phần hay không); ảnh `B08_sau_restart.png`; thư mục `C:\dacn_edr\bronze\` (liệt kê `dir` trước và sau).

## 9. Dừng sạch, không để lại tiến trình (AT-34)

```powershell
tasklist | findstr python
python -m edr_ctl stop --config C:\dacn_edr\edr.yaml
tasklist | findstr python
```
Nếu `stop` báo `STILL-RUNNING`, **ghi lại nguyên văn** rồi mới thử `python -m edr_ctl stop --config C:\dacn_edr\edr.yaml --force`.
**Mong đợi:** sau `stop` không còn `python.exe` của hệ thống.
**Cần thu thập:** ảnh `B09_stop.png` (ba lệnh trên, cùng đầu ra).

## 10. Kịch bản mô phỏng an toàn (AT-16, AT-38, AT-39)

> Đọc nhanh tệp `C:\DACN\scripts\lab\dacn_lab_scenarios.ps1` trước (script chỉ ghi trong `%TEMP%\dacn_lab\` và khóa `HKCU\Software\EDR_PoC`, không tải mạng, không tắt Defender). **Khôi phục snapshot `clean` nếu muốn chạy lại từ đầu.**

Khởi động hệ thống live (xem bước 8.1) rồi chạy:

```powershell
cd C:\DACN
powershell -ExecutionPolicy Bypass -File .\scripts\lab\dacn_lab_scenarios.ps1 -WhatIf
powershell -ExecutionPolicy Bypass -File .\scripts\lab\dacn_lab_scenarios.ps1
powershell -ExecutionPolicy Bypass -File .\scripts\lab\dacn_lab_scenarios.ps1 -Scenario SC04
```
Ghi lại **giờ UTC** lúc bắt đầu (`(Get-Date).ToUniversalTime()`). Chờ khoảng 30 giây, mở Dashboard (`http://127.0.0.1:8765/ui/`) và xem các mục Alerts, Detections, Điều tra (bằng chứng) cho từng alert.
Sau đó dừng hệ thống rồi đối chiếu (làm việc trên **bản sao** của Silver):
```powershell
python -m edr_ctl stop --config C:\dacn_edr\edr.yaml
copy C:\dacn_edr\silver\endpoint_silver.duckdb C:\dacn_results\silver_copy.duckdb
dir $env:TEMP\dacn_lab
python tests\e2e\compare_expected.py --manifest $env:TEMP\dacn_lab\lab_run_<runid>.json --silver C:\dacn_results\silver_copy.duckdb --bronze C:\dacn_edr\bronze --ioc $env:TEMP\dacn_lab\ioc_candidate_<runid>.yaml --out C:\dacn_results\so_sanh.md
```
(thay `<runid>` bằng tên thật trong thư mục; bỏ `--ioc` nếu không có tệp `ioc_candidate_*.yaml` vì chưa chạy SC04.)

**Với mỗi kịch bản SC01–SC07, điền vào bảng mục 13 cột "Ai phát hiện"**: `EDR` (có alert trên Dashboard) / `Defender` (Windows Security có thông báo) / `Cả hai` / `Không ai`. Để biết Defender, mở Windows Security → Virus & threat protection → Protection history ngay sau khi chạy.
**Cần thu thập:**
- Ảnh `B10_whatif.png`: đầu ra của `-WhatIf`.
- Ảnh `B10_chay_that.png`: đầu ra khi chạy thật (có giờ UTC).
- Ảnh `B10_dashboard_alerts.png`: danh sách Alerts; và một ảnh `B10_alert_chi_tiet_<mã>.png` cho mỗi alert (bằng chứng, process tree/timeline nếu có).
- Ảnh `B10_defender_history.png`: Protection history của Windows Security (đã che tên).
- Tệp `so_sanh.md`, `lab_run_<runid>.json`, và thư mục `C:\dacn_edr\logs\`.

## 11. (CHỈ KHI người nhờ test yêu cầu rõ) Response thật — AT-25, AT-26, AT-37

Chỉ làm trên **tiến trình và tệp do kịch bản tạo trong `%TEMP%\dacn_lab`**. Quay về snapshot `clean` nếu có gì bất thường.

1. Mở `C:\DACN\config\response-policy.yaml`, đổi `mode: execute` và `execute_unlocked: true`. **Phải ghi lại** việc này trong bảng kết quả.
2. Tạo token vai trò responder và đặt biến **trước** khi khởi động hệ thống (thiếu biến này responder không chạy):
   ```powershell
   python -m api.auth --config C:\dacn_edr\edr.yaml --role responder --actor tester_r
   $env:EDR_RESPONDER_TOKEN = "<token vừa tạo>"
   python -m edr_ctl start --config C:\dacn_edr\edr.yaml --live
   ```
3. Chạy một tiến trình thử nghiệm sống lâu trong `%TEMP%\dacn_lab` (ví dụ sao chép `ping.exe` vào đó rồi chạy lặp tới localhost) và dùng Dashboard (mục Response Actions): yêu cầu terminate bằng token analyst, duyệt bằng token approver (người duyệt phải khác người yêu cầu).
4. Quarantine một tệp thử nghiệm trong `%TEMP%\dacn_lab`, rồi restore; so SHA-256 trước/sau: `Get-FileHash <tệp>`.
5. Thử **yêu cầu dừng một tiến trình hệ thống** (ví dụ `explorer.exe`): **kỳ vọng bị từ chối**. Chụp ảnh.
6. Xong: đặt lại `mode: dry_run` và `execute_unlocked: false`, rồi `edr_ctl stop`.

**Cần thu thập:** ảnh `B11_yeu_cau_duyet.png`, `B11_task_manager_truoc_sau.png` (tiến trình biến mất), `B11_audit.png` (nhật ký audit trên Dashboard), `B11_hash_truoc_sau.png` (hai giá trị SHA-256), `B11_tu_choi_tien_trinh_he_thong.png`.

## 12. Đo mức dùng RAM (quan trọng nếu VM chỉ có 2 GB)

Khi hệ thống đang chạy ổn định (sau bước 8.1) và một lần nữa lúc đang chạy kịch bản (bước 10):
```powershell
Get-Process python | Select Id, @{n='WS_MB';e={[int]($_.WorkingSet64/1MB)}}
Get-CimInstance Win32_OperatingSystem | Select @{n='Free_MB';e={[int]($_.FreePhysicalMemory/1KB)}}, @{n='Total_MB';e={[int]($_.TotalVisibleMemorySize/1KB)}}
```
**Cần thu thập:** hai ảnh `B12_ram_ranh.png`, `B12_ram_dang_chay_kich_ban.png`, kèm ghi chú: RAM của VM, có app nào khác đang mở không.

## 13. Bảng kết quả (điền và gửi lại)

Sao chép bảng này vào một tệp văn bản và điền. `PASS` chỉ khi có ảnh/tệp bằng chứng; không làm được thì ghi `NOT RUN`; sai/lỗi thì `FAIL` kèm mô tả.

| Bước | Nội dung | Kết quả (PASS/FAIL/NOT RUN) | Ghi chú / mã lỗi | Tệp/ảnh bằng chứng |
|---|---|---|---|---|
| 3 | Cài thư viện | | | pip_freeze.txt |
| 4 | pytest trên Windows | | N passed / M skipped / K failed | pytest_windows.txt |
| 5 | verify_windows_env (user, admin) | | | verify_report_*.json |
| 6 | Cài Sysmon | | | B06_* |
| 7 | Chạy thử với dữ liệu mẫu | | | B07_* |
| 8.1 | AT-03 live khớp wevtutil | | | B08_* |
| 8.2 | AT-04 lỗi C-006 | | | B08_c006 |
| 8.3 | AT-05 kill và phục hồi | | | B08_* |
| 9 | AT-34 dừng sạch | | | B09_stop |
| 10 | SC01 (PowerShell mã hóa vô hại) | | Ai phát hiện: | |
| 10 | SC02 (Run key vô hại) | | Ai phát hiện: | |
| 10 | SC03 (drop, execute, delete) | | Ai phát hiện: | |
| 10 | SC04 (tệp tự biên dịch, hash IOC) | | Ai phát hiện: | |
| 10 | SC06 (lành tính, kỳ vọng không alert) | | Ai phát hiện: | |
| 10 | SC07 (thiếu telemetry) | | Ai phát hiện: | |
| 11 | Response thật (nếu được yêu cầu) | | | B11_* |
| 12 | RAM đo được | | RAM VM: … | B12_* |

Ghi thêm: phiên bản Windows (từ bước 2), thời điểm bắt đầu/kết thúc (UTC), và **mọi hiện tượng lạ** (VM đơ, chậm, bị Defender chặn, tiến trình biến mất…).

## 14. Danh sách cuối: những gì cần gửi lại

Nén thư mục `C:\dacn_results` (loại bỏ mọi token, kiểm tra lại các ảnh đã che tên máy/tên người dùng) và gửi:

- [ ] `transcript_*.txt` (các phiên PowerShell)
- [ ] `pip_freeze.txt`, `pytest_windows.txt`
- [ ] `verify_report_user.json`, `verify_report_admin.json`
- [ ] `sysmon_export.xml`, `health.json`, một tệp Bronze `.jsonl` mẫu (cắt vài dòng nếu quá lớn)
- [ ] `so_sanh.md`, `lab_run_<runid>.json`
- [ ] Thư mục `logs_*` (từ `C:\dacn_edr\logs\`)
- [ ] Toàn bộ ảnh trong `anh\` theo mẫu tên `B<số bước>_...`
- [ ] Bảng kết quả mục 13 đã điền
- [ ] Ghi chú về RAM, thời gian chạy và các điều bất thường

Cảm ơn bạn đã test. Hệ thống đang ở giai đoạn thử nghiệm, nên mọi lỗi bạn gặp đều giúp ích.
