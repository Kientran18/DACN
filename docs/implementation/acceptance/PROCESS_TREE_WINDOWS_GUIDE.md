# Hướng dẫn chạy màn hình Cây tiến trình trên Windows 10 VM

> **Trạng thái (2026-11-26):** màn hình `#/tree` và API `/investigation/*` mới chỉ được kiểm thử trên Linux bằng dữ liệu synthetic (`python -m pytest -q`: 539 pass, 1 skipped). **Chưa chạy trên Windows.** Phần A đã được chạy thử trên Linux bằng `edr_ctl` với cùng tệp synthetic; các con số "mong đợi" ở phần A lấy từ lần chạy đó. Phần B (Sysmon live) chưa ai chạy nên chỉ mô tả hành vi dự kiến. Lỗi gặp phải là kết quả có giá trị: **ghi lại và gửi, đừng tự sửa code.**
>
> Màn hình chỉ đọc: không có nút response, điểm rủi ro không kích hoạt response. Hướng dẫn này **không** chạy response thật, không tắt Defender, không dùng mã độc.

## 0. An toàn và quyền riêng tư

1. Chỉ chạy trên VM lab có snapshot `clean` (xem `WINDOWS_TESTER_GUIDE.md` mục 0).
2. Ảnh chụp màn hình cây tiến trình **chứa hostname, tên người dùng Windows, đường dẫn hồ sơ và command line**. Tô đen các phần đó trước khi gửi. Không gửi token.
3. Ảnh chụp ở phần A là **dữ liệu synthetic**: đặt tên tệp có chữ `SYNTHETIC` (ví dụ `PT_A03_tree_SYNTHETIC.png`). `edr_ctl` không bật biểu ngữ "DỮ LIỆU MẪU", nên tên tệp là nơi duy nhất ghi nhãn này.

## 1. Chuẩn bị (một lần)

Yêu cầu: đã làm xong các bước 3 và 6 của `WINDOWS_TESTER_GUIDE.md` (mã nguồn ở `C:\DACN`, venv `C:\dacn_venv`, Sysmon đã áp cấu hình của repo).

Mở PowerShell, activate venv, cập nhật mã nguồn:

```powershell
Set-ExecutionPolicy -Scope Process -ExecutionPolicy Bypass
C:\dacn_venv\Scripts\Activate.ps1
cd C:\DACN
git pull
git log --oneline -1        # phải là commit 89fe5d6 "feat(dashboard): thêm màn hình cây tiến trình..." hoặc mới hơn
pip install -r requirements.txt
$env:PYTHONPATH = "C:\DACN\src;C:\DACN\src\pipeline;C:\DACN\poc\sysmon-collector"
```

Nếu hệ thống đang chạy từ lần trước: `python -m edr_ctl stop --config C:\dacn_edr\edr.yaml`. Phần A và phần B dùng chung cổng `8765`, nên mỗi lúc chỉ chạy một phần.

(Tùy chọn) Chạy riêng các test của tính năng trên Windows, rồi gửi lại đầu ra:

```powershell
python -m pytest -q tests\alerts\test_process_view.py tests\api\test_investigation_api.py *> C:\dacn_results\pytest_process_tree.txt
```

Mong đợi trên Linux: 26 pass. Test Playwright (`tests\dashboard`) sẽ tự bỏ qua nếu VM không có `node` và `playwright`.

## 2. Phần A — dữ liệu synthetic (không cần Sysmon)

Mục đích: kiểm tra giao diện trên Windows (trình duyệt, đường dẫn, mã hóa ký tự) bằng dữ liệu đã biết trước kết quả. Dùng **thư mục dữ liệu riêng** `C:\dacn_syn` để dữ liệu synthetic không lẫn với dữ liệu Sysmon thật trong `C:\dacn_edr`.

### A1. Tạo cấu hình, token và tệp sự kiện synthetic

```powershell
mkdir C:\dacn_syn
@"
home: C:\dacn_syn
api:
  host: 127.0.0.1
  port: 8765
  tokens_file: C:\dacn_syn\api_tokens.json
"@ | Set-Content -Encoding UTF8 C:\dacn_syn\edr.yaml

python -c "import sys; sys.path.insert(0, r'C:\DACN\tests\e2e'); import scenario_xml as sx; open(r'C:\dacn_syn\events.xml', 'w', encoding='utf-8').write('\n'.join(sx.full_scenario()))"

Stop-Transcript     # nếu đang ghi transcript: token sẽ bị ghi vào tệp
python -m api.auth --config C:\dacn_syn\edr.yaml --role analyst --actor tester_a
python -m api.auth --config C:\dacn_syn\edr.yaml --role viewer --actor tester_v
```

Hai lệnh `api.auth` in token **một lần**: chép vào ghi chú riêng, không gửi.

`events.xml` gồm 8 sự kiện Sysmon giả do `tests\e2e\scenario_xml.py` sinh ra (host `LAB-HOST`, người dùng `LABUSER`): PowerShell `-EncodedCommand` vô hại, ghi Run key, tạo/xóa tệp trong `dacn_lab`, PowerShell lành tính, Event 1 thiếu CommandLine, và một tệp có hash IOC.

### A2. Chạy

```powershell
python -m edr_ctl start --config C:\dacn_syn\edr.yaml --agent-input C:\dacn_syn\events.xml
Start-Sleep -Seconds 15
python -m edr_ctl status --config C:\dacn_syn\edr.yaml
```

Mở `http://127.0.0.1:8765/ui/` và dán token **analyst**.

### A3. Kiểm tra trên giao diện

| Mã | Thao tác | Mong đợi (theo lần chạy trên Linux 2026-11-26) |
|---|---|---|
| PT-A01 | Thanh điều hướng | Có mục **Cây tiến trình** |
| PT-A02 | Bấm **Cây tiến trình** khi chưa nhập gì | Thông báo "Nhập Host + process_guid…" (trạng thái rỗng) |
| PT-A03 | Trang **Alerts** → mở alert `DACN-DET-001` → bấm **Mở màn hình cây tiến trình** | Cây có **2 nút**: nút trên cùng viền nét đứt, nhãn `NO_DATA`, dòng "ParentImage theo Event 1 của tiến trình con: C:\Windows\explorer.exe"; nút trọng tâm `powershell.exe` (viền đậm, dấu ▶) có badge `DACN-DET-001 · medium` và badge rủi ro. Có badge `PARTIAL_ANCESTRY` và liên kết "← Quay lại alert" |
| PT-A04 | Xem panel bên phải của nút powershell | Có command line `-EncodedCommand AAAA…`, user, integrity `Medium`, `file_sha256`, thời điểm bắt đầu theo UTC, "không có Event 5 trong Silver"; bảng alert có liên kết **chi tiết & raw_xml →**; bảng sự kiện có 1 dòng `process` |
| PT-A05 | Bấm **chi tiết & raw_xml →**, rồi **Xem raw XML (ghi audit)** → **Đồng ý xem** | Hiện raw XML của sự kiện (token analyst). Đây là luồng bằng chứng có sẵn, không phải tính năng mới |
| PT-A06 | Quay lại cây, bấm nút `NO_DATA`, rồi **Đặt làm trọng tâm** | Panel ghi "Silver không có Event 1 của tiến trình này…", chỉ có ParentImage/ParentCommandLine/ParentProcessId lấy từ tiến trình con. Sau khi đặt làm trọng tâm: **6 nút** (nút `NO_DATA` và 5 tiến trình con: 3 `powershell.exe`, `DACN_LAB_x_whoami.exe`, `DACN_LAB_x_tool.exe`). Nút `NO_DATA` có badge `DACN-DET-003` và `DACN-DET-010`, cùng số sự kiện `file 2 · registry 1` |
| PT-A07 | **Chi tiết rủi ro** trên một nút có alert | Modal giải thích các thành phần, ghi "heuristic chưa hiệu chỉnh", "không kích hoạt response". Trên Linux: nút `NO_DATA` là `critical · 89`, powershell DET-001 là `low · 25`; con số có thể khác nếu cấu hình rủi ro khác |
| PT-A08 | Ô tìm kiếm: **Image chứa** = `powershell` → **Xem** | Bảng **3 dòng** (một dòng có command line trống "—"). Bấm một dòng để mở cây của tiến trình đó |
| PT-A09 | Ô tìm kiếm: **process_guid** = `00000000-0000-0000-0000-000000000099`, **Host** = `LAB-HOST` | Thông báo "Không tìm thấy tiến trình …" |
| PT-A10 | Đăng xuất, đăng nhập bằng token **viewer**, mở lại cây ở PT-A03 | Cây và panel vẫn hiện. Trong chi tiết alert, nút **Xem raw XML** bị vô hiệu ("vai trò không đủ quyền") |
| PT-A11 | Thu nhỏ cửa sổ trình duyệt còn khoảng 400 px chiều ngang | Cây và panel xếp chồng một cột, không có thanh cuộn ngang |
| PT-A12 | Trên mọi trang cây | Không có nút nào gửi response (không có Duyệt / Gửi yêu cầu / Terminate) |

Ghi chú về dữ liệu synthetic: ở PT-A06, nút `NO_DATA` hiện ParentImage `explorer.exe`, trong khi alert của nó ghi image `cmd.exe`/`reg.exe`. Lý do là bộ sinh synthetic dùng chung một GUID giả làm tác nhân cho nhiều sự kiện. Với Sysmon thật, một ProcessGuid không có nhiều image như vậy.

### A4. Dừng phần A

```powershell
python -m edr_ctl stop --config C:\dacn_syn\edr.yaml
```

(Xóa dữ liệu synthetic khi không cần: `Remove-Item -Recurse -Force C:\dacn_syn`.)

## 3. Phần B — Sysmon live (cần Administrator)

Mục đích: xem cây của tiến trình thật do bạn tự tạo bằng các lệnh **lành tính**. Phần này chưa từng chạy, nên kết quả dưới đây là dự kiến.

### B1. Chạy hệ thống live

Mở PowerShell **Administrator** (activate venv, đặt `PYTHONPATH` như mục 1):

```powershell
python -m edr_ctl start --config C:\dacn_edr\edr.yaml --live
python -m edr_ctl status --config C:\dacn_edr\edr.yaml
```

Nếu chưa có `C:\dacn_edr\edr.yaml` hoặc token, làm theo bước 7 của `WINDOWS_TESTER_GUIDE.md`.

### B2. Tạo một chuỗi tiến trình lành tính

Trong **một cửa sổ PowerShell thường khác** (không cần Administrator), chạy một lệnh duy nhất:

```powershell
cmd.exe /c "echo dacn_tree> %TEMP%\dacn_tree_test.txt & whoami & reg add HKCU\Software\EDR_PoC /v dacn_tree /d test /f & curl.exe -s -o NUL https://example.com & del %TEMP%\dacn_tree_test.txt & reg delete HKCU\Software\EDR_PoC /v dacn_tree /f"
```

Lệnh này tạo rồi xóa một tệp trong `%TEMP%`, chạy `whoami`, ghi rồi xóa một giá trị trong khóa thử nghiệm `HKCU\Software\EDR_PoC` (khóa PoC có sẵn trong cấu hình Sysmon của repo), và tải trang `example.com` một lần. Không thay đổi gì lâu dài. Ghi lại giờ chạy (UTC: `(Get-Date).ToUniversalTime()`).

Đợi khoảng 15–30 giây để agent niêm phong segment Bronze và core nạp vào Silver. Nếu chưa thấy dữ liệu, đợi thêm: ngưỡng niêm phong segment của agent là tối đa 300 giây.

### B3. Kiểm tra trên giao diện

| Mã | Thao tác | Mong đợi (dự kiến, chưa kiểm chứng) |
|---|---|---|
| PT-B01 | **Cây tiến trình** → **Image chứa** = `whoami` → **Xem** | Có ít nhất một dòng `C:\Windows\System32\whoami.exe` vào giờ bạn chạy B2 |
| PT-B02 | Bấm dòng mới nhất | Trọng tâm `whoami.exe`. Tổ tiên: `cmd.exe` → `powershell.exe` → `explorer.exe` → … Chuỗi thường dừng ở một nút `NO_DATA` (ví dụ `userinit.exe` hoặc tiến trình khởi động trước khi agent bắt đầu đọc log), hoặc là `FULL` nếu lần ngược được tới tiến trình hệ thống. **Ghi lại chuỗi bạn thấy** |
| PT-B03 | Bấm nút `cmd.exe` → **Đặt làm trọng tâm** | Các tiến trình con: `whoami.exe`, `reg.exe` (2 lần), `curl.exe`. Panel của `cmd.exe` có sự kiện `file` (Event 11 tạo `dacn_tree_test.txt`; Event 26 khi xóa nếu Sysmon ghi nhận) |
| PT-B04 | Bấm nút `reg.exe` | Sự kiện `registry` có `HKU\…\Software\EDR_PoC\dacn_tree` (Event 13; Event 12 khi xóa) |
| PT-B05 | Bấm nút `curl.exe` | Sự kiện `dns` (`example.com`) và `network` (đích cổng 443). Nếu VM không có internet, ghi "không có mạng" thay vì FAIL |
| PT-B06 | Đối chiếu với Event Viewer | Mở Event Viewer → Applications and Services Logs → Microsoft → Windows → Sysmon → Operational, tìm Event 1 của `whoami.exe` vào giờ B2. `ProcessGuid`, `ParentProcessGuid`, `CommandLine`, `IntegrityLevel` phải khớp panel. Nút tổ tiên `NO_DATA` phải khớp `ParentImage` của Event 1 tiến trình con |
| PT-B07 | Đếm thời gian | Ghi lại thời gian từ lúc bấm **Xem** đến khi cây hiện. Nếu quá 5 giây, ghi lại số sự kiện của hệ thống (trang Tổng quan → Pipeline). Đây chỉ là quan sát thủ công, không phải phép đo hiệu năng |
| PT-B08 | (Tùy chọn) Có alert thật | B2 không kỳ vọng tạo alert (`EDR_PoC` không phải khóa Run). Nếu `C:\dacn_edr` còn dữ liệu từ lượt Atomic Red Team hoặc kịch bản lab SC01–SC03, mở một alert DET-001 hoặc DET-003 → **Mở màn hình cây tiến trình** và kiểm tra badge alert, rủi ro, liên kết bằng chứng như PT-A03 đến PT-A07. Kịch bản lab do người test tự chạy theo `scripts\lab\README.md`, không phải bước bắt buộc của hướng dẫn này |

### B4. Dừng phần B

```powershell
python -m edr_ctl stop --config C:\dacn_edr\edr.yaml
```

## 4. Lỗi thường gặp

| Hiện tượng | Kiểm tra |
|---|---|
| Thanh điều hướng không có "Cây tiến trình" | `git log --oneline -1` chưa tới commit `89fe5d6`; hoặc trình duyệt dùng bản cache (`Ctrl+F5`) |
| `Lỗi: E-FORBIDDEN` | Token vai trò `responder` không có quyền đọc dữ liệu; dùng viewer, analyst hoặc approver |
| `Lỗi: E-VALIDATION` khi tìm | Image phải có ít nhất 2 ký tự; SHA-256 phải đủ 64 ký tự hex |
| Core dừng ngay khi start (phần A) | Xem `python -m edr_ctl logs --config C:\dacn_syn\edr.yaml --name core`; gửi đầu ra |
| Phần B không thấy tiến trình vừa chạy | `edr_ctl status`: agent `running`? `events_written` có tăng? Đợi segment niêm phong (≤ 300 s) |
| Tiếng Việt hiện ký tự lạ trong PowerShell | Xem tệp bằng `Get-Content -Encoding UTF8` (xem `EDR_INSTALL_GUIDE.md`, mục Giới hạn) |

## 5. Bảng kết quả (điền và gửi lại)

`PASS` chỉ khi có ảnh hoặc tệp làm bằng chứng; không làm được thì `NOT RUN`; sai hoặc lỗi thì `FAIL` kèm mô tả.

| Mã | Kết quả | Ghi chú | Ảnh/tệp |
|---|---|---|---|
| pytest tính năng | | N passed / M skipped / K failed | `pytest_process_tree.txt` |
| PT-A01 … PT-A12 | | | `PT_A*_SYNTHETIC.png` |
| PT-B01 … PT-B08 | | chuỗi tổ tiên quan sát được; có mạng không | `PT_B*.png` (đã che tên máy/người dùng) |

Ghi thêm: phiên bản Windows, trình duyệt và phiên bản, giờ bắt đầu và kết thúc (UTC), và mọi hiện tượng lạ (chậm, đơ, Defender chặn).
