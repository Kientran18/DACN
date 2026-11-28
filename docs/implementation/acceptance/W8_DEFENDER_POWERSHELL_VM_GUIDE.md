# Hướng dẫn hạng mục 11: kiểm thử kênh Windows Defender và PowerShell 4104 trên Windows 10 VM

> **Trạng thái (2026-11-28):** đã chạy một lượt trên một VM. Lượt đầu dừng ở V3 vì lỗi hiệu năng nạp (mục 12.10 của tài liệu đề
> xuất); sau bản sửa `208a713`, V1–V7 đạt, trừ phần bấm nút xem bản gốc trên dashboard ở V3 (mục 12.11).
> Mã nguồn tương ứng (hạng mục 1–9 và 4 của
> `docs/architecture/w8/telemetry-defender-powershell-proposal.md`) mới được kiểm thử trên Linux: nguồn giả, fixture synthetic và 28 sự
> kiện thật nạp ở file mode. Mọi chữ "Mong đợi" dưới đây là **dự kiến suy ra từ code**, chưa phải kết quả đo. Bước nào lỗi thì ghi
> lại đầu ra, gửi cho Claude và **đừng tự sửa code**. Lỗi cũng là kết quả có giá trị.
>
> Người dùng tự chạy mọi bước. Claude không chạy script PowerShell trên VM, không chạy response thật.

Mục tiêu (theo mục 6.3 và 6.4 của tài liệu đề xuất):

| Mã | Kiểm tra | Tiêu chí đạt |
|---|---|---|
| V1 | Agent live đọc ba kênh | `health.json` có ba kênh, không kênh nào `error`; có ba checkpoint riêng |
| V2 | 4104 lành tính, script block nhiều phần, PID của 4104 | Vào Silver đủ; block dài ghép đủ phần; nối tiến trình ra `UNIQUE` về `powershell.exe` |
| V3 | Che bí mật, DET-203, DET-204 | Alert không chứa script; `/script` che chuỗi giả; `reveal` chỉ cho analyst và có audit |
| V4 | EICAR qua SC05 | 1116 (có thể kèm 1117) → alert DET-201 nguồn Defender → truy vết được về `raw_xml` |
| V5 | Atomic A02, A03 | Ghi đúng quan sát. Không có 4104 do Defender chặn sớm thì **không** tính là FN của DET-203 |
| V6 | Dừng agent rồi chạy lại | Sự kiện phát sinh lúc agent dừng vẫn vào Silver sau khi chạy lại; ledger cân bằng |
| V7 | An toàn | Không bản ghi kênh mới nào mang `source: SYSMON`; không response nào được tạo tự động |

Không kiểm tra ở đây: một kênh thiếu quyền mà Sysmon vẫn chạy (`degraded`). Trên VM, nhóm Event Log Readers đọc được cả hai kênh
mới (SDDL ở mục 12.2 của tài liệu đề xuất), nên khó tạo tình huống này. Trường hợp này đã có test trên Linux.

## 0. An toàn và quyền riêng tư

1. Chỉ chạy trên VM lab có snapshot sạch. **Không tắt Windows Defender**: real-time protection và tamper protection giữ như lần Atomic.
   Không dùng mã độc. EICAR là tệp kiểm thử chuẩn, vô hại.
2. **Kênh PowerShell ghi lại mọi lệnh bạn gõ.** Khi Script Block Logging bật, lệnh gõ trong bất kỳ cửa sổ PowerShell nào cũng thành
   4104, vào Event Log và vào Silver của DACN. Vì vậy:
   - **Không dán token vào lệnh.** Đọc token bằng `Read-Host -AsSecureString` như ở mục 1.3. Giá trị nhập qua `Read-Host` không phải
     script block nên không bị ghi.
   - Không gõ mật khẩu thật. Mục V3 dùng chuỗi giả `DacnW8FakeValue123`.
3. Lần đầu bật kênh, agent đọc **toàn bộ lịch sử** của hai log (không có checkpoint thì đọc từ bản ghi cũ nhất). Log PowerShell trên VM
   có thể chứa script cũ, kể cả các lệnh bạn gõ những lần trước. Không gửi Bronze, Silver, `raw_xml`, `health.json` đầy đủ hay ảnh chụp
   khung script. Chỉ gửi những tệp nêu ở mục 9.
4. Ảnh chụp dashboard có thể chứa hostname, tên người dùng, đường dẫn và command line. Tô đen trước khi gửi.

## 1. Chuẩn bị

### 1.1. Cập nhật mã nguồn

Cửa sổ **A** (PowerShell, **Administrator**: agent đọc Sysmon cần quyền này, theo lần chạy ngày 2026-11-24):

```powershell
Set-ExecutionPolicy -Scope Process -ExecutionPolicy Bypass -Force
C:\dacn_venv\Scripts\Activate.ps1
cd C:\DACN
python -m edr_ctl stop --config C:\dacn_edr\edr.yaml      # nếu hệ thống đang chạy từ lần trước
git pull --ff-only origin claude_implement
git log --oneline -1          # phải là 30723de "feat(alerts): nối sự kiện Defender/PowerShell..." hoặc mới hơn
pip install -r requirements.txt
$env:PYTHONPATH = "C:\DACN\src;C:\DACN\src\pipeline;C:\DACN\poc\sysmon-collector"
New-Item -ItemType Directory C:\dacn_results -Force | Out-Null
```

(Tùy chọn) Chạy test của phần này trên Windows rồi gửi lại đầu ra. Trên Linux ngày 2026-11-28 các tệp này đều pass.

```powershell
python -m pytest -q tests\agent\test_multichannel.py tests\pipeline\test_bronze_v11_channels.py `
  tests\pipeline\test_silver_windows_channels.py tests\detection\test_defender_rules.py tests\detection\test_powershell_rules.py `
  tests\api\test_script_redaction.py tests\alerts\test_process_link.py tests\e2e\test_w8_channel_report.py *> C:\dacn_results\w8_pytest.txt
```

### 1.2. Kiểm tra môi trường (chỉ đọc)

```powershell
Get-MpComputerStatus | Select-Object AMServiceEnabled, RealTimeProtectionEnabled, IsTamperProtected
Get-Service Sysmon64 | Select-Object Status
Get-ItemProperty "HKLM:\Software\Policies\Microsoft\Windows\PowerShell\ScriptBlockLogging"    # EnableScriptBlockLogging phải là 1
Get-WinEvent -ListLog "Microsoft-Windows-Windows Defender/Operational", "Microsoft-Windows-PowerShell/Operational" |
  Select-Object LogName, IsEnabled, RecordCount, MaximumSizeInBytes
```

Mong đợi: ba giá trị Defender là `True`; Sysmon `Running`; `EnableScriptBlockLogging : 1`. Nếu chưa bật Script Block Logging, làm theo
mục 2.4 của tài liệu đề xuất. Ghi lại `RecordCount` của hai log: đây là khối lượng lịch sử agent sẽ đọc ở lần đầu.

Không đổi `maxSize` của log trong lần này. Nếu V6 cho thấy mất sự kiện do log quay vòng, mình sẽ bàn sau.

Chụp snapshot **`w8-ready`**.

### 1.3. Token API

Nếu chưa có, tạo token (`api.auth` in token **một lần**; output không bị ghi vào 4104):

```powershell
python -m api.auth --config C:\dacn_edr\edr.yaml --role viewer  --actor tester_v
python -m api.auth --config C:\dacn_edr\edr.yaml --role analyst --actor tester_a
```

Trong cửa sổ nào cần gọi API, đọc token bằng lệnh sau. **Không** viết `$tok = "..."`, vì dòng đó sẽ thành 4104:

```powershell
function Read-Token($label) {
  $s = Read-Host -AsSecureString "Dán token $label"
  [Runtime.InteropServices.Marshal]::PtrToStringAuto([Runtime.InteropServices.Marshal]::SecureStringToBSTR($s))
}
$HV = @{ Authorization = "Bearer " + (Read-Token "viewer") }
$HA = @{ Authorization = "Bearer " + (Read-Token "analyst") }
$API = "http://127.0.0.1:8765"
```

## 2. Cấu hình ba kênh

Sao lưu cấu hình rồi mở bằng Notepad:

```powershell
Copy-Item C:\dacn_edr\edr.yaml C:\dacn_edr\edr.yaml.bak_w8
notepad C:\dacn_edr\edr.yaml
```

Thêm (hoặc sửa) khối sau ở cấp cao nhất. Tệp cũ có thể chưa có khối `agent:`, khi đó agent chỉ đọc Sysmon. Mẫu lấy từ
`config\edr.example.yaml`:

```yaml
agent:
  channels:
    - {name: "Microsoft-Windows-Sysmon/Operational", enabled: true}
    - {name: "Microsoft-Windows-Windows Defender/Operational", enabled: true}
    - {name: "Microsoft-Windows-PowerShell/Operational", enabled: true}
```

Nếu tệp đã có khóa `agent:`, đặt `channels:` bên trong khóa đó, đừng tạo khóa `agent:` thứ hai. Tên kênh sai sẽ làm cấu hình lỗi
`CFG-006`; ghi lại thông báo đó nếu gặp.

## 3. V1: khởi động và health

Ghi lại thời điểm bắt đầu theo UTC (dùng cho `--since` ở mục 9) rồi khởi động:

```powershell
$T0 = (Get-Date).ToUniversalTime().ToString("yyyy-MM-ddTHH:mm:ss+00:00"); $T0
python -m edr_ctl start --config C:\dacn_edr\edr.yaml --live
python -m edr_ctl status --config C:\dacn_edr\edr.yaml
```

Chép `$T0` ra ghi chú. Chờ khoảng 1 phút rồi xem health theo từng kênh (lệnh này không in hostname):

```powershell
$h = Get-Content -Encoding UTF8 C:\dacn_edr\agent\health.json | ConvertFrom-Json
$h.state
$h.channels.PSObject.Properties | ForEach-Object { "{0,-50} {1,-8} written={2} errors={3}" -f $_.Name, $_.Value.state, $_.Value.events_written, ($_.Value.errors_by_code | ConvertTo-Json -Compress) }
Get-ChildItem C:\dacn_edr\agent\checkpoint_live_*.json | Select-Object Name, Length
Get-ChildItem C:\dacn_edr\bronze -Filter "seg-*" | Group-Object { ($_.Name -split '-20')[0] } | Select-Object Name, Count
```

Mong đợi:
- `state` là `running` hoặc `idle`, không phải `error` hay `degraded`. Ba dòng kênh, mỗi kênh `running` hoặc `idle`, `errors={}`.
- Ba checkpoint: `checkpoint_live_microsoft_windows_sysmon_operational.json`, `..._windows_defender_operational.json`,
  `..._powershell_operational.json`. Checkpoint Sysmon chép từ `checkpoint_live.json` cũ, tệp cũ vẫn còn.
- Segment Bronze có ba nhóm tên: `seg-<thời điểm>` (Sysmon), `seg-microsoft_windows_windows_defender_operational`,
  `seg-microsoft_windows_powershell_operational`. Ở chế độ `--live`, agent niêm phong segment ở cuối **mỗi lượt đọc** có sự kiện
  (`src/agent/runner.py`), nên hầu như không còn tệp `.jsonl.part`. Mỗi segment có thêm một tệp `.manifest.json`, nên số tệp không
  phải số segment.
- `events_written` của Defender và PowerShell tăng dần cho tới khi đọc hết lịch sử (mỗi lượt đọc tối đa 500 sự kiện mỗi kênh, xoay vòng).
  **Chờ tới khi hai số này đứng yên** rồi mới sang V2. Ghi lại thời gian chờ và hai con số.

Kiểm tra qua API (cần `$HV` ở mục 1.3):

```powershell
$r = Invoke-RestMethod "$API/health" -Headers $HV
$r.agent.status; $r.pipeline | Format-List
$r.core.last_ingest | Format-List      # pending_segments: số segment đã niêm phong chưa nạp
```

`core.last_ingest.pending_segments` phải giảm dần về gần 0 sau khi đọc hết lịch sử. Nếu nó tăng mãi, core nạp không kịp: dừng lại và
gửi `C:\dacn_edr\metrics.jsonl` (10 dòng cuối) cho Claude.

Mong đợi: `agent.status` là `REPORTED`, không phải `DEGRADED`, `ERROR` hay `STALE`.

Mở `http://127.0.0.1:8765/ui/` bằng token analyst. Có thể đã thấy alert DET-201 và DET-202 từ **sự kiện cũ** (EICAR và A09 ngày
2026-11-26, và các lần đổi cấu hình 5007). Đó là kết quả đúng của việc đọc lịch sử. Mục 9 dùng `$T0` để tách alert cũ với alert mới.

## 4. V2: 4104 lành tính, script block nhiều phần và PID

Mở cửa sổ **C**: PowerShell **thường** (không Administrator), không activate venv. Gõ từng dòng:

```powershell
$PID                                         # ghi lại số này
(Get-Date).ToUniversalTime().ToString("o")   # ghi lại
Get-Process | Select-Object -First 3 Name
Get-ChildItem C:\Windows | Measure-Object | Select-Object Count
```

Tạo một script **lành tính dài khoảng 50.000 ký tự** trong thư mục lab rồi chạy nó trong cùng cửa sổ. 4104 chia script dài thành
nhiều phần; mẫu thật cho thấy mỗi phần khoảng 17.651 ký tự, nên script này phải ra khoảng 3 phần:

```powershell
Set-ExecutionPolicy -Scope Process -ExecutionPolicy Bypass -Force
$d = Join-Path $env:TEMP "dacn_lab"; New-Item -ItemType Directory $d -Force | Out-Null
$f = Join-Path $d "w8_long_benign.ps1"
$line = "# dacn w8 benign padding " + ("x" * 100)
(@($line) * 400 + 'Write-Output "w8-long-done"') | Set-Content -Encoding UTF8 $f
& $f
```

Mong đợi: màn hình in `w8-long-done`. Chưa cần kiểm tra gì thêm: số liệu nằm trong báo cáo ở mục 9 (`silver.powershell.multi_part_blocks`
≥ 1, `complete_blocks_view`, và `process_links.powershell_blocks`).

Câu hỏi chính của V2: **PID ghi trong 4104 (`System/Execution@ProcessID`) có phải PID của `powershell.exe` không?** Báo cáo trả lời
bằng `by_confidence` (`UNIQUE`, `AMBIGUOUS`, `NONE`) và `candidate_images`. Nếu giả định đúng, phần lớn block ra `UNIQUE` với ảnh
`powershell.exe`. Nếu nhiều block ra `NONE` và `none_but_pid_has_other_image` > 0, PID đó thuộc tiến trình khác: phương pháp nối
`PID_IMAGE_LIFETIME` phải xem lại. Cách đối chiếu thủ công: trên dashboard, màn hình Cây tiến trình (`#/tree`), tìm theo ảnh
`powershell.exe` (màn hình chưa tìm được theo PID). Một trong các nút phải có PID bằng `$PID` bạn ghi ở trên.

Lưu ý: cửa sổ C mở **trước** khi agent chạy thì Sysmon Event 1 của nó vẫn đã nằm trong log Sysmon. Nhưng nếu nó mở trước lần đọc
Sysmon cuối cùng hơn 24 giờ, kết quả sẽ là `NONE` vì cửa sổ nhìn lại 24 giờ. Mở cửa sổ C mới cho chắc.

## 5. V3: che bí mật, DET-203, DET-204

Trong cửa sổ C, gõ **trên một dòng** (chuỗi `DacnW8FakeValue123` là giả):

```powershell
$p = ConvertTo-SecureString 'DacnW8FakeValue123' -AsPlainText -Force; Invoke-Expression 'Write-Output dacn-w8-redact'
```

Dòng sau gán một chuỗi base64 vào biến rồi chỉ in độ dài, **không giải mã, không chạy**. Chuỗi là UTF-16LE của
`Invoke-Expression 'Write-Output dacn-w8-b64'`:

```powershell
$b = 'SQBuAHYAbwBrAGUALQBFAHgAcAByAGUAcwBzAGkAbwBuACAAJwBXAHIAaQB0AGUALQBPAHUAdABwAHUAdAAgAGQAYQBjAG4ALQB3ADgALQBiADYANAAnAA=='; Write-Output $b.Length
```

Mong đợi (đã thử hai dòng này với hàm của rule trên Linux, chưa thử qua agent):
- Dòng 1: DET-203 MATCH (mẫu `invoke-expression`). Script của alert, khi xem qua API, có `'«ĐÃ CHE»'` thay cho chuỗi giả (luật
  `securestring_plaintext`).
- Dòng 2: DET-204 MATCH (giải mã UTF-16LE ra `invoke-expression`); DET-203 **không** MATCH dòng này.

Đợi khoảng 1 phút để core nạp. Trước khi gọi API, kiểm tra `(Invoke-RestMethod "$API/health" -Headers $HV).core.last_ingest`:
`pending_segments` phải gần 0. Nếu còn lớn, core đang nạp phần cũ hơn: chờ thêm.
Gọi API từ cửa sổ A (đã có `$HV`, `$HA`) để không thêm 4104 vào cửa sổ C:

```powershell
$ps = (Invoke-RestMethod "$API/alerts?limit=200" -Headers $HV).items | Where-Object { $_.rule_id -in "DACN-DET-203","DACN-DET-204" }
$ps | Select-Object alert_id, rule_id, severity, first_seen_utc, source_label | Format-Table
$id = ($ps | Where-Object rule_id -eq "DACN-DET-203" | Sort-Object first_seen_utc | Select-Object -Last 1).alert_id
if (-not $id) { throw "Chưa có alert DET-203: xem pending_segments ở trên, chờ thêm rồi chạy lại từ dòng `$ps = ..." }
$s = Invoke-RestMethod "$API/alerts/$id/script" -Headers $HV
$s.redacted; $s.redaction_rules; $s.text.Contains("DacnW8FakeValue123"); $s.text.Contains("ĐÃ CHE")
try { Invoke-RestMethod "$API/alerts/$id/script?reveal=true" -Headers $HV } catch { $_.Exception.Response.StatusCode }   # viewer: phải 403
(Invoke-RestMethod "$API/alerts/$id/script?reveal=true" -Headers $HA).text.Contains("DacnW8FakeValue123")              # analyst: True
(Invoke-RestMethod "$API/alerts/$id" -Headers $HV | ConvertTo-Json -Depth 6).Contains("DacnW8FakeValue123")             # phải False
```

Mong đợi theo thứ tự: `True`, có `securestring_plaintext`, `False`, `True`, `Forbidden`, `True`, `False`.
Đừng in nguyên `$s.text`: đó là script thật.

Trên dashboard (token analyst): mở alert DET-203. Phải thấy khung script **đã che** và nút xem bản gốc. Bấm nút một lần, rồi kiểm tra
mục 9 có `audit_raw_views.SCRIPT_RAW_VIEW` ≥ 2 (một lần từ PowerShell, một lần từ nút).

## 6. V4: EICAR (SC05)

Trong cửa sổ C, đọc script trước, chạy `-WhatIf` rồi mới chạy thật:

```powershell
cd C:\DACN\scripts\lab
powershell -ExecutionPolicy Bypass -File .\dacn_lab_scenarios.ps1 -Scenario SC05 -Eicar -WhatIf
(Get-Date).ToUniversalTime().ToString("o")          # ghi lại
powershell -ExecutionPolicy Bypass -File .\dacn_lab_scenarios.ps1 -Scenario SC05 -Eicar
```

Script ghép chuỗi EICAR thành tệp trong `%TEMP%\dacn_lab`, chờ 3 giây rồi xóa. Defender thường chặn hoặc xóa tệp trước. Script có thể
báo lỗi khi xóa: **ghi nguyên văn**, không chạy lại nhiều lần.

Xem Defender đã làm gì (không in đường dẫn hay tên người dùng):

```powershell
Get-MpThreatDetection | Sort-Object InitialDetectionTime | Select-Object -Last 3 InitialDetectionTime, ThreatID, ActionSuccess
```

Sau khoảng 1–5 phút, từ cửa sổ A:

```powershell
$d = (Invoke-RestMethod "$API/alerts?source=DEFENDER&limit=200" -Headers $HV).items
$d | Select-Object alert_id, rule_id, severity, first_seen_utc, source_label, detection_source | Format-Table
$id = ($d | Where-Object rule_id -eq "DACN-DET-201" | Sort-Object first_seen_utc | Select-Object -Last 1).alert_id
if (-not $id) { throw "Chưa có alert DET-201: xem core.last_ingest.pending_segments trong /health, chờ thêm" }
$l = Invoke-RestMethod "$API/alerts/$id/process-links" -Headers $HV
$l.events | ForEach-Object { $_.links | Select-Object method, confidence, @{n="n_candidates"; e={$_.candidates.Count}} } | Format-Table
$e = Invoke-RestMethod "$API/alerts/$id/evidence?include_raw=true" -Headers $HA
$e.events | Select-Object status, @{n="has_raw_xml"; e={[bool]$_.raw_xml}}, @{n="has_bronze"; e={[bool]$_.bronze}} | Format-Table
```

Mong đợi:
- Có alert `DACN-DET-201`, `source_label` là `Defender`, `detection_source` là `EXTERNAL_DEFENDER`, severity `medium`. 1116 và 1117 của
  cùng một phát hiện gộp vào **một** alert (theo `detection_id`).
- `process-links`: một dòng `PROCESS_NAME_LIFETIME`. Nếu Defender ghi Process Name là `Unknown` thì dòng này là `NOT_APPLICABLE`.
  Có thêm dòng `FILE_CREATE` nếu Sysmon ghi Event 11 cho tệp EICAR trong `dacn_lab`. Ghi lại có hay không, vì đây là câu hỏi mở của
  mục 6.3.
- Evidence: mỗi sự kiện có `status` `FULL`, có `raw_xml` và tham chiếu Bronze, tức là truy vết được tới `raw_xml` của 1116. Lệnh trên chỉ in `True`/`False`.
  Đừng in `raw_xml`, vì nó chứa hostname và tên người dùng.

Dashboard: cột nguồn có nhãn **Defender**, bộ lọc nguồn DACN/Defender hoạt động, alert có khung Defender (Threat Name, Action) và
khung nối tiến trình ghi rõ **suy luận**.

## 7. V5: Atomic A02 và A03

Dùng cửa sổ B (Administrator) và hàm `Run-One` của `ATOMIC_RED_TEAM_EVAL_GUIDE.md` mục 4.2, với cùng commit ghim
`a0e3f9bc69fed2fd711bd1f1aa87a40c33482fe6`. Chỉ chạy hai test, **mỗi test một lần**:

```powershell
$LOG = "C:\dacn_art\logs_w8"; New-Item -ItemType Directory $LOG -Force | Out-Null
Run-One $tests[3]      # A02 T1059.001 PowerShell Fileless Script Execution
Run-One $tests[4]      # A03 T1059.001 Invoke Known Malicious Cmdlets (cần Administrator)
```

(`Run-One` dùng biến `$LOG` nên cần đặt lại như trên để log không lẫn với các lần trước.) Sau mỗi test, xem Defender như ở mục 4.2 của
hướng dẫn Atomic và ghi lại: Defender có/không, ThreatName.

Lần chạy ngày 2026-11-26 (`ATOMIC_RED_TEAM_RESULTS_2026-11-26.md`): Defender chặn **cả hai** test ngay khi tạo tiến trình
(`Access is denied`), với Threat Name `Trojan:Win32/Powessere.K` (A02) và `Trojan:PowerShell/Mimikatz.A` (A03). Khi đó không có Sysmon
Event 1 và DACN không thấy gì. Mong đợi lần này (chưa đo):
- Defender chặn như lần trước → mỗi test có 1116 (và có thể 1117) → alert **DET-201**. Đây là kỳ vọng tối thiểu của mục 6.3.
- Nếu tiến trình bị chặn trước khi PowerShell chạy script thì **không có 4104**, DET-203/204 không có gì để đánh giá. Ghi đúng như quan
  sát; không coi là FN của DET-203.
- Nếu lần này tiến trình chạy được (Defender không chặn): A02 nhiều khả năng khớp DET-001 và DET-203 (`frombase64string`, `iex`).
  Tên cmdlet giả của A03 **không** nằm trong 9 mẫu của DET-203, nên A03 có thể không MATCH. Đó là giới hạn của danh sách mẫu, không
  phải lỗi thu thập.
- Nối tiến trình của alert DET-201: `NONE` hoặc `NOT_APPLICABLE` là kết quả đúng khi tiến trình không được tạo.
- `atomic_compare.py` chỉ quy alert về test theo cây tiến trình Sysmon. Alert DET-201 đến DET-204 không có `process_guid` nên công
  cụ **không** tính chúng. Xem chúng trong `since.alerts` của báo cáo ở mục 9, theo thời điểm so với giờ chạy từng test.

## 8. V6: dừng agent rồi chạy lại

Từ cửa sổ A:

```powershell
python -m edr_ctl stop --config C:\dacn_edr\edr.yaml
```

Trong lúc hệ thống dừng, ở cửa sổ C gõ:

```powershell
Write-Output "dacn-w8-while-stopped"; (Get-Date).ToUniversalTime().ToString("o")
```

Rồi khởi động lại ở cửa sổ A: `python -m edr_ctl start --config C:\dacn_edr\edr.yaml --live`. Chờ khoảng 1 phút.

Đếm số sự kiện trong Event Log kể từ `$T0` để so với báo cáo. Hai lệnh chỉ in số:

```powershell
$t = [datetime]::Parse($T0).ToUniversalTime()
(Get-WinEvent -FilterHashtable @{ LogName = "Microsoft-Windows-PowerShell/Operational"; Id = 4104; StartTime = $t.ToLocalTime() } -ErrorAction SilentlyContinue).Count
(Get-WinEvent -FilterHashtable @{ LogName = "Microsoft-Windows-Windows Defender/Operational"; Id = 1116,1117,5001,5007,5013; StartTime = $t.ToLocalTime() } -ErrorAction SilentlyContinue).Count
```

Ghi hai con số này kèm thời điểm đếm. 4104 tiếp tục phát sinh sau thời điểm đếm, vì chính các lệnh sau cũng tạo 4104, nên báo cáo có
thể lớn hơn một chút.

## 9. Thu kết quả

1. Dừng hệ thống: `python -m edr_ctl stop --config C:\dacn_edr\edr.yaml`. Báo cáo sao chép DuckDB nên core phải dừng.
2. Chạy báo cáo (chỉ đọc, làm trên bản sao; `--bronze` nạp segment niêm phong lúc dừng mà core chưa kịp nạp):

```powershell
python tests\e2e\w8_channel_report.py --silver C:\dacn_edr\silver\endpoint_silver.duckdb --bronze C:\dacn_edr\bronze `
  --since $T0 --out C:\dacn_results\w8_report.md --json C:\dacn_results\w8_report.json
Get-Content -Encoding UTF8 C:\dacn_results\w8_report.md
```

Nếu đã đóng cửa sổ A, thay `$T0` bằng chuỗi bạn đã chép (dạng `2026-11-29T01:00:00+00:00`).

3. (Tùy chọn) `atomic_compare.py` cho A02/A03 như mục 4.3 của hướng dẫn Atomic, với `--logs C:\dacn_art\logs_w8`.

Cách đọc báo cáo:

| Mục | Đạt khi |
|---|---|
| `bronze.channels.<kênh>.source_values` | Defender chỉ có `WINDOWS_DEFENDER`, PowerShell chỉ có `POWERSHELL`; `channel_mismatch` = 0 (V7) |
| `bronze.open_part_files` | 0 sau khi dừng (agent niêm phong khi dừng) |
| `ledger.<kênh>.balanced` | `true` cho mọi kênh: `records_read = inserted + duplicates + quarantined` |
| `silver.dlq_by_error_code` | Rỗng; nếu có mã như `ERR_DEFENDER_MISSING_THREAT`, `ERR_PS_*`: gửi lại, đây là phát hiện mới |
| `silver.powershell.multi_part_blocks` | ≥ 1 (script V2) và `complete_blocks_view` ≥ 1 |
| `alerts_after_report_ingest.alerts_with_process_guid_new_rules` | 0 (suy luận không được ghi vào alert) |
| `alerts_*.response_actions` | Không có hành động nào ngoài các hành động bạn tự tạo (V7) |
| `process_links.powershell_blocks` | Xem V2 |
| `since.alerts`, `since.defender_events` | Đối chiếu với thời điểm bạn ghi ở V2–V6 |
| `since.powershell_rows`, `len(since.defender_events)` | Gần bằng hai số đếm ở V6 |

4. Khôi phục: snapshot `w8-ready`. Hoặc trả lại cấu hình cũ:
   `Copy-Item C:\dacn_edr\edr.yaml.bak_w8 C:\dacn_edr\edr.yaml -Force`.

## 10. Gửi lại cho Claude

- `C:\dacn_results\w8_report.md` (đọc lại trước khi gửi: công cụ không xuất hostname, tên người dùng, đường dẫn hay script, nhưng hãy
  tự kiểm tra), và `w8_pytest.txt` nếu có chạy.
- Bảng dưới đây đã điền.
- Lỗi và cảnh báo nguyên văn (che định danh). Ảnh chụp dashboard nếu muốn, đã tô đen.

| Mã | Đạt / Không đạt / Không chạy | Ghi chú (con số, thời điểm UTC, thông báo lỗi) |
|---|---|---|
| V1 | | Thời gian đọc hết lịch sử; `events_written` của Defender và PowerShell; `RecordCount` ở 1.2 |
| V2 | | `$PID` của cửa sổ C; `by_confidence`; `candidate_images`; số phần của block dài |
| V3 | | Bảy giá trị kiểm tra ở mục 5; DET-203/DET-204 có MATCH không |
| V4 | | Defender: ThreatName, Action; alert DET-201: số lượng; `FILE_CREATE` có/không; `has_raw_xml` |
| V5 | | A02: Defender?, DET-001/201/203/204; A03: Defender?, có 4104 không, rule nào MATCH |
| V6 | | Hai số đếm Event Log và thời điểm; `dacn-w8-while-stopped` có vào Silver không (tìm qua `since.powershell_rows` tăng) |
| V7 | | `source_values`, `response_actions` |

Kết quả của **một** lần chạy trên **một** VM là quan sát, không phải tỷ lệ phát hiện hay tỷ lệ FP. Claude sẽ ghi kết quả vào mục 12
của tài liệu đề xuất và `CLAUDE.md` với đúng mức độ đó.
