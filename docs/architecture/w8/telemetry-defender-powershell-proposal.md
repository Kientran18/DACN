# Đề xuất bổ sung telemetry Microsoft Defender và PowerShell Script Block Logging

> **Trạng thái: APPROVED BY USER (2026-11-26) / ĐANG TRIỂN KHAI (hạng mục 1–9 xong ngày 2026-11-28, xem mục 12; 11: lượt chạy đầu trên VM xong ngày 2026-11-28, xem mục 12.11).** Người dùng duyệt D1–D10 ở mục 9 theo đúng đề xuất, thay cho
> Data/Cyber; chưa có review độc lập của nhóm Data/Cyber. Người dùng nói "bắt đầu" ngày 2026-11-28. Tài liệu này không
> thay đổi contract `bronze-event/1.0`, DDL v1.1, DDL v1.2, ADR, README hay kế hoạch 12 tuần. Mọi ánh xạ field gắn nhãn **[CHƯA XÁC MINH]**
> giữ nguyên nhãn đó cho tới khi có mẫu XML thật từ VM (mục 2.8); phê duyệt thiết kế không xác minh các field này.
>
> Ngày soạn: 2026-11-26. Nhánh căn cứ: `claude_implement` (commit `dc53684`). Người soạn: Claude Code theo yêu cầu thiết kế.
>
> Quy ước nhãn độ tin cậy dùng trong tài liệu:
> - **[MS-DOC]** có trong tài liệu Microsoft đã đọc ngày 2026-11-26 (URL ở mục 11).
> - **[CODE]** kiểm tra trực tiếp trên mã nguồn repository.
> - **[PROBE]** đã chạy script thăm dò trên dữ liệu **synthetic** trong phiên này (mục 3.1).
> - **[CHƯA XÁC MINH]** giả thuyết; cần mẫu XML thật từ VM trước khi viết code phụ thuộc vào nó.

## 1. Phạm vi và lý do

### 1.1. Căn cứ từ đánh giá Atomic Red Team và EICAR

Theo `docs/implementation/acceptance/ATOMIC_RED_TEAM_RESULTS_2026-11-26.md` (một VM Windows 10, mỗi test chạy một lần, Defender bật, tamper protection bật):

| Quan sát | Hệ quả với DACN hiện tại |
|---|---|
| A02 (T1059.001, kỳ vọng DET-001) bị Defender chặn khi tạo tiến trình (`Access is denied` tại `Invoke-Process.ps1`); Defender ghi nhận mối đe dọa | Không có Sysmon Event 1 nên DACN **không thấy gì**. Bằng chứng duy nhất nằm ở log Defender, kênh DACN không đọc |
| A03 (T1059.001, đã ghi "FN dự kiến (thiếu 4104)") cũng bị Defender chặn | DET-001 chỉ dựa command line. Nội dung script (4104) không được thu thập |
| A09: cả Defender và DET-004 cùng phát hiện | Không có cách hiển thị "hai nguồn cùng chỉ về một tiến trình" |
| EICAR (kịch bản SC05 trong `tests/e2e/scenarios.yaml`, `observe_only`): người dùng báo Defender phát hiện, DACN không có alert vì Sysmon Event 11 không mang hash | Đây là báo cáo của người dùng; báo cáo Atomic ở trên không ghi EICAR. Cần ghi kết quả EICAR vào tài liệu nghiệm thu khi chạy lại (mục 8.3) |

Cyber W5 đã ghi khoảng trống này: `docs/research/cyber/w5/04-telemetry-gaps-and-w06-w09-backlog.md` mục W5-CY-13 (thiếu PowerShell 4104) và
`docs/research/cyber/w5/01-detection-required-fields-and-mitre-to-data.md` (T1059.001: "Chưa có PowerShell 4104"; T1562.001/DET-007 bị chặn vì thiếu tín hiệu tamper).

### 1.2. Mục tiêu

1. Agent đọc thêm hai kênh: `Microsoft-Windows-Windows Defender/Operational` (Event 1116, 1117; tùy chọn 5001, 5007, 5013) và
   `Microsoft-Windows-PowerShell/Operational` (Event 4104).
2. Sự kiện mới đi qua cùng chuỗi Bronze sealed → adapter → validator → Silver, giữ nguyên `raw_xml`, định danh UUIDv5 và nguyên tắc fail closed.
3. Có rule tối thiểu: "Defender đã phát hiện" (alert với nguồn Defender) và "script block PowerShell đáng ngờ".
4. Dashboard phân biệt alert do rule DACN tự suy ra với alert phản ánh phát hiện của Defender.

### 1.3. Không làm

- Không tắt Defender, không thêm exclusion cho Defender, không dùng mã độc thật. EICAR là tệp kiểm thử chuẩn, không phải mã độc.
- Không đọc thêm kênh khác (Security 4688/4624, WMI, TaskScheduler, AMSI ETW trực tiếp). Ghi nhận là backlog.
- Không giải mã Protected Event Logging. Microsoft khuyến cáo không triển khai private key trên máy ghi log **[MS-DOC]**; DACN chạy trên chính máy đó.
- Không tự bật Script Block Logging, không sửa registry/Group Policy của VM. Người dùng tự làm (mục 2.4).
- Không tạo response tự động từ Defender alert, rule 4104, điểm rủi ro hay ML. Response vẫn đi qua Response Engine có duyệt và `dry_run` mặc định.
- Không đổi cách tính `event_id`, `host_id`, không sửa DDL v1.1 hay v1.2, không ALTER bảng Silver hiện có.
- Không coi Defender là "ground truth" để đo chất lượng rule DACN (Defender cũng có FP/FN).

## 2. Thu thập (agent)

### 2.1. Hiện trạng [CODE]

- `src/agent/sources/eventlog.py`: hằng `CHANNEL = "Microsoft-Windows-Sysmon/Operational"`; `EventLogSource(channel=...)` đã nhận tham số `channel`
  nhưng `src/agent/__main__.py` chỉ tạo `EventLogSource()` mặc định.
- Checkpoint một tệp `checkpoint_{mode}.json` (live: `checkpoint_live.json`), chứa **một** bookmark XML.
- `BronzeWriter` ghi manifest có `first_record_id`/`last_record_id`; hai trường này chỉ có nghĩa khi segment chứa **một** kênh
  (EventRecordID đánh số riêng theo từng kênh).
- `bronze_contract.build_bronze_record` gán cứng `"source": "SYSMON"` cho mọi bản ghi.

### 2.2. Đề xuất: một reader (subscription) mỗi kênh, cùng một tiến trình agent

| Phương án | Ưu | Nhược |
|---|---|---|
| **A. Một `EventLogSource` mỗi kênh (đề xuất)** | Lỗi quyền (C-006) ở kênh Defender không chặn Sysmon; bookmark độc lập; giữ nguyên `_Api` đã chạy trên VM | Agent phải lặp nhiều nguồn; nhiều handle |
| B. Một subscription với XML QueryList nhiều kênh | Một handle | Một bookmark chứa nhiều kênh **[CHƯA XÁC MINH]** hành vi `EvtCreateBookmark`/`EvtUpdateBookmark` với nhiều kênh qua pywin32; lỗi một kênh làm hỏng cả truy vấn; phải viết lại `_Api` vừa ổn định |

Thiết kế phương án A:

- Cấu hình mới (đề xuất) trong `edr.yaml`, mặc định chỉ có Sysmon để không đổi hành vi hiện tại:
  ```yaml
  agent:
    channels:
      - {name: "Microsoft-Windows-Sysmon/Operational", source: SYSMON, enabled: true}
      - {name: "Microsoft-Windows-Windows Defender/Operational", source: WINDOWS_DEFENDER, enabled: false,
         xpath: "*[System[(EventID=1116 or EventID=1117 or EventID=5001 or EventID=5007 or EventID=5013)]]"}
      - {name: "Microsoft-Windows-PowerShell/Operational", source: POWERSHELL, enabled: false,
         xpath: "*[System[(EventID=4104)]]"}
  ```
  Bộ lọc XPath giảm tải: kênh PowerShell/Operational còn nhiều Event ID khác (4100, 40961…), kênh Defender có nhiều sự kiện cập nhật chữ ký.
  `_Api.query` hiện truyền `Query="*"`; cần tham số hóa.
- Mỗi kênh có checkpoint riêng: `agent/checkpoint_live_<slug>.json`, `slug` = tên kênh viết thường, ký tự không phải chữ/số thay bằng `_`.
  Di chuyển tương thích: nếu tồn tại `checkpoint_live.json` cũ và chưa có tệp của Sysmon thì dùng nó cho kênh Sysmon (không mất vị trí).
- Mỗi kênh có `BronzeWriter` riêng, cùng thư mục `bronze/`, tiền tố tên segment `seg-<slug>-<timestamp>-<n>.jsonl`.
  `list_sealed` dùng glob `seg-*.jsonl` nên vẫn đọc được; manifest `first/last_record_id` giữ đúng nghĩa (một kênh mỗi segment).
- Vòng lặp: round-robin, mỗi kênh tối đa `batch_size` sự kiện mỗi lượt để kênh ồn (PowerShell) không bỏ đói Sysmon.
- `health.json`: thêm `channels: {<tên>: {state, last_event_at, events_written, errors_by_code}}`; giữ các trường cấp cao hiện có cho tương thích API.
- Lỗi theo kênh: kênh chưa tồn tại (ví dụ máy chưa từng ghi PowerShell/Operational) hoặc thiếu quyền → `SourceError` của kênh đó, ghi
  `collector_errors.jsonl`, health của kênh = `error`, các kênh khác chạy tiếp. Mã lỗi hiện có đủ dùng: C-006 (thiếu quyền), A-002 (lỗi khác).
  **[CHƯA XÁC MINH]** mã winerror khi kênh không tồn tại (thường là 15007 `ERROR_EVT_CHANNEL_NOT_FOUND`); cần quan sát trên VM rồi mới quyết định có cần mã riêng.

### 2.3. Quyền đọc

- Hiện agent live chạy bằng Administrator (`EDR_INSTALL_GUIDE.md`).
- Nhóm **Event Log Readers** (`S-1-5-32-573`) chỉ đọc được kênh nào có SDDL `ChannelAccess` cấp quyền cho SID này. **[CHƯA XÁC MINH]** SDDL
  mặc định của hai kênh Defender và PowerShell trên Windows 10 VM. Người dùng kiểm tra:
  ```powershell
  wevtutil gl "Microsoft-Windows-Windows Defender/Operational"
  wevtutil gl "Microsoft-Windows-PowerShell/Operational"
  # Xem dòng channelAccess: có (A;;0x1;;;S-1-5-32-573) hoặc (A;;0x1;;;ER) không
  ```
  Dán lại dòng `channelAccess` (không chứa định danh máy). Không tự đổi SDDL bằng `wevtutil sl /ca` trong phiên này.

### 2.4. Bật Script Block Logging (người dùng tự làm trên VM)

Windows PowerShell 5.1 **[MS-DOC, about_Logging 5.1]**:

- Group Policy: *Administrative Templates → Windows Components → Windows PowerShell → Turn on PowerShell Script Block Logging*.
- Registry tương đương: khóa `HKLM\Software\Policies\Microsoft\Windows\PowerShell\ScriptBlockLogging`, giá trị `EnableScriptBlockLogging` = `1`.
- Sự kiện ghi vào `Microsoft-Windows-PowerShell/Operational`, Event ID `4104` (`0x1008`), Level Verbose, Opcode Create, Task CommandStart.
- PowerShell 7 dùng kênh khác (`PowerShellCore/Operational`) và policy ở nhánh *PowerShell Core* **[MS-DOC, about_Logging_Windows 7.6]**. Đề xuất
  này chỉ phủ Windows PowerShell 5.1 (mặc định trên Windows 10). Thêm `PowerShellCore/Operational` là backlog.

Lệnh mẫu cho người dùng (Administrator, chỉ trên VM lab):
```powershell
New-Item -Path "HKLM:\Software\Policies\Microsoft\Windows\PowerShell\ScriptBlockLogging" -Force | Out-Null
Set-ItemProperty -Path "HKLM:\Software\Policies\Microsoft\Windows\PowerShell\ScriptBlockLogging" -Name EnableScriptBlockLogging -Value 1
# Kiểm tra
Get-ItemProperty "HKLM:\Software\Policies\Microsoft\Windows\PowerShell\ScriptBlockLogging"
```
Không bật "invocation logging" (4105/4106): tài liệu Microsoft đã đọc không mô tả, và nó tăng khối lượng log mạnh **[CHƯA XÁC MINH]**.

Ghi chú: khi chưa bật policy, Windows PowerShell 5.x vẫn có thể ghi 4104 mức Warning cho script block bị coi là đáng ngờ **[CHƯA XÁC MINH]**:
hai trang Microsoft đã đọc không nêu hành vi này. Không dựa vào nó trong tiêu chí nghiệm thu.

### 2.5. Kích thước log

- Mặc định kích thước tối đa của hai kênh **[CHƯA XÁC MINH]**; người dùng xem bằng `wevtutil gl <kênh>` (dòng `maxSize`).
- 4104 có thể rất lớn và nhiều. Nếu log quay vòng trước khi agent đọc, bookmark trỏ tới bản ghi đã mất. Đây là rủi ro mất sự kiện, không phải lỗi agent.
  Đề xuất: người dùng tăng `maxSize` của PowerShell/Operational trên VM (ví dụ `wevtutil sl "Microsoft-Windows-PowerShell/Operational" /ms:<bytes>`),
  giá trị chọn sau khi đo tốc độ ghi; agent ghi `coverage_gaps` khi phát hiện bước nhảy `EventRecordID` trong cùng kênh (đã có bảng v1.2).
- Bronze: `BronzeWriter` mặc định `max_bytes = 8 MiB`/segment; một 4104 lớn vẫn nằm gọn. `event_data` lặp lại nội dung của `raw_xml`, nên dung lượng
  Bronze cho 4104 xấp xỉ gấp đôi văn bản script. Cần đo trên VM.

### 2.6. Script block bị chia nhiều phần

- **[CHƯA XÁC MINH]** Các trường EventData của 4104 là `MessageNumber`, `MessageTotal`, `ScriptBlockText`, `ScriptBlockId`, `Path`. Hai trang Microsoft
  đã đọc **không** liệt kê tên trường này; cần mẫu XML thật (mục 2.8).
- Thiết kế (khi đã xác minh tên trường): mỗi phần là một bản ghi Bronze độc lập (định danh riêng theo `EventRecordID`). Ở Silver, mỗi phần là một dòng;
  việc ghép (theo `hostname`, `script_block_id`, thứ tự `message_number`) làm ở view/truy vấn, không ghép ở collector. Lý do: giữ ADR 0003 (một bản ghi
  thô = một sự kiện gốc) và tránh agent phải giữ trạng thái chưa đủ phần qua lần khởi động lại.
- Phần thiếu: nếu sau thời hạn trễ cho phép (đề xuất dùng lại `allowed_lateness_seconds` của Detection Engine) vẫn chưa đủ `MessageTotal` phần,
  block được coi là **không đầy đủ**; rule chạy trên phần có được và ghi `coverage_status = PARTIAL`, `missing_fields` gồm số phần thiếu.
  Không bịa phần thiếu.

### 2.7. Dữ liệu nhạy cảm trong script block

Microsoft cảnh báo khi bật script logging, thông tin xác thực hoặc dữ liệu nhạy cảm mà script dùng có thể bị ghi vào log **[MS-DOC]**.

Xung đột: ADR 0003 yêu cầu giữ nguyên `raw_xml`; adapter đối chiếu `raw_xml` với `event_data` (`BRONZE_RAW_MISMATCH`). Che (mask) ở collector sẽ phá cả hai.

| Phương án | Mô tả | Đánh giá |
|---|---|---|
| **P1 (đề xuất)** | Bronze giữ nguyên (ADR 0003). Silver lưu văn bản đầy đủ. API/dashboard **mặc định che** chuỗi khớp mẫu bí mật (ví dụ `-Password`, `ConvertTo-SecureString ... -AsPlainText`, chuỗi giống token dài); vai trò `admin` xem bản gốc qua endpoint riêng, mỗi lần xem ghi `audit_log`. Retention của Bronze/Silver cho kênh PowerShell ngắn hơn mặc định (giá trị do người dùng chọn) | Giữ được bằng chứng; rủi ro lộ dữ liệu nằm trên ổ đĩa cục bộ (đã là vùng tin cậy của EDR) |
| P2 | Silver chỉ lưu `sha256(ScriptBlockText)`, độ dài và các đặc trưng (có base64, có `iex`…); văn bản chỉ còn ở Bronze | An toàn hơn ở Silver nhưng rule phải chạy trên Bronze hoặc đặc trưng tính sẵn; điều tra khó |
| P3 | Không thu thập 4104 | Mất mục tiêu A03 |

Ghi chú: retention xóa thật của DACN mới có dry-run (`CLAUDE.md` mục 3.1), nên "retention ngắn hơn" hiện chỉ là chính sách trên giấy cho tới khi retention thật được làm.
Không đưa văn bản script vào commit, tài liệu công khai hay báo cáo nghiệm thu.

### 2.8. Mẫu XML thật cần người dùng xuất

Repository hiện **không có** mẫu XML thật của hai kênh. Người dùng chạy trên VM (PowerShell Administrator), sau khi đã chạy EICAR và một lệnh PowerShell lành tính:

```powershell
wevtutil qe "Microsoft-Windows-Windows Defender/Operational" /q:"*[System[(EventID=1116 or EventID=1117)]]" /c:4 /rd:true /f:xml > defender_sample.xml
wevtutil qe "Microsoft-Windows-Windows Defender/Operational" /q:"*[System[(EventID=5001 or EventID=5007 or EventID=5013)]]" /c:4 /rd:true /f:xml > defender_cfg_sample.xml
wevtutil qe "Microsoft-Windows-PowerShell/Operational" /q:"*[System[(EventID=4104)]]" /c:6 /rd:true /f:xml > ps4104_sample.xml
```

Trước khi gửi: thay `<Computer>`, `UserID` (SID), tên người dùng trong đường dẫn (`C:\Users\<tên>\...`), `Detection User`/`User` và mọi chuỗi bí mật
trong `ScriptBlockText` bằng giá trị giả nhất quán (ví dụ `SYNTH-HOST`, `S-1-5-21-0-0-0-1001`, `labuser`). Giữ nguyên tên phần tử, tên `Data Name`,
thứ tự trường và định dạng thời gian. Có thể dùng lại công cụ khử định danh đã có (`tests/test_sanitize_samples.py` kiểm tra công cụ đó) sau khi xác nhận nó
xử lý được hai kênh mới.

Cần có ít nhất: một 1116 và một 1117 của EICAR, một 4104 một phần, một 4104 nhiều phần (chạy một script dài lành tính, ví dụ khối comment lớn), nếu có
thì một 5007 (đổi một thiết lập Defender không làm giảm bảo vệ là không cần thiết: chỉ xuất nếu đã có sẵn trong log).

## 3. Bronze

### 3.1. Kết quả thăm dò trên dữ liệu synthetic [PROBE]

Script tạm (scratchpad, không commit) dựng một 4104 và một 1116 giả, gọi `build_bronze_record` → `validate_record` → `to_silver_input` → `SilverValidatorEngine`:

| Sự kiện | `source` | Lỗi schema | `event_type` từ adapter | Validator |
|---|---|---|---|---|
| 4104 synthetic | `SYSMON` (sai) | không | `SYSMON_EVENT_4104` (sai) | `ERR_UNSUPPORTED_EVENT_ID` → DLQ |
| 1116 synthetic | `SYSMON` (sai) | không | `SYSMON_EVENT_1116` (sai) | `ERR_UNSUPPORTED_EVENT_ID` → DLQ |

Kết luận: nếu chỉ trỏ agent sang kênh mới mà không sửa gì, bản ghi **không mất âm thầm** (vào DLQ) nhưng bị **gắn nhãn sai** `source: SYSMON` trong Bronze
bất biến. Không được bật kênh mới trước khi sửa phần Bronze.

### 3.2. Giữ `bronze-event/1.0` hay phiên bản mới

Ràng buộc trong `bronze-event.schema.json` [CODE]:
- `schema_version: {"const": "bronze-event/1.0"}`.
- `source` là enum `["SYSMON", "WINDOWS_SECURITY_LOG", "PSUTIL_SNAPSHOT", "COLLECTOR_INTERNAL"]`: không có giá trị cho Defender/PowerShell.
- Trường `sysmon_event_id` là bắt buộc; tên gắn với Sysmon nhưng nội dung chính là `System/EventID`.
- Mô tả schema: "Consumers must ignore unknown fields (forward compatible)".

| Phương án | Mô tả | Đánh giá |
|---|---|---|
| A. Giữ 1.0, ghi `source: SYSMON` | Không đổi gì | **Loại**: gắn nhãn sai, vi phạm Zero Data Fabrication |
| B. Giữ 1.0, ghi `source: COLLECTOR_INTERNAL` | Không đổi schema | **Loại**: sai nghĩa của giá trị |
| **C. `bronze-event/1.1` bổ sung (đề xuất)** | Thêm hai giá trị enum `WINDOWS_DEFENDER`, `POWERSHELL`; giữ mọi trường 1.0, giữ tên `sysmon_event_id` và ghi rõ nghĩa "System/EventID của kênh `channel`"; consumer route theo `(channel, provider.name, sysmon_event_id)` thay vì chỉ theo `sysmon_event_id` | Thay đổi bổ sung, không phá dữ liệu 1.0 đã lưu. Adapter phải chấp nhận cả `1.0` và `1.1`. Bản ghi Sysmon vẫn ghi `1.0` để segment cũ và mới giống nhau |
| D. `bronze-event/2.0` đổi tên `sysmon_event_id` → `windows_event_id` | Tên đúng nghĩa hơn | Phá vỡ: mọi consumer và dữ liệu đã lưu; không đáng trong Giai đoạn 1 |

Đề xuất C, với quy tắc: bản ghi Sysmon tiếp tục mang `schema_version: bronze-event/1.0`; bản ghi hai kênh mới mang `bronze-event/1.1`.
Tệp schema mới `bronze-event-1.1.schema.json` đặt cạnh tệp 1.0 (không sửa tệp 1.0). Việc này cần Data/Software/Cyber duyệt chéo, giống hợp đồng 1.0 vẫn đang chờ.

### 3.3. Tác động lên định danh và bảo tồn thô

| Thành phần | Tác động |
|---|---|
| `event_id` | Không đổi: UUIDv5(`EVENT_ID_NAMESPACE`, `Computer|Channel|EventRecordID`) theo ADR 0001. Vì khóa đã có `Channel`, EventRecordID trùng số giữa các kênh không va chạm |
| `host_id` | Không đổi: UUIDv5(`HOST_NAMESPACE`, hostname viết thường). Cùng `Computer` nên ba kênh cho cùng `host_id` **[CHƯA XÁC MINH]** `Computer` của Defender/PowerShell giống hệt Sysmon về chữ hoa/thường và dạng FQDN; nếu khác, `host_id` vẫn đúng vì đã viết thường, nhưng FQDN và tên ngắn sẽ cho hai `host_id` khác nhau |
| `raw_xml` | Giữ nguyên byte như `EvtRender` trả về (ADR 0003) |
| `event_data` | Tên `Data Name` gốc, không đổi tên, kể cả tên có khoảng trắng (schema cho phép mọi khóa chuỗi). **[CHƯA XÁC MINH]** Defender dùng `<Data Name=...>` hay `<UserData>`: `_parse_event_element` chỉ đọc `EventData/Data[@Name]`; nếu Defender dùng cấu trúc khác, `event_data` sẽ rỗng trong khi `raw_xml` có dữ liệu. Phải kiểm tra bằng mẫu thật |
| Va chạm sau khi xóa log | Cơ chế `ERR_EVENT_ID_COLLISION` + `coverage_gaps` hiện có áp dụng nguyên cho kênh mới |
| `writer_process_id` | Là tiến trình ghi sự kiện (Defender service hoặc chính `powershell.exe`), **không** mặc định là tiến trình bị giám sát. Với 4104, **[CHƯA XÁC MINH]** `System/Execution@ProcessID` chính là PID của `powershell.exe` chạy script; đây là đầu mối join với Sysmon (mục 4.6) |

### 3.4. Ánh xạ field

> **Cập nhật 2026-11-28:** tên trường đã đối chiếu với mẫu XML thật đã khử định danh; kết quả và các giả thuyết được xác nhận/bác bỏ ở mục 12.2. Bảng dưới giữ nguyên để lưu vết thiết kế.

**Defender 1116/1117.** Tài liệu Microsoft liệt kê **nhãn trong message**, không nói đó là `Data Name` trong XML **[MS-DOC]**:

| Event | Nhãn theo tài liệu Microsoft (đúng thứ tự trang) |
|---|---|
| 1116 `MALWAREPROTECTION_STATE_MALWARE_DETECTED` | Name, ID, Severity, Category, Path, Detection Origin, Detection Type, Detection Source, User, Process Name, Signature Version, Engine Version |
| 1117 `MALWAREPROTECTION_STATE_MALWARE_ACTION_TAKEN` | Name, ID, Severity, Category, Path, Detection Origin, Detection Type, Detection Source, User, Process Name, Action, Action Status, Error Code, Error Description, Signature Version, Engine Version |
| 5001 `MALWAREPROTECTION_RTP_DISABLED` | "Real-time protection is disabled." Không liệt kê trường |
| 5007 `MALWAREPROTECTION_CONFIG_CHANGED` | Old value, New value |
| 5013 | "Tamper protection blocked a change to Microsoft Defender Antivirus." Không liệt kê trường. Trang gán tên ký hiệu `MALWAREPROTECTION_SCAN_CANCELLED` trùng với 1002, không giải thích |

Tên `Data Name` thật trong XML **[CHƯA XÁC MINH]**. Giả thuyết cần kiểm tra (từ hiểu biết chung, không phải tài liệu đã đọc): XML dùng tên có khoảng
trắng như `Threat Name`, `Threat ID`, `Severity Name`, `Category Name`, `Path`, `Process Name`, `Detection User`, `Action Name`, `Detection ID`,
`Detection Time`, và `Path` có tiền tố dạng `file:_`. **Không viết mapping cho tới khi có mẫu thật.**

Cột Silver đề xuất (tên cột là đề xuất; nguồn điền chỉ là `Data Name` xác minh được):

| Cột Silver | Nguồn (sau khi xác minh) | Ghi chú |
|---|---|---|
| `threat_name` | nhãn "Name" | Bắt buộc với 1116/1117 |
| `threat_id` | nhãn "ID" | |
| `severity_name` | nhãn "Severity" | Severity của Defender, **không** phải severity alert DACN |
| `category_name` | nhãn "Category" | |
| `target_path` | nhãn "Path" | Giữ nguyên chuỗi gốc ở `raw_data`; cột chuẩn hóa bỏ tiền tố chỉ khi định dạng đã xác minh |
| `process_name` | nhãn "Process Name" | Có thể là "Unknown" **[CHƯA XÁC MINH]**; không suy ra PID |
| `detection_user` | nhãn "User" | Dữ liệu định danh: che ở báo cáo |
| `detection_source`, `detection_origin`, `detection_type` | các nhãn cùng tên | |
| `action_name`, `action_status`, `error_code` | 1117 | NULL với 1116 |
| `detection_id` | **[CHƯA XÁC MINH]** có trường ID phát hiện để nối 1116↔1117 | Nếu không có, nối theo (`threat_id`, `target_path`, cửa sổ thời gian) và ghi rõ là heuristic |
| `signature_version`, `engine_version` | nhãn cùng tên | |
| `old_value`, `new_value` | 5007 | |

**PowerShell 4104** **[CHƯA XÁC MINH toàn bộ tên trường]**: `MessageNumber` → `message_number` (INTEGER), `MessageTotal` → `message_total` (INTEGER),
`ScriptBlockText` → `script_block_text`, `ScriptBlockId` → `script_block_id` (GUID, bỏ ngoặc nếu có), `Path` → `script_path` (rỗng khi chạy tương tác).
`System/Level` (Verbose/Warning) → `level` để phân biệt 4104 do policy và 4104 tự động mức Warning.

## 4. Silver

### 4.1. Nguyên tắc

- DDL mới đặt trong tệp riêng `src/pipeline/sql/silver_schema_v1_3_proposal_defender_powershell.sql` (tên đề xuất), trạng thái PROPOSAL, chỉ `CREATE TABLE IF NOT EXISTS`.
  Không sửa v1.1, không sửa v1.2. `SilverStore` sẽ áp v1.1 → v1.2 → v1.3 theo thứ tự (khi được duyệt).
- `silver_event_lineage` (v1.2) dùng lại nguyên vẹn: khóa `event_id`, không cần đổi.
- Không thêm cột vào bốn bảng Sysmon.

### 4.2. DDL đề xuất (bản nháp, chưa chạy)

```sql
-- ĐỀ XUẤT v1.3 (PROPOSAL) — CHƯA DUYỆT. Chỉ thêm bảng; không ALTER v1.1/v1.2.
CREATE TABLE IF NOT EXISTS silver_defender_events (
    event_id VARCHAR(36) PRIMARY KEY,           -- UUIDv5 Computer|Channel|EventRecordID (ADR 0001)
    timestamp TIMESTAMPTZ NOT NULL,             -- System/TimeCreated@SystemTime
    hostname VARCHAR(64) NOT NULL,
    channel VARCHAR(128) NOT NULL,
    record_id BIGINT NOT NULL,
    windows_event_id INTEGER NOT NULL,          -- 1116 | 1117 | 5001 | 5007 | 5013
    event_type VARCHAR(48) NOT NULL,            -- xem 4.3
    threat_name VARCHAR,                        -- NULL với 5001/5007/5013
    threat_id VARCHAR,
    severity_name VARCHAR,
    category_name VARCHAR,
    target_path VARCHAR,
    process_name VARCHAR,
    detection_user VARCHAR,
    detection_source VARCHAR,
    detection_origin VARCHAR,
    detection_type VARCHAR,
    action_name VARCHAR,
    action_status VARCHAR,
    error_code VARCHAR,
    detection_id VARCHAR,                       -- chỉ khi xác minh có trường này
    signature_version VARCHAR,
    engine_version VARCHAR,
    old_value VARCHAR,
    new_value VARCHAR,
    raw_data JSON NOT NULL                      -- event_data gốc, như các bảng v1.1
);

CREATE TABLE IF NOT EXISTS silver_powershell_scriptblock_events (
    event_id VARCHAR(36) PRIMARY KEY,
    timestamp TIMESTAMPTZ NOT NULL,
    hostname VARCHAR(64) NOT NULL,
    channel VARCHAR(128) NOT NULL,
    record_id BIGINT NOT NULL,
    windows_event_id INTEGER NOT NULL,          -- 4104
    event_type VARCHAR(48) NOT NULL,
    level INTEGER,                              -- System/Level
    writer_process_id INTEGER,                  -- System/Execution@ProcessID (xem 4.6)
    script_block_id VARCHAR(36) NOT NULL,
    message_number INTEGER NOT NULL,
    message_total INTEGER NOT NULL,
    script_block_text VARCHAR NOT NULL,         -- xem chính sách 2.7
    script_text_sha256 VARCHAR(64) NOT NULL,    -- sha256 UTF-8 của phần này (tính, không bịa)
    script_path VARCHAR,
    raw_data JSON NOT NULL
);

-- Block đã đủ phần; block thiếu phần không xuất hiện ở view này
CREATE VIEW IF NOT EXISTS v_powershell_scriptblocks_complete AS
SELECT hostname, script_block_id, min(timestamp) AS first_ts, max(timestamp) AS last_ts,
       max(message_total) AS message_total, count(*) AS parts_seen,
       string_agg(script_block_text, '' ORDER BY message_number) AS script_text,
       list(event_id ORDER BY message_number) AS event_ids,
       any_value(writer_process_id) AS writer_process_id
FROM silver_powershell_scriptblock_events
GROUP BY hostname, script_block_id
HAVING count(DISTINCT message_number) = max(message_total);
```

Ghi chú: `string_agg(... ORDER BY ...)`, `list(... ORDER BY ...)` và `CREATE VIEW IF NOT EXISTS` cần kiểm tra trên phiên bản DuckDB đang ghim trong `requirements.txt`
trước khi chốt. `writer_process_id` chỉ lấy `any_value` khi mọi phần cùng PID; nếu khác (không mong đợi) phải để rule ghi `PARTIAL`.

### 4.3. Tên event type mới (liên quan Q-X3)

Q-X3 (tên event type giữa collector và validator) vẫn mở. Đề xuất **không** thêm vào `STATIC_EVENT_TYPES` của collector hay `EVENT_ID_TO_TYPE_DEFAULT`
của validator (cả hai khóa theo Sysmon ID và sẽ trùng số nếu Sysmon sau này có ID lớn). Thay vào đó dùng bảng ánh xạ theo `(channel, event_id)`:

| Kênh | ID | event_type đề xuất |
|---|---|---|
| Defender | 1116 | `DEFENDER_MALWARE_DETECTED` |
| Defender | 1117 | `DEFENDER_MALWARE_ACTION` |
| Defender | 5001 | `DEFENDER_RTP_DISABLED` |
| Defender | 5007 | `DEFENDER_CONFIG_CHANGED` |
| Defender | 5013 | `DEFENDER_TAMPER_BLOCKED` |
| PowerShell | 4104 | `POWERSHELL_SCRIPT_BLOCK` |

Một bảng ánh xạ duy nhất, nằm ở module dùng chung, để tránh tạo thêm "hai bộ tên".

### 4.4. Route, validator và mã lỗi

`SilverValidatorEngine` là bản sao thiết kế Data W05 và kiểm tra `sysmon_event_id in SUPPORTED_SYSMON_IDS` từ sớm. Đề xuất **không** nhồi kênh mới vào engine đó.
Thêm validator riêng (ví dụ `src/pipeline/validator_windows_channels.py`) và để `SilverStore.ingest_segment` chọn validator theo `record["channel"]`:

- Kênh Sysmon → `SilverValidatorEngine` như hiện tại (không đổi hành vi).
- Kênh Defender/PowerShell → validator mới.
- Kênh khác → DLQ `ERR_UNSUPPORTED_CHANNEL` (mới).

Thứ tự kiểm tra của validator mới (giống tinh thần W05): khóa tự nhiên → `record_id` → `(channel, event_id)` được hỗ trợ → thời gian hợp lệ → trường bắt buộc theo loại → route.

| Mã lỗi đề xuất | Khi nào | Tầng |
|---|---|---|
| `ERR_UNSUPPORTED_CHANNEL` | Kênh không có validator | route |
| `ERR_UNSUPPORTED_EVENT_ID` (dùng lại) | Kênh đã hỗ trợ nhưng ID ngoài danh sách (ví dụ 4100) | validator |
| `ERR_DEFENDER_MISSING_THREAT` | 1116/1117 thiếu "Name" hoặc "ID" | validator |
| `ERR_PS_MISSING_SCRIPTBLOCK_FIELD` | 4104 thiếu `ScriptBlockId`, `MessageNumber`, `MessageTotal` hoặc `ScriptBlockText` | validator |
| `ERR_PS_INVALID_PART_NUMBER` | `MessageNumber`/`MessageTotal` không phải số nguyên dương, hoặc `MessageNumber > MessageTotal` | validator |
| `ERR_TYPE_COERCION_FAILED`, `ERR_INVALID_TIMESTAMP`, `ERR_MISSING_NATURAL_KEY`, `ERR_INVALID_RECORD_ID` (dùng lại) | như W05 | validator |

Adapter: `to_silver_input` hiện gọi `poc._event_type(sysmon_event_id, ...)`; với kênh mới phải dùng bảng 4.3. Kiểm tra định danh và `BRONZE_RAW_MISMATCH` giữ nguyên.
Validator schema của adapter phải nhận cả 1.0 và 1.1.

Không điền giá trị thiếu: 5001 không có threat → các cột threat là NULL (hợp lệ, không phải lỗi). 1116 thiếu threat name → DLQ.

### 4.5. Dedup

- Theo `event_id` (PRIMARY KEY + `on conflict do nothing`), như hiện tại. Phát lại segment không tạo dòng mới.
- Không dedup ngữ nghĩa ở Silver (ví dụ Defender ghi lại cùng một mối đe dọa nhiều lần): việc gộp thuộc tầng alert (`group_key`).
- 4104 cùng `script_block_id` ở **nhiều lần chạy** **[CHƯA XÁC MINH]** có thể dùng lại ID khi cùng một script block được cache; không giả định duy nhất toàn cục.
  View 4.2 gom theo (`hostname`, `script_block_id`); nếu thấy nhiều hơn `message_total` dòng cho cùng ID, coi là "nhiều lần thực thi" và tách theo thời gian ở tầng detection.

### 4.6. Liên kết với tiến trình Sysmon

| Nguồn | Có gì | Cách join với `silver_process_events.process_guid` | Giới hạn |
|---|---|---|---|
| 4104 | `System/Execution@ProcessID` **[CHƯA XÁC MINH là PID của powershell.exe]** | Tìm Sysmon Event 1 cùng `hostname`, `pid = writer_process_id`, `image_path` kết thúc bằng `powershell.exe`, `timestamp(E1) <= timestamp(4104)`, lấy bản gần nhất; nếu có Sysmon Event 5 cùng PID trước 4104 thì loại ứng viên | PID tái sử dụng; agent khởi động muộn không có Event 1; đồng hồ hai kênh cùng máy nên lệch nhỏ nhưng không bằng 0. Kết quả join ghi `link_method = PID_TIME`, `link_confidence` là nhãn (`UNIQUE`/`AMBIGUOUS`/`NONE`), **không** phải số |
| Defender 1116/1117 | `Process Name` (đường dẫn hoặc "Unknown") **[CHƯA XÁC MINH]**, không có PID theo tài liệu | Theo `image_path` = `process_name` (không phân biệt hoa thường) trong cửa sổ thời gian đề xuất ±N giây trước sự kiện Defender, cùng `hostname` | Nhiều tiến trình cùng image → mơ hồ; "Unknown" → không join. Với A02/A03 tiến trình bị chặn khi tạo nên **không có** Event 1; alert Defender đứng một mình là đúng |
| Defender `Path` | Tệp bị phát hiện | Join với `silver_file_events.target_filename` (Event 11) để tìm `process_guid` tiến trình tạo tệp | Bỏ tiền tố `file:_` chỉ khi định dạng đã xác minh |

Kết quả join tính khi truy vấn (giống `process_context.py`), không ghi đè dữ liệu Silver. Rule dùng join phải xử lý `AMBIGUOUS` bằng cách liệt kê mọi ứng viên, không chọn đại.

## 5. Detection, điểm rủi ro, hiển thị

### 5.1. Thay đổi rule model

`loader.py` từ chối rule có `sysmon_event_ids` không nằm trong `SILVER_TABLE_FOR_EVENT` [CODE]. Đề xuất thêm khóa tùy chọn
`source_events: [{channel: <tên kênh>, event_ids: [...]}]` cho rule kênh mới, song song `sysmon_event_ids` (rule cũ không đổi). Rule chỉ được khai một trong hai.
`schema.py` thêm ánh xạ `(channel, event_id) → bảng Silver`. `DetectionResult` không đổi trường.

### 5.2. Rule đề xuất

| Rule ID đề xuất | Tên | Logic | Severity đề xuất | MITRE | Căn cứ MITRE |
|---|---|---|---|---|---|
| `DACN-DET-201` | Defender phát hiện mối đe dọa | Mỗi 1116 hợp lệ (gộp 1117 cùng phát hiện vào `contributing_event_ids` nếu nối được) | Ánh xạ từ `severity_name` của Defender, bảng ánh xạ do Cyber duyệt; mặc định `medium` nếu chưa có ánh xạ | Không gắn | Tên mối đe dọa của Defender không cho technique một cách tin cậy; gắn theo tên là đoán |
| `DACN-DET-202` | Defender real-time protection bị tắt / cấu hình bị đổi / tamper bị chặn | 5001, 5007, 5013 | 5001: `high`; 5007: `low`; 5013: `medium` (đề xuất, Cyber duyệt) | T1562.001 | Cyber W5 `01-...md` đã gắn T1562.001 (Disable or Modify Tools) cho DET-007. 5007 đơn lẻ thường là thay đổi lành tính (ví dụ cập nhật), nên severity thấp |
| `DACN-DET-203` | Script block PowerShell có dấu hiệu đáng ngờ | Trên block đã ghép (view 4.2) hoặc trên từng phần nếu block chưa đủ (`PARTIAL`): `contains_any` các mẫu như `frombase64string`, `invoke-expression`, `iex(`, `downloadstring`, `net.webclient`, `-bxor`, `reflection.assembly]::load`, `virtualalloc` | `medium` | T1059.001 | Giống DET-001 (`docs/research/cyber/w5/01-...md`); danh sách mẫu do Cyber duyệt |
| `DACN-DET-204` | Script block có chuỗi base64 dài giải mã ra lệnh PowerShell đáng ngờ | Tìm chuỗi base64 dài ≥ L ký tự, giải mã (UTF-16LE và UTF-8, giới hạn kích thước), áp lại mẫu DET-203 lên kết quả; `matched_fields` ghi đoạn khớp đã che | `medium` | T1027 (đề xuất), T1059.001 | T1027 cần Cyber xác nhận căn cứ; chưa có trong tài liệu Cyber W5 |

Rule ID dải `2xx` là đề xuất để không đụng `DET-001..010` (Cyber) và `DET-101`. Tất cả bắt đầu `validation_status: synthetic_only`, `status: enabled`
chỉ sau khi người dùng duyệt. DET-201 không "xác nhận" phát hiện của Defender là đúng; mô tả rule ghi rõ "phản ánh phát hiện của Defender".

Giới hạn đã biết: script bị làm rối ở mức chuỗi nối/biến sẽ né DET-203; giải mã base64 có chi phí và nguy cơ bom giải nén thì không áp dụng (không giải nén),
nhưng phải giới hạn độ dài đầu vào; DET-204 có FP với script quản trị nhúng dữ liệu base64.

DET-007 (đang blocked vì thiếu tín hiệu tamper): DET-202 chỉ phủ một phần (tamper của Defender), không mở khóa DET-007 (tamper của chính DACN/Sysmon).

### 5.3. Điểm rủi ro

`src/risk/config.py` khóa danh sách `CATEGORIES`. Đề xuất thêm category `EXTERNAL_AV` cho alert DET-201/202 (nguồn bên ngoài DACN), giữ DET-203/204 ở `RULE`.
Thay đổi `config/risk-scoring.yaml` (tăng `version`, ghi `changelog`, vẫn `status: heuristic_uncalibrated`):

```yaml
weights: {..., EXTERNAL_AV: 1.0}
category_caps: {..., EXTERNAL_AV: 60}
```

`EXTERNAL_AV` được tính vào `diversity_bonus` như một cơ chế độc lập (Defender không dùng dữ liệu của DACN). Giá trị là heuristic, chưa hiệu chỉnh.
**Điểm rủi ro và ML tiếp tục không kích hoạt response** (kiểm tra AST hiện có phải giữ pass).

### 5.4. Alert và dashboard

- `alerts.detection_source` (v1.2) là `VARCHAR(32)`, hiện nhận `RULE | IOC | ML`. Đề xuất thêm giá trị `EXTERNAL_DEFENDER` cho DET-201/202; không cần ALTER.
  Đây vẫn là thay đổi ý nghĩa contract alert → cần Data duyệt.
- Dashboard: cột/nhãn "Nguồn phát hiện" với hai giá trị hiển thị **DACN** (RULE/IOC/CORRELATION/STATIC) và **Defender** (EXTERNAL_DEFENDER); bộ lọc theo nguồn;
  trong chi tiết alert, khi một tiến trình có cả alert DACN và Defender thì hiển thị cả hai (A09 là ví dụ).
- Chi tiết alert DET-203/204: văn bản script mặc định đã che (mục 2.7).
- Một phiên Claude khác đang sửa `src/api` và `src/dashboard` (process tree); phần dashboard làm sau cùng và phải merge với thay đổi đó.

## 6. Kiểm thử

### 6.1. Fixture synthetic

Đặt ở `tests/fixtures/windows_channels/` (đề xuất), mỗi tệp có comment đầu `<!-- SYNTHETIC: ... không phải dữ liệu thật -->`, `Computer` = `SYNTH-HOST`.
Tên `Data Name` trong fixture đầu tiên phải **sao từ mẫu thật đã khử định danh** (mục 2.8); trước khi có mẫu, fixture chỉ dùng cho test không phụ thuộc tên trường
(định danh, route theo kênh, nhãn `source`).

| Fixture | Mục đích |
|---|---|
| `defender_1116_eicar.synthetic.xml`, `defender_1117_eicar.synthetic.xml` | luồng chuẩn, nối 1116↔1117 |
| `defender_5001.synthetic.xml`, `defender_5007.synthetic.xml`, `defender_5013.synthetic.xml` | DET-202 |
| `defender_1116_missing_threat.synthetic.xml` | `ERR_DEFENDER_MISSING_THREAT` |
| `ps4104_single.synthetic.xml`, `ps4104_three_parts.synthetic.xml`, `ps4104_missing_part.synthetic.xml`, `ps4104_bad_partno.synthetic.xml` | ghép, PARTIAL, `ERR_PS_INVALID_PART_NUMBER` |
| `ps4104_base64.synthetic.xml` | DET-204, chuỗi base64 của lệnh lành tính chứa từ khóa |
| `ps4104_secret.synthetic.xml` | kiểm tra che bí mật ở API (chuỗi giả `SYNTHETIC-NOT-A-SECRET`) |
| `mixed_channels_same_record_id.synthetic.xml` | ba kênh cùng `EventRecordID` → ba `event_id` khác nhau |

### 6.2. Test cần viết (khi triển khai)

- Agent: một nguồn mỗi kênh, checkpoint riêng, di chuyển `checkpoint_live.json` cũ, một kênh lỗi C-006 không chặn kênh khác, round-robin không bỏ đói,
  tiền tố segment, manifest một kênh, health theo kênh. Dùng `_Api` giả như test hiện có.
- Bronze: `source` đúng theo kênh; bản ghi Sysmon vẫn `bronze-event/1.0` và byte-identical với hiện tại (hồi quy); schema 1.1 hợp lệ; adapter nhận 1.0 và 1.1;
  định danh không đổi so với công thức ADR 0001.
- Silver: route theo kênh, từng mã lỗi mới, dedup khi phát lại segment, view ghép block, lineage.
- Detection: DET-201..204 MATCH/NO_MATCH/INSUFFICIENT_TELEMETRY/PARTIAL; `source_events` trong loader; loader vẫn từ chối rule sai.
- Join tiến trình: UNIQUE/AMBIGUOUS/NONE với PID tái sử dụng.
- Risk: category `EXTERNAL_AV`, `diversity_bonus`, kiểm tra AST "không response" vẫn pass.
- API: che bí mật mặc định, endpoint xem bản gốc chỉ cho `admin` và ghi audit.
- Toàn bộ `python -m pytest -q` phải giữ 513 test hiện có pass (con số đo ngày 2026-11-26; chạy lại trước khi so).

### 6.3. Kế hoạch trên VM (người dùng chạy, Claude không chạy)

Điều kiện: một Windows 10 VM, Defender bật (real-time và tamper protection như lần Atomic), Sysmon đang chạy, Script Block Logging đã bật (mục 2.4).

1. Xuất mẫu XML (mục 2.8), khử định danh, gửi lại. **Đây là cổng chặn trước khi viết mapping.**
2. Sau khi có bản triển khai: `edr_ctl start --live` với ba kênh bật. Kiểm tra `health.json` có ba kênh `running`.
3. EICAR (SC05): tạo tệp kiểm thử EICAR theo hướng dẫn hiện có. Kỳ vọng: 1116 (và có thể 1117) trong Silver; DET-201 MATCH; dashboard hiển thị nguồn Defender.
   Ghi thêm Sysmon Event 11 có/không.
4. Atomic A02, A03 (cùng commit ghim như lần trước, dùng `atomic_compare.py`). Kỳ vọng tối thiểu: Defender bắt → DET-201 MATCH. A03: nếu Defender chặn
   trước khi script chạy thì **có thể không có** 4104; ghi đúng như quan sát, không coi là FN của DET-203.
5. Đối chứng lành tính: chạy vài lệnh PowerShell quản trị thường ngày; ghi số alert DET-203/204 (FP quan sát, không phải tỷ lệ).
6. Restart agent giữa chừng; kiểm tra không mất/trùng ngoài at-least-once theo từng kênh.

### 6.4. Tiêu chí nghiệm thu đề xuất

- Không bản ghi nào của kênh mới mang `source: SYSMON`.
- Mọi bản ghi kênh mới vào Silver hoặc DLQ với mã lỗi cụ thể; không mất âm thầm (đếm Bronze = Silver + DLQ + trùng).
- EICAR trên VM: có alert DET-201 truy vết được về `raw_xml` của 1116.
- 4104 nhiều phần ghép đúng thứ tự; block thiếu phần → `PARTIAL`, không bịa.
- Văn bản script không lộ qua API ở vai trò `viewer`/`analyst` khi khớp mẫu bí mật.
- Không có response nào được tạo tự động.

### 6.5. Đề xuất bổ sung `at_catalog.yaml` (chưa sửa tệp)

| AT đề xuất | level | Mục tiêu |
|---|---|---|
| AT-44 | L | Bản ghi Defender/PowerShell synthetic → Bronze `bronze-event/1.1`, `source` đúng, định danh theo ADR 0001 |
| AT-45 | L | Route theo kênh, mã lỗi mới, dedup, view ghép 4104 |
| AT-46 | L | DET-201..204 trên fixture; không response |
| AT-47 | W | Agent đọc ba kênh trên VM, checkpoint riêng, một kênh thiếu quyền không chặn Sysmon |
| AT-48 | W | EICAR → 1116 → alert DET-201 → truy vết `raw_xml` |
| AT-49 | W | 4104 thật (một phần và nhiều phần) vào Silver đúng; che bí mật ở API |

## 7. Rủi ro

| Rủi ro | Ảnh hưởng | Giảm thiểu |
|---|---|---|
| Tên trường XML khác giả thuyết | Mapping sai, DLQ hàng loạt | Cổng chặn mục 2.8; validator fail closed vào DLQ, không bịa |
| Defender dùng `UserData` thay `EventData` | `event_data` rỗng, adapter vẫn "khớp" vì cả hai rỗng | Thêm kiểm tra: kênh Defender mà `event_data` rỗng → DLQ, không vào Silver |
| Lộ bí mật qua 4104 | Dữ liệu nhạy cảm trên đĩa/API | Mục 2.7; không đưa script vào tài liệu/commit |
| Khối lượng 4104 lớn trên VM 2 GB | CPU/đĩa, log quay vòng | XPath lọc, tăng `maxSize`, đo trên VM trước khi bật mặc định; mặc định `enabled: false` |
| Join PID sai | Gắn alert vào sai tiến trình | Nhãn `AMBIGUOUS`, liệt kê ứng viên, không chọn đại |
| Coi Defender là sự thật | Đánh giá rule DACN sai | Tách nguồn trên dashboard; không dùng Defender làm nhãn đo chất lượng |
| Xung đột với phiên khác sửa `src/api`, `src/dashboard` | Merge khó | Làm dashboard sau cùng, `git fetch` trước khi push |
| Contract 1.0 vẫn chưa được duyệt chéo mà đã có 1.1 | Hai phiên bản chờ duyệt cùng lúc | Duyệt 1.1 cùng gói với 1.0 |

## 8. Phạm vi công việc và thứ tự triển khai

Ước lượng tương đối (S < M < L), không phải số giờ.

| # | Hạng mục | Cỡ | Phụ thuộc |
|---|---|---|---|
| 0 | Người dùng xuất mẫu XML + kiểm tra `channelAccess`, `maxSize` (mục 2.3, 2.5, 2.8) | S | — (cổng chặn) |
| 1 | Bronze 1.1: schema mới, `build_bronze_record` gán `source` theo kênh, adapter nhận 1.0/1.1, test hồi quy Sysmon | M | duyệt quyết định D1–D2 |
| 2 | Agent đa kênh: cấu hình, checkpoint riêng + di chuyển, writer theo kênh, XPath, health | M | 1 |
| 3 | Silver v1.3: DDL, validator theo kênh, mã lỗi, view ghép 4104 | M | 0, 1, duyệt D3–D5 |
| 4 | Join tiến trình (query-time) | S–M | 3 |
| 5 | Rule model `source_events` + DET-201/202 | M | 3, duyệt D6–D7 |
| 6 | DET-203/204 (mẫu chuỗi, giải mã base64 có giới hạn) | M | 3, 5 |
| 7 | Risk `EXTERNAL_AV`, `risk-scoring.yaml` v2 | S | 5 |
| 8 | API che bí mật + endpoint xem bản gốc có audit | M | 3, duyệt D8 |
| 9 | Dashboard nguồn phát hiện | S–M | 5, 8, merge với phiên process tree |
| 10 | Tài liệu: `EDR_INSTALL_GUIDE.md` (bật 4104, quyền), `at_catalog.yaml`, `CLAUDE.md` mục 3.1 | S | sau từng hạng mục |
| 11 | Kiểm tra trên VM (mục 6.3), ghi kết quả | M | 2–9 |

Thứ tự đề xuất: 0 → 1 → 2 → 3 → 5 (DET-201/202, giải quyết EICAR/A02 trước) → 4 → 6 → 7 → 8 → 9 → 11, tài liệu cập nhật song song.
Defender đi trước PowerShell vì ít rủi ro dữ liệu nhạy cảm và trực tiếp lấp khoảng trống A02/A03/EICAR.

## 9. Quyết định cần duyệt

> **Ghi nhận phê duyệt (2026-11-26):** người dùng xác nhận trong phiên thiết kế: duyệt D1–D10 theo cột "Đề xuất" bên dưới, với vai trò người duyệt
> thay cho Data/Cyber/Software (chưa có review độc lập của các nhóm). Điều kiện kèm theo:
> - D6: T1027 cho DACN-DET-204 chỉ gắn khi có căn cứ được ghi lại (`mitre_basis`); chưa có căn cứ thì để trống.
> - D8: chọn P1. Số ngày retention cho kênh PowerShell **chưa chọn**: triển khai thành giá trị cấu hình, không đặt con số mặc định; hỏi người dùng khi cần.
> - Mẫu XML thật (mục 2.8) người dùng sẽ gửi sau; các field **[CHƯA XÁC MINH]** giữ nhãn cho tới khi đối chiếu với mẫu.
> - Phê duyệt thiết kế không phải lệnh triển khai: không sửa `src/`, contract, DDL cho tới khi người dùng nói "bắt đầu".

| # | Quyết định | Người duyệt | Đề xuất |
|---|---|---|---|
| D1 | `bronze-event/1.1` bổ sung enum `WINDOWS_DEFENDER`, `POWERSHELL`; Sysmon giữ 1.0 | Data + Software + Cyber | Phương án C mục 3.2 |
| D2 | Giữ tên `sysmon_event_id` với nghĩa System/EventID cho mọi kênh | Data | Giữ (tránh 2.0) |
| D3 | DDL v1.3 tách tệp: `silver_defender_events`, `silver_powershell_scriptblock_events`, view ghép | Data | Mục 4.2 |
| D4 | Tên event type theo `(channel, event_id)` (mục 4.3), độc lập Q-X3 | Data + Cyber | Mục 4.3 |
| D5 | Mã lỗi mới `ERR_UNSUPPORTED_CHANNEL`, `ERR_DEFENDER_MISSING_THREAT`, `ERR_PS_MISSING_SCRIPTBLOCK_FIELD`, `ERR_PS_INVALID_PART_NUMBER` | Data | Mục 4.4 |
| D6 | Rule ID dải `DACN-DET-201..204`, severity, MITRE (T1562.001 cho DET-202; T1059.001; T1027 cần căn cứ) | Cyber | Mục 5.2 |
| D7 | Khóa rule `source_events`; `detection_source = EXTERNAL_DEFENDER`; risk category `EXTERNAL_AV` | Software + Data + Cyber | Mục 5.1, 5.3, 5.4 |
| D8 | Chính sách dữ liệu nhạy cảm 4104 (P1/P2/P3) và retention cho kênh PowerShell | Người dùng + Cyber | P1 |
| D9 | Có thu 5001/5007/5013 trong đợt đầu không | Người dùng + Cyber | Có (rẻ, phủ một phần T1562.001) |
| D10 | Mặc định các kênh mới `enabled: false` cho tới khi đo trên VM | Người dùng | Có |

## 10. Liên quan tới các nhóm

- **Software**: agent, Bronze writer, adapter, validator mới, API, dashboard.
- **Data**: contract Bronze 1.1, DDL v1.3, event type, mã lỗi, lineage, retention.
- **Cyber**: rule DET-201..204, MITRE, ánh xạ severity Defender, danh sách mẫu chuỗi, chính sách bí mật.

## 11. Nguồn

- Microsoft, *Review event logs and error codes to troubleshoot issues with Microsoft Defender Antivirus*:
  https://learn.microsoft.com/en-us/defender-endpoint/troubleshoot-microsoft-defender-antivirus (đọc 2026-11-26).
- Microsoft, *about_Logging* (Windows PowerShell 5.1):
  https://learn.microsoft.com/en-us/powershell/module/microsoft.powershell.core/about/about_logging?view=powershell-5.1 (đọc 2026-11-26).
- Microsoft, *about_Logging_Windows* (PowerShell 7.6):
  https://learn.microsoft.com/en-us/powershell/module/microsoft.powershell.core/about/about_logging_windows (đọc 2026-11-26).
- Repository: `docs/decisions/0001`–`0003`, `poc/sysmon-collector/bronze-event.schema.json`, `bronze_contract.py`, `bronze_to_silver_adapter.py`,
  `src/agent/`, `src/pipeline/silver_store.py`, `src/pipeline/validator_poc.py`, `src/pipeline/sql/*_v1_2_proposal.sql`, `src/detection/`, `src/risk/`,
  `docs/implementation/acceptance/ATOMIC_RED_TEAM_RESULTS_2026-11-26.md`, `docs/research/cyber/w5/01-...md`, `04-...md`.

## 12. Tiến độ triển khai

### 12.1. Ngày 2026-11-28: hạng mục 1 (Bronze 1.1) và 2 (agent đa kênh)

Làm trước cổng chặn "mẫu XML thật" (hạng mục 0) vì không phụ thuộc tên trường EventData. Hạng mục 3 trở đi (Silver, rule) **chờ mẫu XML**.

| Thay đổi | Tệp |
|---|---|
| Bảng kênh dùng chung: kênh → (`source`, `schema_version`), Event ID hỗ trợ, event type theo (kênh, ID), XPath mặc định | `poc/sysmon-collector/windows_channels.py` (mới) |
| Schema `bronze-event/1.1` (tệp riêng; tệp 1.0 không sửa) | `poc/sysmon-collector/bronze-event-1.1.schema.json` (mới) |
| `build_bronze_record` gán `source`/`schema_version` theo kênh; kênh khác → `C-007`; `validate_record` chọn schema theo phiên bản và kiểm tra chéo (source, schema_version) với channel | `poc/sysmon-collector/bronze_contract.py` |
| Adapter: event type theo (kênh, ID) cho kênh mới; Sysmon giữ `_event_type` | `poc/sysmon-collector/bronze_to_silver_adapter.py` |
| Manifest ghi `schema_version` thật của segment (`mixed` + `schema_versions` nếu trộn); tiền tố tên segment theo kênh | `src/agent/bronze_writer.py` |
| `EventLogSource(xpath=...)`; `AgentRunner(max_events_per_run=...)`, `state`, `hit_limit` | `src/agent/sources/eventlog.py`, `src/agent/runner.py` |
| Agent đa kênh: reader/checkpoint/segment/health riêng, round-robin, kế thừa `checkpoint_live.json`, `health.json` tổng hợp (`degraded` khi một phần kênh lỗi) | `src/agent/multichannel.py` (mới), `src/agent/__main__.py` |
| Cấu hình `agent.channels` (mặc định chỉ Sysmon; tệp mẫu để Defender/PowerShell `enabled: false`, D10); mã `CFG-006` | `src/common/config.py`, `config/edr.example.yaml` |
| `/health` báo `DEGRADED` khi `state = degraded` | `src/api/app.py` |
| Fixture SYNTHETIC (tên `Data Name` là giả thuyết, gắn nhãn) và test | `tests/fixtures/windows_channels/`, `tests/pipeline/test_bronze_v11_channels.py`, `tests/agent/test_multichannel.py`, `tests/api/test_api.py`, `tests/agent/test_runner.py`, `tests/agent/test_eventlog_source.py` |

Quyết định triển khai nhỏ phát sinh (ngoài D1–D10; **người dùng duyệt `C-007`, `CFG-006` và `degraded` ngày 2026-11-28**, thay cho Data/Software, chưa có review độc lập):
- **Mã collector mới `C-007`** (kênh không được hỗ trợ): sự kiện kênh lạ (ví dụ file mode đọc export Security) bị từ chối ở collector,
  ghi `collector_errors.jsonl` kèm `raw_xml`, thay vì gắn nhãn sai `SYSMON`. Bảng mã C-001..C-006 trong
  `docs/research/software/w5/01-collector-to-bronze-interface-contract-v1.md` đã bổ sung dòng C-007 (2026-11-28).
- **Mã cấu hình `CFG-006`** (danh sách kênh không hợp lệ hoặc kênh không hỗ trợ; agent thoát mã 2).
- **Trạng thái health `degraded`** và `/health` status `DEGRADED`.
- Tên segment Sysmon giữ nguyên `seg-<thời gian>-<n>`; kênh khác `seg-<slug>-<thời gian>-<n>`.
- Giới hạn mặc định 500 sự kiện/kênh/lượt; vòng `--follow` không ngủ khi còn tồn đọng.

Kiểm thử (Linux, Python 3.13, môi trường **không** có `lightgbm`): `python -m pytest -q` → 566 pass, 2 skipped, 0 fail
(trước thay đổi: 533 pass, 2 skipped cùng môi trường). Chưa chạy trên Windows.

Hiện trạng dữ liệu: bản ghi Defender/PowerShell vào Bronze đúng nhãn rồi vào DLQ `ERR_UNSUPPORTED_EVENT_ID` ở validator Sysmon
(không vào 4 bảng Sysmon, không mất âm thầm). Hạng mục 3 sẽ route theo kênh sang validator riêng.

Kiểm tra trên VM khi người dùng muốn (không bắt buộc trước hạng mục 3): bật một kênh mới trong `edr.yaml`, chạy
`python -m agent run --config C:\dacn_edr\edr.yaml --live` (không `--follow`), xem `C:\dacn_edr\agent\health.json` mục `channels`
và segment `seg-microsoft_windows_...` trong `bronze\`. Không gửi nội dung segment PowerShell (có thể chứa script/bí mật).

### 12.2. Ngày 2026-11-28: đối chiếu mẫu XML thật và hạng mục 3 (Silver v1.3)

**Mẫu nhận được** (người dùng xuất bằng `wevtutil qe` trên một Windows 10 VM, đã khử định danh: `LAB-HOST-01`, `LABUSER01`, SID giả;
Defender Product Version 4.18.26100.4; Windows PowerShell 5.1). Mẫu **không** được commit; fixture trong
`tests/fixtures/windows_channels/` dựng lại theo cấu trúc, với giá trị giả.

| Tệp | Nội dung |
|---|---|
| defender_detect | 2 cặp 1116/1117: EICAR (Real-Time Protection, Quarantine) và `Trojan:Win32/Commandrob.A!ml` từ Atomic A09 (System, Remove) |
| defender_cfg | 4 sự kiện 5007; **không có** 5001/5013 |
| ps4104 | 20 sự kiện 4104 mới nhất: 13 block một phần và phần 13–19 của một block 19 phần |
| `wevtutil gl` | `channelAccess` và `maxSize` của hai kênh |

**Kết quả đối chiếu:**

| Giả thuyết (mục 2–4) | Kết quả trên mẫu |
|---|---|
| Defender dùng `EventData/Data[@Name]` (không phải `UserData`) | **Xác nhận**. `event_data` đầy đủ, adapter khớp `raw_xml` |
| Tên trường có khoảng trắng: `Threat Name`, `Threat ID`, `Severity Name`, `Category Name`, `Path`, `Process Name`, `Detection User`, `Action Name`, `Detection ID`, `Detection Time` | **Xác nhận**. Có thêm `Security intelligence Version`, `Engine Version`, `Source Name`, `Remediation User`, `Unused`..`Unused6` (rỗng). Nhãn trên trang Microsoft ("Name", "User", "Action") **không** phải `Data Name` |
| Có trường nối 1116↔1117 | **Xác nhận**: `Detection ID` giống nhau ở 1116 và 1117 của cùng phát hiện (cả hai cặp) |
| `Path` có tiền tố `file:_` | **Xác nhận**, và có thêm `CmdLine:_` (Atomic A09: Path là command line, không phải tệp). Path của A09 **bị cắt ngắn** giữa chừng |
| `Process Name` có thể là "Unknown" | **Xác nhận** (A09). EICAR: đường dẫn đầy đủ `...\powershell.exe`. Không có PID |
| 5007 có `Old value`/`New value` | Tên thật là `Old Value`/`New Value` (V hoa). Cả 4 mẫu là thay đổi nội bộ của Defender (`WdConfigHash`, `ServiceStartStates`, `InitializingComponentProgress`): 5007 đơn lẻ rất ồn, giữ severity thấp cho DET-202 |
| 4104: `MessageNumber`, `MessageTotal`, `ScriptBlockText`, `ScriptBlockId`, `Path` | **Xác nhận** (đúng thứ tự này). `Path` rỗng khi chạy tương tác. Level 5 (Verbose), Task 2, Opcode 15 |
| Script block lớn bị chia nhiều sự kiện | **Xác nhận**: block 19 phần, mỗi phần 17.651 ký tự (phần cuối ngắn hơn); các phần ghi liên tiếp trong cùng mili giây, EventRecordID tăng dần |
| `System/Execution@ProcessID` của 4104 là PID của `powershell.exe` | **Chưa xác nhận**: mọi 4104 cùng PID 2888, khớp với một phiên PowerShell, nhưng chưa đối chiếu với Sysmon Event 1 cùng máy |
| Event Log Readers đọc được hai kênh | SDDL `channelAccess` của **cả hai** kênh có `(A;;0x1;;;S-1-5-32-573)` (quyền đọc cho Event Log Readers). Mới đọc SDDL, **chưa** thử chạy agent bằng tài khoản không phải Administrator |
| Kích thước log | `maxSize`: Defender 16.777.216 byte (16 MiB), PowerShell 15.728.640 byte (15 MiB); `retention: false` (ghi đè vòng). Chưa đo tốc độ ghi |
| 5001, 5013 | **Chưa có mẫu**: chỉ lưu khung chung + `raw_data`; fixture `defender_5001.synthetic.xml` vẫn gắn nhãn giả thuyết |

**Hạng mục 3 đã làm:**

| Thay đổi | Tệp |
|---|---|
| DDL v1.3 (tệp riêng, không sửa v1.1/v1.2): `silver_defender_events`, `silver_powershell_scriptblock_events`, view `v_powershell_scriptblocks_complete`, 2 index | `src/pipeline/sql/silver_schema_v1_3_proposal_defender_powershell.sql` |
| Validator riêng cho hai kênh, mã lỗi D5 (`ERR_UNSUPPORTED_CHANNEL`, `ERR_DEFENDER_MISSING_THREAT`, `ERR_PS_MISSING_SCRIPTBLOCK_FIELD`, `ERR_PS_INVALID_PART_NUMBER`) và mã W05 dùng lại | `src/pipeline/validator_windows_channels.py` |
| `SilverStore` áp v1.3 và route theo kênh (Sysmon → validator W05 không đổi; Defender/PowerShell → validator mới); lineage, dedup, va chạm định danh dùng chung | `src/pipeline/silver_store.py` |
| Fixture dựng theo cấu trúc thật (10 tệp) và 17 test | `tests/fixtures/windows_channels/`, `tests/pipeline/test_silver_windows_channels.py` |

Khác biệt so với DDL nháp ở mục 4.2 (do mẫu thật):
- `target_path` thay bằng `path_raw` (nguyên văn), `resource_type` (tiền tố trước `:_`, ví dụ `file`, `CmdLine`), `resource_value` (phần sau).
  Chỉ tách tiền tố đầu tiên; nếu Path chứa nhiều tài nguyên thì giữ nguyên trong `resource_value` (chưa thấy trên mẫu).
- Mọi giá trị Defender lưu dạng **chuỗi gốc** (kể cả `Severity ID`, `Action ID`): không ép kiểu, nên không có lỗi ép kiểu và không bịa giá trị.
- Thêm `ingest_timestamp`, `source`, `level` (cả hai bảng), `user_sid` (4104), `remediation_user`, `source_name`, `origin_name`,
  `execution_name`, `type_name`, `detection_time` (chuỗi gốc). Bỏ `detection_source`/`detection_type` (không có `Data Name` như vậy).
- View gom theo (`hostname`, `script_block_id`, `message_total`) và chỉ nhận block có **đúng** `message_total` dòng với đủ số thứ tự.
  Giới hạn: nếu cùng `ScriptBlockId` lặp lại (chạy lại cùng script, chưa xác minh có xảy ra không), block bị loại khỏi view; rule sẽ phải xét theo từng phần.

Kiểm tra trên mẫu thật (scratchpad, không commit): 28 sự kiện → Bronze hợp lệ (28/28) → Silver 28 dòng, DLQ 0; 1116/1117 nối đúng
qua `detection_id`; block 19 phần (chỉ có phần 13–19) **không** vào view, đúng thiết kế.

Kiểm thử (Linux, Python 3.13, không có `lightgbm`): `python -m pytest -q` → 583 pass, 2 skipped, 0 fail. Chưa chạy trên Windows.

Còn lại: hạng mục 4 (join tiến trình), 5–6 (rule DET-201..204), 7 (risk), 8 (API che bí mật; **trước khi xong hạng mục 8, văn bản
script nằm nguyên trong Silver và có thể đọc qua truy vấn DuckDB trực tiếp**; API hiện chưa có endpoint đọc bảng này), 9 (dashboard), 11 (VM).

### 12.3. Ngày 2026-11-28: hạng mục 5 (rule model `source_events`, DACN-DET-201/202)

| Thay đổi | Tệp |
|---|---|
| Rule schema thêm field tùy chọn: `source_events` (D7), `detection_source: EXTERNAL_DEFENDER` (D7), `severity_by`, `context_fields`, `group_by_field`; loader kiểm tra kênh/Event ID theo `windows_channels`, loại trừ lẫn nhau với `sysmon_event_ids`, chuẩn hóa tên kênh | `src/detection/schema.py`, `src/detection/loader.py` |
| Evaluator: severity theo giá trị trường (`severity_by`), ngữ cảnh vào `matched_fields["context"]` chỉ khi MATCH | `src/detection/evaluator.py` |
| Engine: đọc bảng v1.3 theo `windows_event_id` khi bảng tồn tại; con trỏ `ingest_timestamp` tính cả bảng v1.3; **watermark correlation chỉ tính bảng Sysmon** (segment Defender có thể đến sớm hơn Sysmon cùng khoảng thời gian, không được đóng cửa sổ DET-010 sớm) | `src/detection/engine.py` |
| AlertBuilder: `detection_source` và `group_by_field` từ rule; evidence tra được `silver_defender_events` (bảng PowerShell **cố ý chưa** tra cho tới khi có che bí mật ở API) | `src/alerts/builder.py`, `src/alerts/evidence.py` |
| DACN-DET-201 (1116/1117, medium cố định, không MITRE, gom theo `detection_id`) và DACN-DET-202 (5001 high / 5013 medium / 5007 low, T1562.001) | `src/detection/rules/dacn-det-201.yaml`, `dacn-det-202.yaml` |
| Contract W06 xuất lại (chỉ thêm field) | `docs/architecture/w6/contracts/rule.schema.json`, `README.md` |
| 16 test | `tests/detection/test_defender_rules.py` |

Quyết định triển khai phát sinh (**chờ duyệt**, ngoài D1–D10):
- `severity_by` (cần để một rule DET-202 có severity khác nhau theo Event ID như D6), `context_fields` (đưa tên mối đe dọa,
  đường dẫn, hành động vào alert; Defender không có `image_path`/`command_line`), `group_by_field` (Defender không có `process_guid`;
  thiếu nó mọi phát hiện Defender trong 10 phút trên một máy bị gộp vào một alert).
- DET-201 đọc cả 1116 và 1117 (1117 gộp vào alert của 1116 nhờ `detection_id`; còn 1117 khi mất 1116 vẫn có alert).
- DET-201 severity cố định `medium`: chưa có bảng ánh xạ `Severity Name` được Cyber duyệt (D6 cho phép mặc định này).

Kết quả trên 28 sự kiện thật đã khử định danh (scratchpad, không commit, một lần trên Linux): DET-201 MATCH 4 (EICAR 1116+1117,
Atomic A09 1116+1117) → **2 alert** `EXTERNAL_DEFENDER`; DET-202 MATCH 4 (4 sự kiện 5007 nội bộ của Defender) → **3 alert `low`**.
Xác nhận 5007 gây nhiễu: cần Cyber chọn danh sách loại trừ (`exclude`) hoặc tắt 5007 khỏi DET-202.

Kiểm thử (Linux, Python 3.13, không có `lightgbm`): `python -m pytest -q` → 599 pass, 2 skipped, 0 fail. Chưa chạy trên Windows.

Giới hạn hiện tại:
- Điểm rủi ro (`src/risk`) chưa có category `EXTERNAL_AV` (hạng mục 7): alert `EXTERNAL_DEFENDER` đang được tính như `RULE`
  và gắn vào chủ thể host (không có `process_guid`).
- Dashboard hiển thị nguyên giá trị `EXTERNAL_DEFENDER`; nhãn "DACN/Defender" và bộ lọc nguồn là hạng mục 9.
- Không nối alert Defender với tiến trình Sysmon (hạng mục 4).

### 12.4. Ngày 2026-11-28: hạng mục 6 (DACN-DET-203/204, rule PowerShell 4104)

| Thay đổi | Tệp |
|---|---|
| Rule type mới `scriptblock` + field `patterns`, `base64`; loader **cấm rule `single` đọc kênh PowerShell** (evaluator `single` chép nguyên giá trị trường vào `matched_fields`, tức là chép văn bản script vào alert) | `src/detection/schema.py`, `src/detection/loader.py` |
| Evaluator script block: ghép theo (`hostname`, `script_block_id`, `message_total`) theo `message_number`; thiếu phần thì chèn ký tự ngăn cách ở chỗ hở (không ghép giả), `coverage_status = PARTIAL_SCRIPT_BLOCK`, `missing_fields` liệt kê phần thiếu; giải mã base64 có giới hạn (số ứng viên, kích thước, không giải nén, chỉ văn bản in được, UTF-16LE hoặc UTF-8). `matched_fields` chỉ có tên mẫu, sha256, độ dài, số phần: **không có văn bản script hay văn bản giải mã** | `src/detection/scriptblock.py` (mới) |
| Engine: mỗi lượt đánh giá lại MỌI phần của các block có phần mới (phần đến muộn làm block đầy đủ); cùng `message_number` lặp lại thì giữ `record_id` nhỏ nhất | `src/detection/engine.py` |
| AlertBuilder tra bảng PowerShell **nội bộ** (lấy hostname/thời điểm/`script_block_id`); `resolve_evidence` (API) **không** tra bảng này nên evidence của alert DET-203/204 là PARTIAL, không trả script hay `raw_xml` cho tới hạng mục 8 | `src/alerts/evidence.py`, `src/alerts/builder.py` |
| DACN-DET-203 (9 mẫu chuỗi, medium, T1059.001) và DACN-DET-204 (base64 `min_length` 40, tối đa 50 ứng viên, 1 MiB; medium; T1059.001; **T1027 không gắn** vì chưa có căn cứ trong tài liệu Cyber, điều kiện của D6) | `src/detection/rules/dacn-det-203.yaml`, `dacn-det-204.yaml` |
| Contract W06 xuất lại (chỉ thêm) | `docs/architecture/w6/contracts/rule.schema.json`, `README.md` |
| 11 test + 1 test hồi quy | `tests/detection/test_powershell_rules.py`, `tests/detection/test_defender_rules.py` |

**Lỗi phát hiện và đã sửa** (do hạng mục 5 gây ra): DB chỉ có dữ liệu kênh v1.3 (chưa có sự kiện Sysmon nào) thì lượt chạy
tăng dần thứ hai lỗi `min() iterable argument is empty` ở bước correlation, vì watermark và mốc thấp nhất đều chỉ tính bảng Sysmon.
Sửa: không có mốc Sysmon thì nạp toàn bộ bảng Sysmon (đang rỗng). Có test hồi quy `test_incremental_run_with_only_channel_data_and_no_sysmon`.

Chuỗi "đáng ngờ" và base64 trong test được ghép lúc chạy, không để trong tệp fixture tĩnh, để Defender trên VM không cách ly tệp khi clone repo.

Kết quả trên 28 sự kiện thật đã khử định danh (scratchpad, một lần, Linux): 20 sự kiện 4104 (lệnh tương tác và script chú thích
lành tính của người dùng) → **0** kết quả DET-203/204; Defender giữ nguyên như 12.3. Mẫu rất nhỏ: không phải số đo FP.

Kiểm thử (Linux, Python 3.13, không có `lightgbm`): `python -m pytest -q` → 612 pass, 2 skipped, 0 fail. Chưa chạy trên Windows.

Quyết định triển khai **chờ duyệt**: rule type `scriptblock`, field `patterns`/`base64`, giá trị `min_length` 40, danh sách 9 mẫu
(lấy từ mục 5.2 và DET-001), giữ alert ở coverage PARTIAL khi phần thiếu đến sau.

### 12.5. Ngày 2026-11-28: hạng mục 7 (điểm rủi ro `EXTERNAL_AV`)

| Thay đổi | Tệp |
|---|---|
| Cơ chế `EXTERNAL_AV` trong danh sách category (không phải ML, nên được tính vào thưởng đa dạng như một cơ chế độc lập với rule DACN) | `src/risk/config.py`, `src/risk/scoring.py` |
| Alert có `detection_source` bắt đầu bằng `EXTERNAL_` (Defender DET-201/202) xếp vào `EXTERNAL_AV`; không có `process_guid` nên chỉ vào chủ thể host | `src/risk/service.py` |
| Cấu hình lên **v2**: `EXTERNAL_AV` trọng số 1.0, trần 60 (bằng `RULE`, vì DACN không xác minh lại phát hiện của Defender); `status: heuristic_uncalibrated`; changelog ghi lý do. Cấu hình thiếu khóa `EXTERNAL_AV` bị loader từ chối | `config/risk-scoring.yaml` |
| Tài liệu | `docs/implementation/RISK_SCORING.md` |
| 3 test mới; test cũ đổi `version == 1` thành `2` | `tests/risk/test_external_av.py`, `tests/risk/test_risk_scoring.py`, `tests/api/test_risk_api.py` |

Ví dụ (synthetic): một alert Defender `medium` (25) và một alert DET-001 `medium` (25) trên cùng host trong cửa sổ 1 giờ
→ 25 + 25 + thưởng đa dạng 10 = 60 (mức `high`). Giá trị heuristic, chưa hiệu chỉnh; điểm rủi ro vẫn **không** kích hoạt response.

Hệ quả cần biết: nhiễu của DET-202 (5007 nội bộ, `low` = 10 điểm) giờ góp vào điểm host và thưởng đa dạng. Một host chỉ có
5007 nội bộ và một alert DACN `medium` sẽ được 10 + 25 + 10 = 45 (`medium`). Cần Cyber quyết định loại trừ 5007 (xem 12.3).

Kiểm thử (Linux, Python 3.13, không có `lightgbm`): `python -m pytest -q` → 615 pass, 2 skipped, 0 fail.

Quyết định triển khai **chờ duyệt**: trọng số 1.0 và trần 60 cho `EXTERNAL_AV`; quy tắc nhận diện theo tiền tố `EXTERNAL_` của `detection_source`.

### 12.6. Ngày 2026-11-28: hạng mục 8 (API che bí mật, xem script có kiểm soát, retention PowerShell)

| Thay đổi | Tệp |
|---|---|
| Hàm che chuỗi giống bí mật (heuristic): khối private key, `ConvertTo-SecureString '...'`, tham số `-Password/-Token/-ApiKey...`, gán `password=`/`api_key:`..., `Bearer ...`, khóa dạng `AKIA...`, chuỗi dài ≥ 40 ký tự có cả hoa/thường/số | `src/common/redact.py` (mới) |
| Ghép script block của một alert, đánh dấu phần thiếu `[... THIẾU PHẦN n ...]` (không bịa) | `src/alerts/scriptblock_view.py` (mới) |
| `GET /alerts/{id}/script`: mặc định trả bản **đã che** + danh sách luật đã áp dụng; `?reveal=true` cần quyền `raw` và ghi `audit_log` `SCRIPT_RAW_VIEW` (actor, alert, script_block_id) | `src/api/app.py` |
| Evidence: nay tra cả bảng PowerShell; `script_block_text` được che khi không `include_raw`; `raw_xml` vẫn chỉ trả khi `include_raw` (quyền `raw`, audit `EVIDENCE_RAW_VIEW` như trước) | `src/alerts/evidence.py`, `src/api/app.py` |
| Retention dry-run: `--powershell-raw-days` tùy chọn, **không có mặc định** (bỏ trống = dùng `--raw-days`), áp cho segment có tiền tố kênh PowerShell. Đáp ứng điều kiện D8: số ngày là cấu hình do người dùng chọn | `src/pipeline/retention.py` |
| Test: 17 test API/che + 1 test retention; sửa 1 test hạng mục 6 (evidence nội bộ nay trả nguyên văn, API che) | `tests/api/test_script_redaction.py`, `tests/pipeline/test_retention.py`, `tests/detection/test_powershell_rules.py` |

**Khác thiết kế P1 (mục 2.7):** P1 ghi "vai trò `admin` xem bản gốc", nhưng hệ thống không có vai trò admin (chỉ `viewer`, `analyst`,
`approver`, `responder`). Đã dùng quyền `raw` hiện có (analyst, approver), đúng cơ chế đang áp cho `raw_xml`, kèm audit mỗi lần xem.
Nếu muốn chặt hơn (ví dụ chỉ approver), cần quyết định thêm quyền riêng.

Giới hạn:
- Che là heuristic: bí mật không theo mẫu (mật khẩu trần trong chuỗi bình thường, biến ghép) vẫn lộ ở bản "đã che". Bản gốc vẫn nằm
  nguyên ở Bronze/Silver (ADR 0003); ai đọc trực tiếp tệp/DuckDB trên máy vẫn thấy.
- Luật `long_token` cũng che payload base64 dài (DET-204); người điều tra cần `reveal` để xem.
- Retention xóa thật vẫn chưa có (chỉ dry-run); Silver PowerShell không bị dọn.

Kiểm tra trên mẫu thật (scratchpad): 20 script block 4104 lành tính của người dùng → 0 lần che (không che nhầm). Mẫu nhỏ.

Kiểm thử (Linux, Python 3.13, không có `lightgbm`): `python -m pytest -q` → 633 pass, 2 skipped, 0 fail.

Quyết định triển khai **chờ duyệt**: dùng quyền `raw` thay vai trò admin; danh sách luật che; ngưỡng 40 ký tự của `long_token`.

### 12.7. Ngày 2026-11-28: hạng mục 9 (dashboard nguồn phát hiện và khung script)

| Thay đổi | Tệp |
|---|---|
| `/alerts?source=DACN|DEFENDER`; mọi alert trả thêm trường suy ra `source_label` (`Defender` khi `detection_source = EXTERNAL_DEFENDER`, còn lại `DACN`; không lưu DB) | `src/api/app.py`, `src/alerts/store.py` |
| Danh sách alert: cột "Nguồn" (huy hiệu Defender màu riêng), bộ lọc "Nguồn phát hiện" | `src/dashboard/static/app.js`, `style.css` |
| Chi tiết alert: huy hiệu nguồn ở tiêu đề và dòng "nguồn phát hiện"; alert Defender có khung "Phát hiện của Microsoft Defender" (ghi rõ DACN không xác minh lại, không có PID) và bảng ngữ cảnh; alert PowerShell có khung "Script PowerShell (Event 4104)" hiện bản **đã che**, luật đã áp dụng, phần thiếu, nút "Hiện bản gốc (ghi audit)" chỉ bật với quyền `raw` và hỏi xác nhận trước; bảng bằng chứng hiện Event ID và kênh của bảng v1.3 | `src/dashboard/static/app.js` |
| Test: Playwright riêng (không sửa `ui_check.js` của màn hình cây tiến trình) và test API lọc nguồn | `tests/dashboard/test_dashboard_sources.py`, `tests/dashboard/ui_sources_check.js`, `tests/api/test_alert_sources.py` |

Playwright (Linux, Chromium có sẵn, dữ liệu synthetic) kiểm: cột nguồn có cả hai giá trị; lọc Defender/DACN đúng; khung Defender
có ngữ cảnh EICAR; script đã che không chứa bí mật giả; chuỗi `<img onerror>` trong script hiện thành chữ (không chạy); approver
xem được bản gốc sau xác nhận và audit ghi đúng một `SCRIPT_RAW_VIEW`; viewer thấy nút bị tắt và không thấy bí mật; không có
request ra ngoài. Ảnh chụp chỉ để kiểm tra, không commit.

Kiểm thử (Linux, Python 3.13, không có `lightgbm`): `python -m pytest -q` → 635 pass, 2 skipped, 0 fail. Chưa chạy trên Windows.

Chưa làm: trang Tổng quan chưa tách số alert theo nguồn; cây tiến trình chưa hiện alert Defender/PowerShell (cần hạng mục 4).

### 12.8. Ngày 2026-11-28: hạng mục 4 (nối sự kiện Defender/PowerShell với tiến trình Sysmon)

| Thay đổi | Tệp |
|---|---|
| Suy luận tính khi truy vấn, **không ghi DB** và không gán `process_guid` vào alert/Silver. Ba phương pháp: `PID_IMAGE_LIFETIME` (4104: `writer_process_id` + host + ảnh `powershell.exe`/`pwsh.exe`/`powershell_ise.exe` + còn sống tại thời điểm 4104), `PROCESS_NAME_LIFETIME` (Defender: `Process Name` = `image_path`, còn sống tại `Detection Time`; "Unknown" → `NOT_APPLICABLE`), `FILE_CREATE` (Defender `resource_type=file`: `file_path` của Sysmon Event 11 trước `Detection Time`). Nhãn `UNIQUE`/`AMBIGUOUS`/`NONE`/`NOT_APPLICABLE`; liệt kê mọi ứng viên (tối đa 20); cửa sổ nhìn lại 24 giờ (heuristic) | `src/alerts/process_link.py` (mới) |
| `GET /alerts/{id}/process-links` (quyền `read`; không trả văn bản script) | `src/api/app.py` |
| Dashboard: khung "SUY LUẬN — Tiến trình liên quan" cho alert Defender/PowerShell không có `process_guid`, có link mở màn hình cây tiến trình | `src/dashboard/static/app.js` |
| 10 test + 3 kiểm tra Playwright | `tests/alerts/test_process_link.py`, `tests/dashboard/test_dashboard_sources.py`, `ui_sources_check.js` |

"Còn sống tại t" = có Event 1 trong [t − 24h, t] và không có Event 5 cùng `process_guid` trước t. Giới hạn:
- Thiếu Event 5 (agent không chạy lúc tiến trình kết thúc) làm tiến trình cũ trông như còn sống → thêm ứng viên (AMBIGUOUS), không chọn đại.
- 4104 dùng PID làm khóa chính, khác nguyên tắc W06 "không PID-only" (`src/detection/process_context.py`) của join Sysmon–Sysmon;
  được giảm rủi ro bằng host + ảnh + vòng đời và luôn hiển thị là suy luận. Việc `System/Execution@ProcessID` của 4104 là PID của
  `powershell.exe` **chưa xác nhận trên VM** (mẫu thật có PID nhất quán 2888 nhưng chưa có Sysmon Event 1 cùng lúc để đối chiếu).
- A02/A03 (Defender chặn khi tạo tiến trình): không có Event 1 → `NONE` là kết quả đúng.
- Kết quả nối không vào điểm rủi ro theo tiến trình và không hiện trên màn hình cây tiến trình (chỉ link sang cây).
- Chưa thử trên dữ liệu VM có cả Sysmon và Defender/4104 cùng khoảng thời gian.

Kiểm thử (Linux, Python 3.13, không có `lightgbm`): `python -m pytest -q` → 645 pass, 2 skipped, 0 fail. Chưa chạy trên Windows.

Quyết định triển khai **chờ duyệt**: ba phương pháp nối và điều kiện "còn sống"; cửa sổ 24 giờ; không đưa kết quả nối vào alert/rủi ro.

### 12.9. Ngày 2026-11-28: hướng dẫn chạy hạng mục 11 trên VM (chưa chạy)

| Thay đổi | Tệp |
|---|---|
| Hướng dẫn từng bước V1–V7: agent ba kênh, 4104 lành tính và block nhiều phần, kiểm tra PID của 4104, che bí mật/DET-203/DET-204 bằng chuỗi giả, EICAR (SC05), Atomic A02/A03, dừng/chạy lại; đọc token bằng `Read-Host -AsSecureString` để token không thành 4104 | `docs/implementation/acceptance/W8_DEFENDER_POWERSHELL_VM_GUIDE.md` |
| Công cụ báo cáo CHỈ ĐỌC (bản sao Silver, `--bronze` nạp segment còn thiếu, `--since` tách sự kiện cũ do lần đầu đọc cả lịch sử log): đếm Bronze/ledger/Silver/DLQ theo kênh, kiểm tra `source`, alert theo rule, nhãn nối tiến trình và ảnh ứng viên; không xuất hostname, người dùng, đường dẫn hay script | `tests/e2e/w8_channel_report.py`, `tests/e2e/test_w8_channel_report.py` (5 test, fixture synthetic) |

Hai dòng thử DET-203/DET-204 trong hướng dẫn đã được kiểm với `find_patterns`, `decode_candidates`, `redact` trên Linux; chưa qua agent.
`atomic_compare.py` không quy alert DET-201..204 về test Atomic vì các alert này không có `process_guid`; hướng dẫn dùng `--since` của
báo cáo mới thay thế. Lưu ý quan sát từ code: lần đầu bật kênh không có checkpoint, `EventLogSource` đọc từ bản ghi cũ nhất (`EvtQuery`
chiều tiến), nên alert từ sự kiện cũ (EICAR/A09 ngày 2026-11-26, 5007) sẽ xuất hiện; đây là hành vi đúng, không phải FP mới.

### 12.10. Ngày 2026-11-28: lượt chạy đầu hạng mục 11 trên VM (người dùng chạy) và sửa lỗi hiệu năng nạp

Quan sát (một Windows 10 VM, một lần; số liệu do người dùng chụp lại):

| Bước | Kết quả |
|---|---|
| V1 | Agent đọc ba kênh: `state` idle, ba kênh idle, `errors={}`; ba checkpoint riêng; lần đầu đọc lịch sử: Sysmon 9.173, Defender 314, PowerShell 313 sự kiện. `/health` agent `REPORTED`. DLQ 5 dòng (chưa biết thuộc kênh nào) |
| V2 | Script lành tính khoảng 50.000 ký tự chạy được. `Get-WinEvent`: các 4104 của cửa sổ thử có `ProcessId` **bằng `$PID`** của `powershell.exe` đó (3 sự kiện V3 cùng PID). Đây là quan sát đầu tiên ủng hộ giả định của `PID_IMAGE_LIFETIME` (mục 12.8); một lần, một VM. Chưa xem được nhãn nối trên DACN vì lỗi dưới |
| V3 | Dừng. Agent đã đọc 4104 của V3 (`events_written` 313 → 377), nhưng không có alert DET-203/204 mới; 6 kết quả DET-203 MATCH nhiều khả năng từ lịch sử log |

Nguyên nhân V3 (đo trên VM): core nạp quá chậm. `metrics.jsonl`: một vòng nạp 46 segment, 7.569 bản ghi trong **1.962 giây** (khoảng
3,9 bản ghi/giây), CPU-bound; hàng đợi 185–193 segment; Detection chỉ chạy sau khi nạp hết hàng đợi, và hàng đợi xếp theo tên nên
segment PowerShell/Defender (`seg-microsoft...`) đứng sau mọi segment Sysmon (`seg-2026...`). Profile trên bản sao Silver (khoảng 59.000
dòng lineage): segment Sysmon 500 bản ghi mất 209 giây (0,42 giây/bản ghi), thời gian nằm ở các lệnh DuckDB: `_insert` 0,27 giây/lệnh
và phần còn lại trong `ingest_segment` (INSERT lineage, commit); `checkpoint` chỉ 0,38 giây. Trên Linux cùng cỡ DB: 7,6 ms/bản ghi.
Vì sao mỗi lệnh DuckDB trên VM chậm như vậy **chưa rõ** (giả thuyết chưa kiểm: quét thời gian thực của Defender trên tệp DB/WAL,
đĩa của VM; không tắt hay thêm loại trừ Defender khi chưa có quyết định của người dùng). Lỗi có từ trước hạng mục 1–9 (chỉ Sysmon cũng
gặp); hai kênh mới và việc đọc lịch sử làm lộ rõ.

Sửa (người dùng yêu cầu "làm cả 1 và 2"):

| Thay đổi | Tệp |
|---|---|
| Nạp theo lô: adapter/validator từng bản ghi như cũ, rồi tra trùng một truy vấn mỗi bảng, INSERT nhiều dòng (tối đa 200 dòng/lệnh) cho bảng Silver và lineage. Số lệnh DuckDB mỗi segment không tăng theo số bản ghi (khoảng 10 thay vì khoảng 2 mỗi bản ghi). Ngữ nghĩa giữ nguyên: bản đầu tiên của một `event_id` được ghi, bản sau là duplicate hoặc `ERR_EVENT_ID_COLLISION` (kể cả trong cùng segment), DLQ như cũ, một transaction mỗi segment | `src/pipeline/silver_store.py` |
| `ingest_dir`: segment niêm phong sớm nhất trước (mtime, rồi tên); `max_seconds` tùy chọn, luôn nạp ít nhất một segment | `src/pipeline/silver_store.py` |
| Core: ngân sách nạp 20 giây mỗi vòng (`DEFAULT_INGEST_BUDGET_S`, chọn tay, chưa đo) rồi chạy Detection; `metrics.jsonl` và `/health` (`core.last_ingest`) có `pending_segments` | `src/core/service.py`, `src/pipeline/worker.py` |
| Test | `tests/pipeline/test_ingest_batching.py` (5), `tests/core/test_core_loop.py` (+1) |

Đo trên Linux (dữ liệu synthetic, DB khoảng 128.000 dòng lineage): 500 bản ghi từ 3,8 giây xuống 0,6 giây. **Chưa đo lại trên VM**;
nếu chi phí trên VM là theo lệnh, kỳ vọng giảm mạnh, nếu theo dòng thì giảm ít. Hướng dẫn mục 3 và 5 đã sửa: bỏ câu sai về niêm phong
300 giây (ở `--live` agent niêm phong cuối mỗi lượt đọc), chặn `$id` rỗng, xem `pending_segments`.

### 12.11. Ngày 2026-11-28: kết quả lượt chạy hạng mục 11 trên VM (sau bản sửa `208a713`)

Một Windows 10 VM, Defender bật (real-time, tamper protection), Sysmon v15.22, Script Block Logging bật; người dùng chạy **một lần**
theo `docs/implementation/acceptance/W8_DEFENDER_POWERSHELL_VM_GUIDE.md`; số liệu từ ảnh chụp và `w8_channel_report.py`
(`--since` = thời điểm bắt đầu V1). Đây là quan sát, không phải tỷ lệ phát hiện hay tỷ lệ FP.

| Mã | Kết quả | Bằng chứng |
|---|---|---|
| V1 | Đạt | Ba kênh idle, `errors={}`, ba checkpoint riêng; `/health` agent `REPORTED` |
| V2 | Đạt | Block dài ghép đủ: 554 script block, 33 nhiều phần, **554/554** có mặt trong `v_powershell_scriptblocks_complete` (không block thiếu phần). Nối tiến trình 4104: **548/554 `UNIQUE`**, ảnh ứng viên đều là `powershell.exe`; 6 `NONE`; `none_but_pid_has_other_image = 0` (không thấy PID nào thuộc ảnh khác). `Get-WinEvent`: `ProcessId` của 4104 = `$PID` của cửa sổ thử. Kích thước phần lớn nhất 19.452 ký tự (mẫu trước 17.651) |
| V3 | Đạt (trừ phần dashboard) | DET-203 MATCH dòng có `Invoke-Expression`, DET-204 MATCH dòng base64 (không MATCH DET-203). `/script`: `redacted=True`, luật `securestring_plaintext`, chuỗi giả không còn; viewer `reveal` → 403; analyst `reveal` thấy bản gốc; chi tiết alert không chứa chuỗi giả. Kiểm tra chữ "ĐÃ CHE" ra False vì lệnh gõ "DA CHE" không dấu (lỗi kiểm tra, không phải lỗi che). Audit: `SCRIPT_RAW_VIEW` = 1, tức nút xem bản gốc trên dashboard **chưa được bấm/chưa quan sát** |
| V4 | Đạt | EICAR qua SC05: Defender 1116 (Real-Time Protection, `file`) rồi 1117 `Quarantine`; một alert DET-201 (2 sự kiện), `source_label` Defender; evidence `FULL`, có `raw_xml` và tham chiếu Bronze. Nối tiến trình: `FILE_CREATE` **UNIQUE** (Sysmon có Event 11 cho tệp EICAR trong `dacn_lab`, trả lời câu hỏi mở của 6.3); `PROCESS_NAME_LIFETIME` AMBIGUOUS (6 ứng viên cùng ảnh) |
| V5 | Đạt (kỳ vọng tối thiểu) | A02: Defender chặn khi tạo tiến trình (`Access is denied`), `Trojan:Win32/Powessere.K` (`CmdLine`), DET-201 có, không có 4104 từ A02. A03: AMSI chặn khi phân tích cú pháp (`ScriptContainedMaliciousContent`), Defender `Trojan:PowerShell/Mimikatz.A` (`CmdLine`) và `Trojan:PowerShell/PSAttackTool.A` (`amsi`), DET-201 có; DET-203 không MATCH A03 (tên cmdlet không thuộc 9 mẫu, như dự kiến). `Resources` của mọi phát hiện không trỏ vào `C:\dacn_edr\` (giả thuyết "Defender quét tệp DACN" bị bác bỏ) |
| V6 | Đạt | 4104 phát sinh khi agent và core dừng (RecordId 914) có trong Silver sau khi chạy lại (`count = 1`). Event Log kể từ mốc: 4104 = 459 (đếm trước khi dừng), Silver = 465 (sau đó còn lệnh mới); Defender = 8, Silver = 8 |
| V7 | Đạt | Bronze: Sysmon chỉ `SYSMON` (63.994), PowerShell chỉ `POWERSHELL` (760), Defender chỉ `WINDOWS_DEFENDER` (322), `channel_mismatch = 0`; `open_part_files = 0`; ledger cân bằng ở cả ba kênh; DLQ 6 dòng đều `ERR_UNSUPPORTED_EVENT_ID` ở kênh **Sysmon** (0 ở kênh mới); `response_actions` rỗng; `alerts_with_process_guid_new_rules = 0` |

Phát hiện mới (chưa sửa, chờ người dùng quyết):
1. **Một phát hiện Defender bị tách thành hai alert DET-201.** `detection_id` `f21b…` (PSAttackTool, AMSI): 1116 lúc 02:38:55 và 1117 lúc
   02:40:27 (giờ VM) rơi vào hai khung `BUCKET_SECONDS = 600` cố định (`src/alerts/builder.py`), nên thành hai alert. Đề xuất: rule có
   `group_by_field` (Defender theo `detection_id`, PowerShell theo `script_block_id`) gom không theo khung thời gian.
2. **5 alert DET-203 từ `Import-Module invoke-atomicredteam`** (mẫu `net.webclient`, `reflection.assembly]::load`, `invoke-expression`;
   suy ra từ thời điểm, chưa đối chiếu `script_path`). Quan sát FP với công cụ quản trị/kiểm thử; DET-203 vốn ghi giới hạn này.
3. **5007 nhiễu:** 306 sự kiện 5007 trong Silver → 11 alert DET-202 `low` (gom theo khung 10 phút). Vẫn chờ quyết định loại trừ.
4. **Checkpoint DuckDB chậm trên VM**: một `checkpoint` sau khi nạp 500 bản ghi mất 124,88 giây (Linux dưới 1 giây); chưa thấy ảnh hưởng
   trong lượt chạy (hàng đợi về 0), nguyên nhân chưa rõ.
5. Hiệu năng sau bản sửa: segment 500 bản ghi 209 s → 7,2 s trên VM; khi chạy live mỗi vòng nạp 0,07–0,3 s, `pending_segments = 0`.

Kiểm tra chưa làm: một kênh thiếu quyền (`degraded`) trên VM; nút xem bản gốc trên dashboard; 5001/5013 (không có sự kiện).

### 12.12. Ngày 2026-11-28: sửa lỗi tách alert Defender (phát hiện 1 của mục 12.11, người dùng yêu cầu)

| Thay đổi | Tệp |
|---|---|
| Khóa gom alert: rule khai `group_by_field` và sự kiện có giá trị đó → `rule_id|host|<field>=<giá trị>`, **không** chia khung `BUCKET_SECONDS`. Chỉ áp dụng cho DET-201 (`detection_id`), DET-203/204 (`script_block_id`). Thiếu giá trị, hoặc rule không khai (DET-001..101, DET-202) → giữ khóa cũ có khung 10 phút | `src/alerts/builder.py` (`_group_key`) |
| `bump` cập nhật `first_seen_utc = least(...)`: outbox giao kết quả theo `dedup_key`, không theo thời gian, nên 1117 có thể được dựng trước 1116; trước đây alert giữ thời điểm của kết quả đến trước | `src/alerts/store.py` |
| 4 test: dựng lại trường hợp VM (1116 lúc 10:38:55Z, 1117 lúc 10:40:27Z, cùng Detection ID → 1 alert), 1117 xử lý trước vẫn giữ first_seen sớm nhất, hai Detection ID khác nhau không gộp, DET-202 vẫn chia khung | `tests/detection/test_defender_rules.py` |

Hệ quả cần biết: (i) khóa nhóm mới không khớp khóa cũ, nên alert đã tạo trước bản sửa không được gộp lại; 1117 đến sau bản sửa cho
một phát hiện có alert cũ sẽ thành alert mới (một lần). (ii) Cùng `ScriptBlockId` xuất hiện lại sau nhiều giờ (chạy lại cùng script,
chưa xác minh có xảy ra không) sẽ tăng `occurrence_count` của alert cũ thay vì tạo alert mới; nếu alert cũ đã đóng, lần chạy lại vẫn
gộp vào alert đã đóng (`find_group` không lọc trạng thái, như trước). (iii) Ghi chú cột `group_key` trong DDL v1.2 đề xuất
("rule_id|host|process_guid|bucket thời gian") không được sửa (không sửa DDL v1.1/v1.2), nên lệch với khóa mới của ba rule trên.
Kiểm thử: `python -m pytest -q` → 660 pass, 2 skipped, 0 fail (Linux). Chưa chạy lại trên VM.

### 12.13. Ngày 2026-11-28: DACN-DET-202 v2, giảm nhiễu 5007 (phát hiện 3 của mục 12.11, người dùng chọn cách B)

Thống kê 306 sự kiện 5007 thật trên VM (2026-11-23..28, 272 khóa; script chỉ đọc trên bản sao Silver, người dùng chạy): `Features\EcsConfigs` 120,
`Features\Controls\<số>` 99, `CoreService` (kể cả `MemorySensor`, `CpuSensor`, `DiskSensor`) 27, `Diagnostics` 15; khóa liên quan bảo vệ chỉ thấy
`Features\TamperProtection` (3 lần, bật lên) và `NIS\Consumers\IPS\DisableBmNetworkSensor` (0x0 → 0x1); không có thay đổi `Exclusions`
hay `DisableRealtimeMonitoring`; nhiều thay đổi không đổi giá trị (`0x0` → `0x0`).

| Thay đổi | Tệp |
|---|---|
| `rule_version` 2; thêm `exclude` regex trên `new_value`: loại trừ 5007 khi phần tên khóa (trước `=`) KHÔNG chứa `\Disable*` (tên giá trị), `\Exclusions\`, `\TamperProtection`, `\Spynet\SpynetReporting` hoặc `\Spynet\SubmitSamplesConsent`. Dùng điều kiện `exclude` có sẵn, không đổi rule model. 5001/5013 không có `New Value` nên không bị ảnh hưởng; 5007 có `New Value` rỗng (xóa khóa) vẫn ra alert | `src/detection/rules/dacn-det-202.yaml` |
| Test: 9 thay đổi nội bộ (hình dạng khóa thật) không ra alert; 7 thay đổi liên quan bảo vệ ra alert `low`; 5001 vẫn `high`. Hai test cũ dùng fixture 5007 khóa `Synthetic` chuyển sang khóa `TamperProtection` | `tests/detection/test_defender_rules.py` |

Ước tính trên 306 sự kiện (đếm tay từ top 30 khóa và nhóm khóa cha, không phải số đo lại): còn khoảng 5 kết quả 5007 (TamperProtection ×3,
DisableBmNetworkSensor ×2). Giới hạn: danh sách khóa là đề xuất của Software theo tên chính sách Defender, **chưa được Cyber xác nhận**;
khóa liên quan bảo vệ có tên khác bị bỏ sót; không xét hướng thay đổi (bật lại bảo vệ vẫn ra alert) và không bỏ thay đổi không đổi
giá trị (cách C, cần sửa evaluator, chưa làm). Đổi `rule_version` làm engine đánh giá lại toàn bộ; alert DET-202 v1 đã có vẫn giữ.
Kiểm thử: `python -m pytest -q` → 669 pass, 2 skipped, 0 fail (Linux). Chưa chạy trên VM.

### 12.14. Ngày 2026-11-28: DACN-DET-202 v3, lọc 5007 theo hướng thay đổi (cách C, người dùng yêu cầu)

| Thay đổi | Tệp |
|---|---|
| `classify_registry_change(old, new)` phân loại `NOOP` / `WEAKEN` / `STRENGTHEN` / `CHANGE` (None khi cả hai trống). Chỉ suy hướng ở chỗ tự rõ từ tên: giá trị `Disable*` là số (0 hoặc không có → khác 0 = WEAKEN; khác 0 → 0 hoặc xóa = STRENGTHEN), nhánh `\Exclusions\` (thêm hoặc đổi sang khóa khác = WEAKEN; xóa = STRENGTHEN). `TamperProtection`, `Spynet` và mọi khóa khác: `CHANGE` (ý nghĩa giá trị chưa kiểm chứng, không đoán) | `src/detection/registry_change.py` (mới) |
| Khóa rule mới `registry_change_filter: {old_field, new_field, drop}`; evaluator chạy sau `exclude`, lớp trong `drop` → NO_MATCH (`notes: registry_change:<lớp>`), MATCH ghi `matched_fields.registry_change`. Hàng không có cả hai trường (5001/5013) không bị lọc. **Thay đổi rule model**: quyết định triển khai chờ duyệt như `severity_by`/`context_fields`/`group_by_field` | `src/detection/schema.py`, `src/detection/evaluator.py`, `docs/architecture/w6/contracts/rule.schema.json` (xuất lại bằng `scripts/contracts/export_issue40_contracts.py`) |
| DET-202 `rule_version` 3: `registry_change_filter: {old_field: old_value, new_field: new_value, drop: [NOOP, STRENGTHEN]}`, giữ `exclude` của v2 | `src/detection/rules/dacn-det-202.yaml` |
| Test: 16 ca phân loại; 5 ca 5007 mạnh lên hoặc không đổi không ra alert (gồm xóa Exclusion, `DisableBmNetworkSensor` 1→0, so sánh không phân biệt hoa/thường); MATCH ghi lớp; ca xóa Exclusion của v2 (giữ alert thận trọng) đổi thành không alert | `tests/detection/test_defender_rules.py` |

Ước tính trên 306 sự kiện 5007 của VM (đếm tay từ thống kê ở 12.13, không phải đo lại): còn khoảng 4 kết quả (TamperProtection ×3 là
`CHANGE`, `NIS\Consumers\IPS\DisableBmNetworkSensor` 0x0 → 0x1 là `WEAKEN`; `Default\...\DisableBmNetworkSensor` 0x1 → 0x0 bị bỏ).
Giới hạn: hướng chỉ suy từ tên; một chính sách mà giá trị khác 0 nghĩa là bật bảo vệ nhưng tên bắt đầu bằng `Disable` sẽ bị phân loại
sai (chưa thấy trên dữ liệu); TamperProtection/Spynet đổi theo hướng nào cũng ra alert. Kiểm thử: `python -m pytest -q` → 690 pass,
2 skipped, 0 fail (Linux). Chưa chạy trên VM.

