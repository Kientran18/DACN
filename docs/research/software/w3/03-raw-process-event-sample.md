# Raw Process Event Sample (Sysmon Event 1, 5)

**Trạng thái: ĐÃ CÓ MẪU THẬT.** Xem [XML đã commit](../../../../references/samples/raw/raw_process_create_event1.xml) và [index](00-index-and-dod.md). Các bảng kiểm tra cần reviewer xác nhận; không coi placeholder bên dưới là dữ liệu. Chạy bước 1 và 2 của `run-poc-activities.ps1`, rồi `export-samples.ps1`. File nguồn: `samples/raw/raw_process_create_event1.xml`, `raw_process_terminate_event5.xml`.

## Lệnh thu thập nhanh (Admin)
```powershell
wevtutil qe Microsoft-Windows-Sysmon/Operational /q:"*[System[(EventID=1)]]" /c:5 /rd:true /f:xml
```

## Mẫu thật – Event 1 (dán vào đây)
```xml
<!-- Xem file XML đã liên kết ở đầu trang; không sao chép mẫu giả vào đây.
```

## Mẫu thật – Event 5
```xml
<!-- Xem file XML đã liên kết ở đầu trang; không sao chép mẫu giả vào đây.
```

## Kiểm tra từng trường (đánh dấu sau khi xem mẫu thật)

| Trường Sysmon | Trường PoC / Silver | Silver hiện có (báo cáo Tuần 1)? | Có trong mẫu? | Ghi chú cần kiểm tra |
|---|---|---|---|---|
| ProcessGuid | `process_guid` | Có | ☐ | Định dạng GUID có ngoặc nhọn; có phải UUIDv4 không (Q-D1) |
| ProcessId / ParentProcessId | `pid` / `ppid` | Có | ☐ | |
| ParentProcessGuid | `parent_guid` | Có | ☐ | |
| Image, CommandLine, CurrentDirectory | `image_path`, `command_line`, `current_working_directory` | Có | ☐ | Command line có marker không |
| User | `user_name` | Có | ☐ | Dạng `HOST\user`? |
| Hashes | `file_sha256` | Có (`file_sha256`) | ☐ | Có SHA256 **và** IMPHASH không |
| ParentImage, ParentCommandLine | `parent_image`, `parent_command_line` | **Chưa có** (Q-D6) | ☐ | DET-001/002 cần `parent_image` |
| IntegrityLevel, TerminalSessionId | `integrity_level`, `session_id` | **Chưa có** | ☐ | |
| Event 5: UtcTime, ProcessGuid, Image | `end_time` | **Chưa có** | ☐ | Event 5 có `ExitCode` không? (dự kiến không) |
| `TimeCreated/@SystemTime` so với `UtcTime` | `timestamp` | — | ☐ | Độ phân giải 100 ns so với mili-giây |

## Câu hỏi cần trả lời từ mẫu
1. `token_elevation_type`, `exit_code`, `is_wow64`, `user_sid` có xuất hiện không (dự kiến: không)?
2. `ParentImage` của `cmd.exe` là `powershell.exe` như mong đợi?
3. Event 1 cho `powershell.exe` con (bước 2b) có `ParentProcessGuid` trỏ đúng về PowerShell chạy script?
