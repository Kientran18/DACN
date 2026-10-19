# W03 Cyber — Sysmon / Windows Event Reference v1

Issue #14. Trạng thái 'Có mẫu' nghĩa là đã có XML thực tế, không phải đã kiểm thử detection.

| Nguồn | Event ID | Ý nghĩa | Trường quan trọng | Trạng thái |
|---|---|---|---|---|
| Sysmon | 1 | Process Create | ProcessGuid, Image, CommandLine, ParentImage, ParentProcessGuid, Hashes | Có mẫu |
| Sysmon | 5 | Process Terminate | ProcessGuid, ProcessId, Image, UtcTime | Có mẫu |
| Sysmon | 3 | Network Connect | ProcessGuid, Protocol, Initiated, SourceIp, DestinationIp, DestinationPort | Có mẫu |
| Sysmon | 11 | File Create | ProcessGuid, Image, TargetFilename, CreationUtcTime | Có mẫu |
| Sysmon | 12 | Registry Create/Delete | EventType, TargetObject, ProcessGuid, Image | Có mẫu |
| Sysmon | 13 | Registry Set Value | EventType, TargetObject, Details, ProcessGuid | Có mẫu |
| Sysmon | 14 | Registry Rename | TargetObject, NewName, ProcessGuid | Chưa có mẫu |
| Sysmon | 15 | File Create Stream Hash | TargetFilename, Hash, Contents | Chưa có mẫu |
| Sysmon | 22 | DNS Query | QueryName, QueryResults, QueryStatus, ProcessGuid | Có mẫu |
| Sysmon | 26 | File Delete Detected | TargetFilename, Hashes, IsExecutable, ProcessGuid | Có mẫu |
| Sysmon | 29 | File Executable Detected | TargetFilename, Hashes, ProcessGuid | Có mẫu |
| Sysmon | 4 | Service State | State, Version | Có mẫu |
| Sysmon | 16 | Configuration Change | Configuration, ConfigurationFileHash | Có mẫu |
| Sysmon | 7 | Image Load | Image, ImageLoaded, Signed, Hashes | Chưa bật |
| Sysmon | 10 | Process Access | SourceImage, TargetImage, GrantedAccess | Chưa bật |
| Windows Security | 4688 | Process Creation | NewProcessName, CommandLine, CreatorProcessId | Chưa thu |
| Windows Security | 4689 | Process Termination | ProcessId, ProcessName, ExitStatus | Chưa thu |
| Windows Security | 4698/4702 | Scheduled Task Create/Update | TaskName, TaskContent | Chưa thu |
| PowerShell Operational | 4104 | Script Block | ScriptBlockText, ScriptBlockId | Chưa thu |
| Windows System | 7036/7040 | Service State/Startup Change | ServiceName, State/StartType | Chưa thu |

Windows audit/PowerShell logging phải được bật và xác minh trước khi dựa vào các event ngoài Sysmon.

## Quy tắc sử dụng

1. Dùng `(hostname, process_guid)` để nối sự kiện; PID có thể tái sử dụng.
2. Sysmon 11 không ghi toàn bộ thao tác write, append, rename, read; không dùng làm bằng chứng chắc chắn cho ransomware.
3. Sysmon 3/22 chỉ cung cấp metadata kết nối/DNS; không có HTTPS payload, SNI, bytes, duration hay xác nhận C2.
4. Sysmon 26 trong mẫu có `Hashes` và `IsExecutable`; không bắt buộc bật Event 23 chỉ để lấy hash.
5. Event 4/16 không có `ProcessGuid` nên không được ép theo schema event gắn tiến trình.

Tham khảo: https://learn.microsoft.com/en-us/sysinternals/downloads/sysmon và https://attack.mitre.org/
