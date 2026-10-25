# Windows Telemetry Catalogue v1

Ngày tổng hợp 2026-10-19. Nguồn đang dùng: Microsoft-Windows-Sysmon/Operational. Windows 10.0.19045, Sysmon 15.22; dữ liệu tại references/samples. Trạng thái chờ review liên nhóm.

| Nhóm | Event ID | Trường quan trọng | Mẫu thật hiện có | Giới hạn |
|---|---|---|---|---|
| Process start | 1 | ProcessGuid, Image, CommandLine, ParentProcessGuid, ParentImage, Hashes | 3 raw/JSON | Bộ mẫu chọn chưa gồm đủ mọi command của lần thử |
| Process terminate | 5 | ProcessGuid, ProcessId, Image, UtcTime | 1 XML | Không có parent hoặc nguyên nhân/actor kết thúc |
| File create | 11 | ProcessGuid, TargetFilename, Image | 2 raw/JSON | Không có hash/size; không bao phủ đầy đủ write/rename |
| File delete | 26 | ProcessGuid, TargetFilename, Hashes nếu có | 2 XML | Không dùng archive Event 23 trong config hiện tại |
| Executable created | 29 | ProcessGuid, TargetFilename và metadata nguồn | 1 XML | Không đại diện mọi loại file hoặc chứng minh malware |
| Registry key | 12 | EventType, TargetObject, ProcessGuid | 2 XML | Không có previous value |
| Registry value | 13 | EventType, TargetObject, Details | 2 raw/JSON | Native type chỉ suy diễn một phần |
| Network connect | 3 | ProcessGuid, source/destination IP/port, Initiated | 1 raw/JSON | Không bytes/duration/TLS content |
| DNS | 22 | ProcessGuid, QueryName, QueryResults | 1 XML | Không có socket fields; phải đối chiếu riêng |
| Sysmon state/config | 4,16 | State/Version hoặc Configuration/FileHash | Mỗi loại 1 XML | Chỉ quản trị Sysmon; không mọi Windows service |

ID 14/15 được code/config đề cập nhưng chưa có mẫu thật trong bộ này. Security 4688/4689, TaskScheduler, System service logs, ETW và WMI/API là nguồn khảo sát, chưa có bộ mẫu kiểm chứng ở đây.

[Manifest](../../../../references/samples/raw/export_manifest.json), [báo cáo lần chạy](../../../../references/samples/evidence/poc_run_20261018_021142.json), [schema](../../../architecture/w3/endpoint_event_schema_v1.md), [MITRE Matrix v2](../../cyber/mitre-detection-matrix-v2.md), [review](../../../project/week-01-03-review-and-ownership.md).
