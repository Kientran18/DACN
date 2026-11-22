# Telemetry Source Mapping Table

Ký hiệu độ phủ: **Full** = lấy trực tiếp · **Partial** = suy ra/làm giàu được nhưng có điều kiện · **Gap** = nguồn Phase 1 không cung cấp.
Mỗi bảng đối chiếu từng field **Required** trong `edr_data_requirements_architecture.md` (mục 2.1–2.4) với nguồn thực tế.

---

## A. Process telemetry

**Nguồn ứng viên:** Sysmon 1 / 5 (chính) · Security 4688 / 4689 (bổ sung) · psutil / Win32 API (làm giàu)

| Field (Data spec) | Sysmon | Độ phủ | Fallback / Ghi chú |
|---|---|---|---|
| `process_guid` | ProcessGuid | Full | Là GUID của Sysmon, **không phải** `UUIDv5(host_id,pid,start_time)` như spec — dùng giá trị Sysmon (xem câu hỏi Q-D1) |
| `pid`, `ppid` | ProcessId, ParentProcessId | Full | |
| `parent_guid` | ParentProcessGuid | Full | |
| `image_path`, `command_line`, `current_working_directory` | Image, CommandLine, CurrentDirectory | Full | |
| `user_name` | User | Full | Dạng `DOMAIN\user` |
| `user_sid` | — | Partial | Resolve từ User bằng `LookupAccountName`, hoặc lấy `SubjectUserSid` từ 4688 |
| `integrity_level` | IntegrityLevel | Full | Giá trị chữ (Low/Medium/High/System) → map về enum của Data |
| `token_elevation_type` | — | **Gap** | 4688 có `TokenElevationType` (enum khớp DEFAULT/FULL/LIMITED); join với Sysmon 1 theo (PID + thời gian ±1s) — không có GUID chung |
| `session_id`, `terminal_session_id` | TerminalSessionId | Full | |
| `start_time` | UtcTime | Partial | Độ phân giải mili-giây; dùng `TimeCreated/@SystemTime` (100 ns) trong XML nếu cần ns |
| `end_time` | Event 5 UtcTime | Full | Cập nhật bản ghi cũ theo `process_guid` |
| `exit_code` | — | **Gap** (Optional) | 4689 `Status`; hoặc ETW Kernel-Process (Phase 2) |
| `is_wow64` | — | **Gap** | Suy từ `\SysWOW64\` hoặc `IsWow64Process2` (chỉ khi process còn sống) |
| `hashes` | Hashes | Full | **Phụ thuộc config:** phải bật `HashAlgorithms` gồm SHA256 (+MD5, SHA1, IMPHASH) |

## B. File telemetry

**Nguồn ứng viên:** Sysmon 11 / 23 hoặc 26 / 15 / 29 (chính) · ETW Kernel-File (Phase 2) · `os.stat` / Win32 (làm giàu)

| Field (Data spec) | Sysmon | Độ phủ | Fallback / Ghi chú |
|---|---|---|---|
| `process_guid` | ProcessGuid | Full | |
| `operation` = `CREATE` | Event 11 | Full | 11 gồm cả tạo mới và **ghi đè** |
| `operation` = `DELETE` | Event 23 / 26 | Full | |
| `operation` = `WRITE` / `MODIFY` / `READ` / `RENAME` | — | **Gap** | Sysmon không có. Cần ETW Kernel-File (hoặc minifilter — ngoài phạm vi) |
| `file_path` | TargetFilename | Full | |
| `canonical_path` | — | Partial | `os.path.realpath` nếu file còn tồn tại; nếu không dùng `file_path` |
| `previous_file_path` | — | **Gap** | Chỉ có khi có sự kiện rename |
| `file_size_bytes` | — | **Gap** | `os.stat` tại thời điểm xử lý (race); NULL nếu file đã mất |
| `byte_delta` | — | **Gap** | Cần ETW/minifilter |
| `chunk_entropy` | — | **Gap** | Pipeline tự tính từ nội dung file (race); với file bị xóa có thể đọc bản archive của Event 23 |
| `is_directory` | — | Partial | Sysmon chỉ log file → mặc định `false` |
| `share_name` | — | Partial | Suy từ tiền tố UNC `\\server\share` trong `file_path` |
| `file_attributes`, `hard_link_count` | — | **Gap** | `GetFileAttributesW` / `GetFileInformationByHandle` (race) |

**Event bổ sung:** 15 (Zone.Identifier/MOTW + hash), 29 (PE mới tạo) — phục vụ T1204.002 và T1105.

## C. Registry telemetry

**Nguồn ứng viên:** Sysmon 12 / 13 / 14 (chính) · `winreg` snapshot (đối chiếu) · Security 4657 (chỉ cho key đặt SACL)

| Field (Data spec) | Sysmon | Độ phủ | Fallback / Ghi chú |
|---|---|---|---|
| `process_guid` | ProcessGuid | Full | |
| `operation` | EventType: CreateKey/DeleteKey/DeleteValue (ID 12), SetValue (ID 13), RenameKey (ID 14) | Full | Map `SetValue→VALUE_SET`, `DeleteValue→VALUE_DELETE`; `RenameKey` chưa có trong enum của Data |
| `hive`, `key_path` | TargetObject | Full | Tách tiền tố (`HKLM\`, `HKU\<SID>\`) bằng pipeline; Sysmon quy HKCU về `HKU\<SID>` |
| `value_name` | TargetObject (đoạn cuối) | Partial | Với SetValue, đoạn cuối của đường dẫn là tên value |
| `value_type` | Details | Partial | `DWORD (0x…)` → REG_DWORD, `QWORD (…)` → REG_QWORD, `Binary Data` → REG_BINARY; chuỗi thường **không phân biệt được** SZ/EXPAND_SZ/MULTI_SZ |
| `new_data_str` | Details | Full (chuỗi) | |
| `new_data_bytes` | Details | **Gap** | Chỉ ghi nhãn "Binary Data", không có nội dung |
| `previous_data_*` | — | **Gap** | Sysmon không log giá trị cũ |
| `status_code` | — | **Gap** | Sysmon chỉ ghi thao tác thành công → gán hằng `0` hoặc NULL |

**Lưu ý config:** Sysmon **chỉ log registry khớp rule** trong XML — phải liệt kê Run/RunOnce, Winlogon, `Schedule\TaskCache`, Services… (do Cyber chốt danh sách).

## D. Network telemetry

**Nguồn ứng viên:** Sysmon 3 / 22 (chính) · Security 5156 (đối chiếu) · `psutil.net_connections` (snapshot) · ETW Kernel-Network (Phase 2)

| Field (Data spec) | Sysmon | Độ phủ | Fallback / Ghi chú |
|---|---|---|---|
| `process_guid` | ProcessGuid | Full | |
| `ip_version` | SourceIsIpv6 / DestinationIsIpv6 | Full | |
| `protocol` | Protocol | Full | tcp / udp |
| `direction` | Initiated | Partial | `true→OUTBOUND`, `false→INBOUND`; **`LISTEN` không có** (Sysmon không log bind) — dùng psutil snapshot |
| `src_ip/port`, `dest_ip/port` | SourceIp/Port, DestinationIp/Port | Full | |
| `connection_state` | — | **Gap** | psutil snapshot (đúng thời điểm poll); hoặc hằng `ESTABLISHED` cho mọi Event 3 (cần Data chấp thuận) |
| `dns_query_name` | Event 22 QueryName | Partial | Correlate: cùng `process_guid`, thời gian gần, và `dest_ip` nằm trong QueryResults |
| `tls_sni` | — | **Gap** | Cần phân tích gói tin → ngoài phạm vi |
| `bytes_sent`, `bytes_received`, `duration_ms` | — | **Gap** | ETW Kernel-Network (Phase 2); NIC counter không theo process |

---

## E. Độ phủ theo 13 kỹ thuật MITRE của Cyber

| # | Kỹ thuật | Nguồn chính | Nguồn bổ sung | Độ phủ | Nhận xét |
|---|---|---|---|---|---|
| 1 | T1204.002 | Sysmon 11, 1 | Sysmon 15 (MOTW), 29 | **Full** | |
| 2 | T1059.001 | Sysmon 1, 3 | PowerShell 4104 (Phase 2) | **Full** | Command line đủ để bắt `-enc`, `-w hidden` |
| 3 | T1059.003 | Sysmon 1 | — | **Full** | Dựa vào `ParentImage` |
| 4 | T1218 | Sysmon 1 | Sysmon 7 (tùy chọn, nhiều noise) | **Full** | |
| 5 | T1547.001 | Sysmon 13 (12) | `winreg` snapshot | **Full** | Phụ thuộc rule registry trong config |
| 6 | T1053.005 | Sysmon 1 (`schtasks.exe`) | TaskScheduler/Operational 106; registry `TaskCache`; Security 4698 | **Partial** | Task tạo qua API/COM không sinh `schtasks.exe` |
| 7 | T1562.001 | Sysmon 5 | Sysmon 4, 16; System 7036/7045; Security 1102 | **Partial** | Sysmon 5 một mình không đủ; collector của chính ta không được bảo vệ |
| 8 | T1082 | Sysmon 1 | — | **Full** | Chủ yếu là AI/feature (chuỗi lệnh liên tiếp) |
| 9 | T1083 | Sysmon 1 | ETW Kernel-File (Phase 2) | **Partial** | Chỉ thấy liệt kê qua lệnh; liệt kê bằng API và READ không thấy |
| 10 | T1105 | Sysmon 3, 11 | Sysmon 22, 29 | **Full** | Correlate theo `process_guid` + khoảng thời gian |
| 11 | T1071.001 | Sysmon 3, 22 | — | **Partial** | Không có bytes/duration/SNI; beaconing chỉ suy từ timestamp + dest |
| 12 | T1070.004 | Sysmon 11, 1, 23 | — | **Full** | Cần chốt 23 (archive) hay 26 |
| 13 | T1486 | Sysmon 11, 23 | ETW Kernel-File (Phase 2) | **Partial / yếu** | Không có write-in-place và rename; chỉ bắt được ransomware kiểu tạo file mới + xóa file cũ (tín hiệu = tốc độ Event 11 + 23, đa dạng extension) |

**Tổng:** 8 Full · 5 Partial (T1053.005, T1562.001, T1083, T1071.001, T1486).

---

## F. Ánh xạ kiến trúc enterprise → nguồn Phase 1

| Data spec §4.1 (enterprise) | Phase 1 thay bằng | Mất gì khi down-scale |
|---|---|---|
| `PsSetCreateProcessNotifyRoutineEx` + Kernel-Process ETW | Sysmon 1 / 5 | Không chặn đồng bộ, không có exit code/elevation gốc |
| Minifilter `IRP_MJ_CREATE/WRITE/SET_INFORMATION` | Sysmon 11 / 23 | Mất WRITE, RENAME, byte_delta, chunk entropy realtime |
| `CmRegisterCallbackEx` | Sysmon 12 / 13 / 14 | Mất giá trị cũ, status code, nội dung binary |
| WFP ALE layers | Sysmon 3 / 22 | Mất bytes, duration, state, SNI |
| Userland PE parser | `pefile` trong pipeline | Không đổi |

---

## G. Độ phủ theo 10 Detection Rule của Cyber (DET-001 đến DET-010)

Telemetry yêu cầu lấy từ `security_telemetry_v1.md` (bảng Telemetry Mapping) và `initial_detection_notes.md`.

| DET | Rule | Telemetry Cyber yêu cầu | Nguồn Phase 1 | Độ phủ | Ghi chú |
|---|---|---|---|---|---|
| 001 | Suspicious PowerShell | Process, parent process, command line | Sysmon 1 (`ParentImage`, `CommandLine`) | **Full** | Cần cột `parent_image` trong Silver (Q-D6) |
| 002 | Suspicious CMD | Process, parent process, command line | Sysmon 1 | **Full** | Như DET-001 |
| 003 | Run Key Persistence | Registry, process, target path | Sysmon 13 (`Details` chứa đường dẫn đích) + Sysmon 1 | **Full** | Chỉ với key nằm trong rule config (Q-C3); "unknown executable" cần hash/whitelist |
| 004 | Scheduled Task Persistence | Scheduled task event, process, command line, user, exe path | Sysmon 1 (`schtasks.exe`), Sysmon 12/13 (`TaskCache`); TaskScheduler 106 (backlog) | **Partial** | Task tạo qua COM chỉ thấy qua registry; chưa có bảng Silver cho task events (Q-X1) |
| 005 | Suspicious Tool Download | Process, network, destination, file creation, hash | Sysmon 1, 3, 22, 11, **29** | **Full** | Hash lúc tạo file lấy từ Event 29/15, không có ở Event 11; correlate theo `process_guid` + khoảng thời gian |
| 006 | Possible C2 | Process, network, DNS | Sysmon 3, 22 | **Partial** | Chỉ tần suất theo `(process_guid, dest_ip, dest_port)`; không có bytes/duration/SNI |
| 007 | Agent Tampering | Process termination, service events, heartbeat | Sysmon 5, 4, 16; System 7036/7045; Security 1102; heartbeat của watchdog | **Partial** | Chưa có bảng Silver cho service events và heartbeat (Q-X1); thiết kế watchdog ở TR-05 |
| 008 | Ransomware-like File Activity | Process, file write / rename / delete, extension, timestamp | Sysmon 11, 23/26 | **Partial (yếu)** | Không có write/rename; định nghĩa lại ở Q-C1 |
| 009 | Suspicious Discovery Chain | Process, parent process, command line | Sysmon 1 | **Full (qua lệnh)** | Liệt kê thư mục bằng API không để lại sự kiện |
| 010 | Drop → Execute → Delete | File create, process execution, file delete, hash, timestamp | Sysmon 11, 1, 23/26 | **Full** | Khóa nối `file_path` = `image_path`; hash từ Event 1 và 23/26 |

**Tổng:** 6 Full (001, 002, 003, 005, 009, 010) · 4 Partial (004, 006, 007, 008).

## H. Bảng quy đổi event type (đề xuất, chờ Q-X3)

Ba hệ thống đang dùng ba bộ tên khác nhau. Cột "Data envelope" lấy từ `edr_data_requirements_architecture.md` §3.1.

| Nguồn Phase 1 | Cyber (`security_telemetry_v1.md`) | Data envelope | Bảng Silver | Ghi chú |
|---|---|---|---|---|
| Sysmon 1 | `PROCESS_CREATE` | `PROCESS_START` | `silver_process_events` | |
| Sysmon 5 | `PROCESS_TERMINATE` | `PROCESS_TERMINATE` | `silver_process_events` | Cập nhật `end_time` |
| Sysmon 11 | `FILE_CREATE` | `FILE_CREATE` | `silver_file_events` | Gồm cả ghi đè |
| Sysmon 23 / 26 | `FILE_DELETE` | `FILE_DELETE` | `silver_file_events` | |
| *không có nguồn* | `FILE_WRITE` | `FILE_WRITE` | — | Cả hai bên đều liệt kê, Phase 1 không thu được |
| *không có nguồn* | `FILE_RENAME` | `FILE_RENAME` | — | Như trên |
| Sysmon 13 | `REGISTRY_SET` | `REGISTRY_SET_VALUE` | `silver_registry_events` | |
| Sysmon 12 (DeleteValue) | `REGISTRY_DELETE` | `REGISTRY_DELETE_VALUE` | `silver_registry_events` | |
| Sysmon 12 (CreateKey) | — | `REGISTRY_CREATE_KEY` | `silver_registry_events` | |
| Sysmon 12 (DeleteKey), 14 (RenameKey) | — | *không có trong enum* | `silver_registry_events` | Enum của Data thiếu, dù Group 3 có `KEY_DELETE` |
| Sysmon 3 (`Initiated=true`) | `NETWORK_CONNECT` | `NETWORK_CONNECT` | `silver_network_events` | |
| Sysmon 3 (`Initiated=false`) | `NETWORK_CONNECT` | `NETWORK_ACCEPT` | `silver_network_events` | |
| Sysmon 22 | `DNS_QUERY` | `DNS_QUERY` | `silver_network_events` | Bổ sung cho Event 3 |
| Sysmon 7 | `IMAGE_LOAD` | *không có trong enum* | — | Chưa bật (nhiều noise) |
| TaskScheduler 106; Sysmon 12/13 `TaskCache` | `TASK_CREATE`, `TASK_UPDATE` | *không có trong enum* | — | Q-X1 |
| System 7036/7045; Sysmon 4 | `SERVICE_START`, `SERVICE_STOP`, `SERVICE_CHANGE` | *không có trong enum* | — | Q-X1 |

**`source` đề xuất bổ sung** vào enum của Data: `SYSMON`, `WINDOWS_SECURITY_LOG`, `PSUTIL_SNAPSHOT`, `COLLECTOR_INTERNAL` (cho heartbeat và cảnh báo mất dữ liệu).
