# Windows Telemetry Sources v1

**Phạm vi:** Phase 1 – Local EDR trên 1 Windows endpoint (Software role)
**Căn cứ:** `edr_data_requirements_architecture.md`, `sysmon_to_silver_schema_mapping.md`, `week2_behavior_telemetry_mapping.md` (13 kỹ thuật MITRE của Cyber)
**Thay thế:** bản v1 trước đó (bản đó chưa đối chiếu với tài liệu của Data và có 2 chỗ chưa chính xác — xem mục 6)

---

## 1. Tóm tắt vai trò từng nguồn trong Phase 1

| Nguồn | Vai trò | Lý do ngắn gọn |
|---|---|---|
| **Sysmon (v15+)** | **Nguồn chính** cho cả 4 nhóm | Đã có ProcessGuid, parent GUID, hash, command line; Data đã xây Silver schema và nạp dữ liệu thật từ Sysmon |
| **Windows Event Log – kênh Security/System** | **Bổ sung có chọn lọc** | Lấp các trường Sysmon không có (token elevation, exit code, SID) và các sự kiện tamper/service |
| **ETW** | **Nghiên cứu cho Phase 2** | Là nguồn duy nhất có write/rename/byte count/bytes sent-received, nhưng chi phí triển khai cao |
| **WMI / Windows API (psutil, pywin32)** | **Làm giàu tại thời điểm xử lý (enrichment) + snapshot** | Lấy trạng thái socket, file attributes, token info; không phải nguồn sự kiện liên tục |

Nguyên tắc: **Sysmon trả lời "cái gì đã xảy ra"; các nguồn còn lại chỉ bổ sung trường còn thiếu hoặc đối chiếu.**

---

## 2. Windows Event Log

**Bản chất:** hạ tầng log gốc của Windows, chia theo *channel*. Phần liên quan đến đề tài:

| Channel | Event | Dùng cho | Điều kiện bật |
|---|---|---|---|
| `Microsoft-Windows-Sysmon/Operational` | Sysmon 1, 3, 5, 11, 12–14, 22, 23… | **Kênh chính mà collector đọc** | Cài Sysmon + config |
| Security | 4688 / 4689 (process create / exit) | `token_elevation_type`, `exit_code`, `user_sid` | Audit Process Creation; thêm GPO *Include command line in process creation events* (`ProcessCreationIncludeCmdLine_Enabled=1`) nếu cần command line |
| Security | 5156 / 5157 (WFP connection allowed / blocked) | Đối chiếu network: có PID, đường dẫn app, direction, protocol | Audit Filtering Platform Connection — **volume rất lớn** |
| Security | 4663 / 4657 (object / registry access) | Chỉ cho đường dẫn/key đã đặt SACL | Phải đặt SACL từng đối tượng |
| Security | 1102; System 104 | Phát hiện xóa log (T1562) | Mặc định có |
| System | 7036 / 7040 / 7045 (service state / start type / new service) | Phát hiện tắt service (T1562.001) | Mặc định có |
| `Microsoft-Windows-TaskScheduler/Operational` | 106 (task registered) | Bổ sung T1053.005 | Channel mặc định **tắt**, cần enable |
| `Microsoft-Windows-PowerShell/Operational` | 4104 (script block) | Giải mã payload PowerShell (T1059.001) – ứng viên Phase 2 | Cần bật Script Block Logging |

**Cách đọc từ Python:** `pywin32` – `win32evtlog.EvtSubscribe` (push, có callback, phù hợp live) hoặc `EvtQuery` (pull theo query), `EvtRender` ra XML rồi parse bằng `xml.etree` (đúng hướng Data đang dùng). Dùng **bookmark** (`EvtCreateBookmark`) để không mất/lặp sự kiện khi collector khởi động lại.

**Quyền:** đọc Security và Sysmon channel thường cần quyền Administrator (hoặc cấp quyền đọc channel cho tài khoản chạy collector).

---

## 3. Sysmon

**Bản chất:** driver + service của Sysinternals, ghi sự kiện đã làm giàu vào channel Sysmon/Operational. Từ **v15** Sysmon chạy ở dạng protected process và có thêm Event 29 (FileExecutableDetected). Cần ghim phiên bản cụ thể trong `environment-log.md` (kiểm tra bản mới nhất trên trang Sysinternals trước khi chốt).

**Sự kiện cần cho Phase 1 (khớp danh sách Data yêu cầu + 4 bổ sung):**

| ID | Tên | Dùng cho | Trường chính |
|---|---|---|---|
| 1 | Process Create | Process | ProcessGuid, ProcessId, Image, CommandLine, CurrentDirectory, User, LogonId, TerminalSessionId, IntegrityLevel, Hashes, ParentProcessGuid, ParentProcessId, ParentImage, ParentCommandLine |
| 5 | Process Terminate | Process (`end_time`) | UtcTime, ProcessGuid, Image |
| 3 | Network Connect | Network | ProcessGuid, Protocol, Initiated, SourceIp/Port, DestinationIp/Port, SourceIsIpv6 |
| 22 | DNS Query | Network (`dns_query_name`) | ProcessGuid, QueryName, QueryStatus, QueryResults |
| 11 | File Create (tạo mới hoặc ghi đè) | File | ProcessGuid, Image, TargetFilename, CreationUtcTime |
| 23 | File Delete (có lưu bản archive) | File | ProcessGuid, TargetFilename, Hashes, IsExecutable, Archived |
| 26 | File Delete Detected (chỉ log, không archive) | File — lựa chọn thay cho 23 | tương tự 23 |
| 12 | Registry create/delete key | Registry | EventType, ProcessGuid, TargetObject |
| 13 | Registry set value | Registry | EventType, ProcessGuid, TargetObject, Details |
| 14 | Registry rename key/value | Registry | EventType, ProcessGuid, TargetObject, NewName |
| **15** | File stream created (+ hash) | *Bổ sung:* Zone.Identifier / Mark-of-the-Web cho T1204.002 | TargetFilename, Hash |
| **29** | File Executable Detected (v15+) | *Bổ sung:* PE mới tạo — hỗ trợ T1204.002, T1105 | TargetFilename, Hashes |
| **4** | Sysmon service state change | *Bổ sung:* tamper — T1562.001 | State |
| **16** | Sysmon config change | *Bổ sung:* tamper — T1562.001 | Configuration |

**Điểm mạnh:** event-driven, có GUID chống PID reuse, lọc bằng XML config (include/exclude) trước khi ghi log.
**Điểm yếu:** không có write/rename/read file, không có byte count/duration/TCP state, không có giá trị trước khi sửa registry — chi tiết ở file 02 và 04.

---

## 4. ETW (mức tổng quan)

**Bản chất:** hạ tầng tracing của kernel. Các provider liên quan:

| Provider | Có thể cung cấp thêm so với Sysmon |
|---|---|
| `Microsoft-Windows-Kernel-Process` | Process start/stop kèm **exit code** |
| `Microsoft-Windows-Kernel-File` | **Write, Rename, SetInformation, Read** → `WRITE`/`MODIFY`/`RENAME`/`byte_delta` |
| `Microsoft-Windows-Kernel-Registry` | Sự kiện registry ở mức kernel (cần PoC để xác nhận mức chi tiết dữ liệu giá trị) |
| `Microsoft-Windows-Kernel-Network` | Gửi/nhận theo socket kèm **kích thước** → `bytes_sent`/`bytes_received` |
| `Microsoft-Windows-DNS-Client` | DNS query ở mức client |

**Cách tiêu thụ:** tạo real-time trace session (cần Administrator) bằng `logman`/`tracerpt` để thử nhanh, hoặc thư viện (ví dụ `pywintrace`) để tích hợp Python. Phải tự parse payload theo manifest, xử lý mất sự kiện khi buffer đầy, và lọc volume rất lớn (đặc biệt File).
Provider `Microsoft-Windows-Threat-Intelligence` chỉ cho process được bảo vệ kiểu antimalware (PPL) → **không khả thi** với dự án này.

**Kết luận Phase 1:** chỉ khảo sát. Đề xuất **một research spike ngắn (1–2 ngày)** bằng `logman` + Kernel-File để chứng minh có thể lấy rename/write cho T1486; kết quả quyết định có đưa vào Phase 2 hay không.

---

## 5. WMI / Windows API (mức tổng quan)

| Cơ chế | Cho gì | Dùng trong dự án để |
|---|---|---|
| `psutil.process_iter` / WMI `Win32_Process` | Snapshot tiến trình: pid, ppid, exe, cmdline, create_time, username | Đối chiếu; không bắt được tiến trình sống ngắn |
| `psutil.net_connections` (GetExtendedTcpTable) | Socket hiện tại + **status** (ESTABLISHED, LISTEN…) + PID | Lấp `connection_state`, `LISTEN` ở dạng snapshot |
| WMI event (`Win32_ProcessStartTrace`) | Sự kiện tạo process (không có command line) | **Không dùng** — kém Sysmon, có thể mất sự kiện |
| `GetTokenInformation` (pywin32) | `TokenElevationType`, integrity level | Làm giàu `token_elevation_type` — chỉ khi process còn sống |
| `IsWow64Process2` | Kiến trúc process | Làm giàu `is_wow64` |
| `os.stat`, `GetFileAttributesW`, `GetFileInformationByHandle` | Kích thước, attributes, hard-link count | Làm giàu `file_size_bytes`, `file_attributes`, `hard_link_count` — **có race condition** (file có thể đã bị xóa) |
| `pefile`, Authenticode | Metadata PE, chữ ký | Static analysis (module riêng) |

WMI event subscription cũng là kỹ thuật persistence của kẻ tấn công (Sysmon 19/20/21 theo dõi được) — không nên dùng WMI subscription làm cơ chế giám sát chính.

---

## 6. Hiệu chỉnh so với bản v1 trước

1. v1 ghi *"Sysmon không có tamper-protection mặc định"* → **chưa chính xác với Sysmon 15+**, chạy ở dạng protected process nên khó bị kill hơn. Quản trị viên vẫn có thể gỡ/đổi config; hai hành vi đó được ghi bởi Sysmon Event 4 và 16 (đã đưa vào danh sách bổ sung ở mục 3).
2. v1 ghi *Firewall 5156 không gắn với process* → **sai**: 5156 có PID và đường dẫn ứng dụng, chỉ thiếu GUID nên vẫn có rủi ro PID reuse.
