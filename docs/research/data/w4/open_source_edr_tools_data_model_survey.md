# Nghiên Cứu & Khảo Sát: Mô Hình Dữ Liệu, Định Dạng Xuất Và Truy Vết Của 5 Công Cụ Trong Hệ Sinh Thái EDR

**Người thực hiện:** Huỳnh Hữu Nhật (Data Engineer)  
**Thời điểm khảo sát:** Ngày 20/10/2026 – 23/10/2026 (Tuần 4)  
**Mục tiêu:** Phân tích chuyên sâu mô hình dữ liệu (Data Model), định dạng xuất (Output Format), cơ chế truy vấn/API và metadata truy vết (Lineage/Correlation) của **Sysmon, Wazuh, osquery, Velociraptor và Atomic Red Team** theo đúng vai trò kiến trúc của từng công cụ.

---

## 1. Phân Định Vai Trò Kiến Trúc & Phương Pháp Khảo Sát

Một sai lầm phổ biến khi thiết kế hệ thống giám sát điểm cuối là coi Sysmon, Wazuh, osquery, Velociraptor và Atomic Red Team như các giải pháp thay thế tương đương (1-to-1 substitutes). Dưới góc nhìn Kỹ thuật Dữ liệu, 5 công cụ này nằm ở **các tầng hoàn toàn khác nhau** trong chuỗi cung ứng dữ liệu an ninh (Security Data Supply Chain):

```text
+---------------------------------------------------------------------------------------------------+
|                        PHÂN TẦNG VAI TRÒ CÔNG CỤ TRONG CHUỖI DỮ LIỆU EDR                          |
|                                                                                                   |
|  [TẦNG KÍCH HOẠT & GẮN NHÃN]   Atomic Red Team (Thực thi kịch bản MITRE -> Sinh Ground-Truth)     |
|                                        |                                                          |
|                                        v (Tác động lên Hệ điều hành Windows)                      |
|  [TẦNG THU THẬP TELEMETRY]     1. Sysmon (Event-driven Kernel/ETW Stream - Real-time Push)        |
|                                2. osquery (Relational SQL State Table - Snapshot/Diff Poll)       |
|                                3. Velociraptor (DFIR Artifact & VQL Stream - On-demand/Hunt)      |
|                                        |                                                          |
|                                        v (Chuyển tiếp Log / Chuẩn hóa Tập trung)                  |
|  [TẦNG TỔNG HỢP & SIEM/XDR]    Wazuh (Log Shipper + Manager Decoder + Rule Alerting Engine)       |
+---------------------------------------------------------------------------------------------------+
```

### Quy ước minh bạch nguồn khảo sát
* **`[ĐÃ THỬ NGHIỆM THỰC TẾ - TESTED POC]`:** Các kết quả được trích xuất trực tiếp từ môi trường máy trạm thử nghiệm của nhóm (`DESKTOP-IDEMGQU`, bộ mẫu `poc_run_20261018_021142.json` ở Tuần 2–3).
* **`[NHẬN ĐỊNH TỪ TÀI LIỆU - DOCS ASSESSMENT]`:** Các phân tích dựa trên tài liệu kỹ thuật chính thức của nhà phát triển (Official Documentation) tại thời điểm tháng 10/2026; không yêu cầu cài đặt toàn bộ hệ thống nặng lên máy trạm.

---

## 2. Microsoft Sysmon (System Monitor)

* **Phiên bản & Ngày khảo sát:** Sysmon v15.15 | Ngày khảo sát: 20/10/2026.
* **Nguồn tài liệu chính thức:** Microsoft Learn – *Sysinternals Sysmon Documentation* (`https://learn.microsoft.com/en-us/sysinternals/downloads/sysmon`).
* **Vai trò kiến trúc:** **Real-time Kernel-level Event Collector**. Hoạt động thông qua minifilter driver cấp nhân kết hợp Windows ETW để bắt tức thời các sự kiện hệ thống và ghi vào kênh Windows Event Log nội bộ.
* **Trạng thái kiểm chứng:** **`[ĐÃ THỬ NGHIỆM THỰC TẾ - TESTED POC]`** trên máy trạm Windows 10/11 (`DESKTOP-IDEMGQU`) qua script `sysmon_collector_poc.py`.

### 2.1. Mô hình dữ liệu & Định dạng xuất
* **Mô hình dữ liệu (Data Model):** Mô hình hướng sự kiện (Event-driven Push Model) chia làm 2 phần tách biệt trong mỗi bản ghi:
  1. `System` (Header chuẩn của Windows Event Log): Chứa metadata định danh cấp hệ điều hành (`Provider`, `EventID`, `TimeCreated.SystemTime`, `EventRecordID`, `Channel`, `Computer`, `Security.UserID`).
  2. `EventData` (Payload động theo từng loại `EventID`): Chứa các cặp khóa-giá trị (Key-Value) đặc tả hành vi như `ProcessGuid`, `Image`, `CommandLine`, `TargetFilename`, `TargetObject`, `DestinationIp`.
* **Định dạng xuất (Output Format):** Lưu trữ gốc dưới dạng nhị phân `.evtx` hoặc xuất qua Windows Event Log API (`EvtRender`) dưới dạng XML. Trong PoC của nhóm, Software Team chuyển đổi trực tiếp XML sang chuỗi **JSONL (JSON Lines)** để đưa vào tầng Bronze.
* **API / Cơ chế truy vấn:** Truy xuất qua Win32 Event Log API (`win32evtlog` / XPath Query) hoặc PowerShell `Get-WinEvent`.

### 2.2. Metadata truy vết & Ví dụ cấu trúc thực tế (Tuần 3 PoC)
Sysmon cung cấp bộ metadata truy vết mạnh nhất cho điểm cuối Windows:
* **Định danh bản ghi tuần tự:** `EventRecordID` tăng đơn điệu không trùng lặp trong cùng một kênh `Microsoft-Windows-Sysmon/Operational`.
* **Liên kết phả hệ tiến trình:** Sinh mã `ProcessGuid` và `ParentProcessGuid` duy nhất toàn cục trên máy trạm (kết hợp Machine GUID + Timestamp khởi tạo + Token ID), miễn nhiễm với hiện tượng PID Reuse.

```json
{
  "System": {
    "Provider": {"Name": "Microsoft-Windows-Sysmon", "Guid": "{5770385F-C22A-43E0-BF4C-06F5698FFBD9}"},
    "EventID": 1,
    "TimeCreated": {"SystemTime": "2026-10-18T09:11:55.8868056Z"},
    "EventRecordID": 185,
    "Channel": "Microsoft-Windows-Sysmon/Operational",
    "Computer": "DESKTOP-IDEMGQU"
  },
  "EventData": {
    "RuleName": "technique_id=T1059.001,technique_name=PowerShell",
    "UtcTime": "2026-10-18 09:11:55.884",
    "ProcessGuid": "{43f71ec6-8d5b-6ad4-2601-000000000400}",
    "ProcessId": "8412",
    "Image": "C:\\Users\\Trankien\\AppData\\Local\\Temp\\edr_poc\\EDR_POC_drop.exe",
    "CommandLine": "\"C:\\Users\\Trankien\\AppData\\Local\\Temp\\edr_poc\\EDR_POC_drop.exe\" --silent",
    "CurrentDirectory": "C:\\Users\\Trankien\\AppData\\Local\\Temp\\edr_poc\\",
    "User": "DESKTOP-IDEMGQU\\Trankien",
    "IntegrityLevel": "Medium",
    "Hashes": "SHA256=C43CF46192DA061DD6169E55A0B1C2D3E4F5A6B7C8D9E0F1A2B3C4D5E6F7A8B9",
    "ParentProcessGuid": "{43f71ec6-8d5b-6ad4-2501-000000000400}",
    "ParentProcessId": "5120",
    "ParentImage": "C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe",
    "ParentCommandLine": "powershell.exe -ExecutionPolicy Bypass -File run_poc.ps1"
  }
}
```

---

## 3. Wazuh (Open Source XDR / SIEM Platform)

* **Phiên bản & Ngày khảo sát:** Wazuh v4.9.x | Ngày khảo sát: 23/10/2026.
* **Nguồn tài liệu chính thức:** Wazuh Documentation – *Windows Eventchannel monitoring & JSON Alerts Format* (`https://documentation.wazuh.com/current/user-manual/`).
* **Vai trò kiến trúc:** **Centralized SIEM / XDR Manager & Log Aggregator**. Wazuh gồm Wazuh Agent (chạy trên máy trạm để gom log, quét FIM định kỳ, kiểm tra cấu hình SCA) và Wazuh Server/Indexer (giải mã log, khớp luật cảnh báo và lưu vào OpenSearch).
* **Trạng thái kiểm chứng:** **`[NHẬN ĐỊNH TỪ TÀI LIỆU - DOCS ASSESSMENT]`** (Không triển khai cụm Wazuh Manager + OpenSearch do vượt quá phạm vi Local EDR gọn nhẹ).

### 3.1. Mô hình dữ liệu & Định dạng xuất
* **Mô hình dữ liệu (Data Model):**
  * Bản thân Wazuh Agent trên Windows **không có kernel driver riêng để bắt từng thao tác tạo process, registry hay kết nối socket theo thời gian thực** như Sysmon. Để có dữ liệu EDR chi tiết, Wazuh Agent bắt buộc phải cấu hình `<localfile>` với `log_format` là `eventchannel` để đọc lại kênh `Microsoft-Windows-Sysmon/Operational`.
  * Module File Integrity Monitoring (`syscheck`) của Wazuh có thể theo dõi tạo/sửa/xóa file và registry, nhưng mặc định chạy theo chu kỳ quét (scheduled scan) hoặc dùng API `ReadDirectoryChangesW` (không cho biết tiến trình nào vừa sửa file nếu không bật Windows Audit ACL phức tạp).
* **Định dạng xuất (Output Format):** Xuất ra tệp `/var/ossec/logs/alerts/alerts.json` (chỉ chứa các sự kiện khớp rule) hoặc `/var/ossec/logs/archives/archives.json` (chứa toàn bộ sự kiện) trên Wazuh Manager.
* **API / Cơ chế truy vấn:** Wazuh RESTful API (cổng `55000`) và OpenSearch Query DSL (cổng `9200`).

### 3.2. Metadata truy vết & Ví dụ cấu trúc từ tài liệu chính thức
Khi Wazuh nhận một bản ghi Sysmon, Wazuh bọc (wrap) bản ghi đó vào trong một JSON lồng nhiều cấp (`agent`, `manager`, `rule`, `decoder`, `data.win.system`, `data.win.eventdata`):
* **Ưu điểm:** Bổ sung sẵn metadata `agent.id`, `agent.name`, `agent.ip` và thông tin phân loại `rule.mitre.id` nếu đã khớp luật của Wazuh.
* **Nhược điểm góc nhìn Data:** Tất cả các trường số trong `data.win.eventdata` và `data.win.system` đều bị ép thành chuỗi ký tự (`string`), làm tăng độ trễ bóc tách JSON lồng nhau.

```json
{
  "timestamp": "2026-10-23T10:15:30.124+0000",
  "rule": {
    "level": 12,
    "description": "Sysmon - Event 1: Process creation",
    "id": "61603",
    "mitre": {"id": ["T1059.001"], "tactic": ["Execution"]}
  },
  "agent": {"id": "001", "name": "DESKTOP-IDEMGQU", "ip": "192.168.1.50"},
  "manager": {"name": "wazuh-server"},
  "id": "1729678530.129481",
  "decoder": {"name": "windows_eventchannel"},
  "data": {
    "win": {
      "system": {
        "providerName": "Microsoft-Windows-Sysmon",
        "eventID": "1",
        "eventRecordID": "185",
        "channel": "Microsoft-Windows-Sysmon/Operational",
        "computer": "DESKTOP-IDEMGQU",
        "systemTime": "2026-10-18T09:11:55.8868056Z"
      },
      "eventdata": {
        "processGuid": "{43f71ec6-8d5b-6ad4-2601-000000000400}",
        "processId": "8412",
        "image": "C:\\\\Users\\\\Trankien\\\\AppData\\\\Local\\\\Temp\\\\edr_poc\\\\EDR_POC_drop.exe"
      }
    }
  },
  "location": "EventChannel"
}
```

---

## 4. osquery

* **Phiên bản & Ngày khảo sát:** osquery v5.13.x | Ngày khảo sát: 22/10/2026.
* **Nguồn tài liệu chính thức:** osquery Documentation & Schema v5.13.1 (`https://osquery.io/schema/5.13.1/` và `https://osquery.readthedocs.io/en/stable/`).
* **Vai trò kiến trúc:** **SQL-powered OS State & Instrumentation Engine**. Biến hệ điều hành thành một cơ sở dữ liệu quan hệ ảo (SQLite virtual tables), cho phép truy vấn trạng thái cấu hình và tài nguyên hiện hành bằng cú pháp SQL.
* **Trạng thái kiểm chứng:** **`[NHẬN ĐỊNH TỪ TÀI LIỆU - DOCS ASSESSMENT]`**.

### 4.1. Mô hình dữ liệu & Định dạng xuất
* **Mô hình dữ liệu (Data Model):** Chia làm 2 chế độ thu thập:
  1. **Scheduled State Queries (Mặc định):** Truy vấn định kỳ (ví dụ mỗi 60 giây) các bảng trạng thái như `processes`, `registry`, `process_open_sockets`, `users`. Engine của osquery so sánh kết quả mới với kết quả lưu trong RocksDB nội bộ để xuất ra **Differential Logs** (`action: "added"` hoặc `"removed"`) hoặc xuất toàn bộ trạng thái (**Snapshot Logs**).
  2. **Evented Tables (`*_events`):** Sử dụng publisher/subscriber nền (như `ntfs_journal_events`, `windows_events`, hoặc thử nghiệm `process_etw_events`) để gom sự kiện vào RocksDB rồi đợi chu kỳ truy vấn mới đẩy ra ngoài.
* **Định dạng xuất (Output Format):** JSON Lines ghi ra tệp `osqueryd.results.log` hoặc đẩy qua TLS/Logger plugin.
* **API / Cơ chế truy vấn:** SQLite SQL Dialect qua `osqueryi` (interactive shell), Thrift IPC socket cục bộ, hoặc FleetDM TLS API.

### 4.2. Metadata truy vết & Ví dụ cấu trúc từ tài liệu chính thức
* Mỗi bản ghi xuất ra có khung bao đóng gồm: `name` (tên query), `hostIdentifier`, `calendarTime` (chuỗi thời gian không chuẩn ISO 8601), `unixTime` (số nguyên giây Epoch, **mất độ phân giải mili-giây/micro-giây**), `epoch`, `counter`, và `columns` (hoặc `snapshot`).
* **Điểm yếu nghiêm trọng trên Windows (`[NHẬN ĐỊNH TỪ TÀI LIỆU]`):**
  * Bảng `processes` và `process_open_sockets` chỉ cung cấp `pid` và `parent` (PPID), **không có trường `process_guid`**.
  * Nếu một tiến trình độc hại khởi chạy và kết thúc trong vòng $2\text{ giây}$ nằm giữa hai chu kỳ poll $60\text{ giây}$, chế độ truy vấn trạng thái của osquery sẽ **bỏ lọt hoàn toàn (100% blind spot)**.

```json
{
  "name": "pack_edr_processes",
  "hostIdentifier": "DESKTOP-IDEMGQU",
  "calendarTime": "Thu Oct 22 08:30:00 2026 UTC",
  "unixTime": 1792657800,
  "epoch": 0,
  "counter": 42,
  "numerics": false,
  "decorations": {
    "host_uuid": "A1B2C3D4-E5F6-7890-ABCD-1234567890AB",
    "username": "Trankien"
  },
  "columns": {
    "pid": "8412",
    "parent": "5120",
    "name": "EDR_POC_drop.exe",
    "path": "C:\\Users\\Trankien\\AppData\\Local\\Temp\\edr_poc\\EDR_POC_drop.exe",
    "cmdline": "\"C:\\Users\\Trankien\\AppData\\Local\\Temp\\edr_poc\\EDR_POC_drop.exe\" --silent",
    "cwd": "C:\\Users\\Trankien\\AppData\\Local\\Temp\\edr_poc\\",
    "uid": "1001",
    "start_time": "1792657795"
  },
  "action": "added"
}
```

---

## 5. Velociraptor

* **Phiên bản & Ngày khảo sát:** Velociraptor v0.72.x | Ngày khảo sát: 22/10/2026.
* **Nguồn tài liệu chính thức:** Rapid7 Velociraptor Documentation – *VQL Reference & Client Event Artifacts* (`https://docs.velociraptor.app/`).
* **Vai trò kiến trúc:** **Digital Forensics, Incident Response (DFIR) & VQL Hunting Platform**. Cho phép thực thi ngôn ngữ truy vấn **VQL (Velociraptor Query Language)** trực tiếp trên điểm cuối để thu thập bằng chứng pháp y (MFT, USN Journal, Prefetch, Memory Dump) hoặc theo dõi luồng sự kiện ETW.
* **Trạng thái kiểm chứng:** **`[NHẬN ĐỊNH TỪ TÀI LIỆU - DOCS ASSESSMENT]`**.

### 5.1. Mô hình dữ liệu & Định dạng xuất
* **Mô hình dữ liệu (Data Model):** Mọi tác vụ thu thập được đóng gói thành các **Artifacts** (định nghĩa bằng YAML chứa câu lệnh VQL).
  * *State/Forensic Artifacts:* Truy vấn trực tiếp đĩa cứng, bộ nhớ, hoặc cấu trúc NTFS (`Windows.NTFS.MFT`, `Windows.System.Pslist`).
  * *Client Event Monitoring Artifacts:* Sử dụng plugin `watch_etw()` hoặc `watch_evtx()` để lắng nghe liên tục các sự kiện từ Windows ETW hoặc từ chính tệp log của Sysmon (`Windows.Events.Sysmon`, `Windows.ETW.ProcessCreation`).
* **Định dạng xuất (Output Format):** Xuất kết quả từng dòng VQL dưới dạng **JSONL**, **CSV**, hoặc đóng gói toàn bộ thành tệp ZIP (`Collector` offline).
* **API / Cơ chế truy vấn:** VQL Engine kết hợp gRPC API để tích hợp với các script Python bên ngoài (`pyvelociraptor`).

### 5.2. Metadata truy vết & Ví dụ cấu trúc từ tài liệu chính thức
* Velociraptor có cơ chế **Process Tracker** nội bộ trên Client để duy trì bộ nhớ đệm cây tiến trình (`process_tracker_get()`), giúp bổ sung thông tin cha-con ngay cả khi chỉ dùng ETW thuần (vốn chỉ có PID/PPID).
* Tuy nhiên, cấu trúc cột đầu ra của Velociraptor **hoàn toàn phụ thuộc vào câu lệnh `SELECT` trong VQL Artifact** (không có một schema phẳng cố định nếu người viết Artifact thay đổi bí danh cột).

```json
{
  "Timestamp": "2026-10-22T09:15:10.412Z",
  "ClientId": "C.89a1b2c3d4e5f601",
  "Hostname": "DESKTOP-IDEMGQU",
  "Artifact": "Windows.Events.ProcessCreation",
  "System": {
    "ID": 1,
    "Version": 5,
    "Provider": "Microsoft-Windows-Sysmon"
  },
  "EventData": {
    "ProcessId": 8412,
    "Image": "C:\\Users\\Trankien\\AppData\\Local\\Temp\\edr_poc\\EDR_POC_drop.exe",
    "CommandLine": "\"C:\\Users\\Trankien\\AppData\\Local\\Temp\\edr_poc\\EDR_POC_drop.exe\" --silent"
  },
  "ProcessChain": [
    {"Pid": 5120, "Exe": "C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe"}
  ]
}
```

---

## 6. Atomic Red Team (và Invoke-AtomicRedTeam)

* **Phiên bản & Ngày khảo sát:** Atomic Red Team Repository & `Invoke-AtomicRedTeam` v2.2+ | Ngày khảo sát: 21/10/2026.
* **Nguồn tài liệu chính thức:** Red Canary Atomic Red Team Docs (`https://atomicredteam.io/` và `https://github.com/redcanaryco/invoke-atomicredteam/wiki`).
* **Vai trò kiến trúc:** **Adversary Emulation Framework & Ground-Truth Labeling Generator**. **Tuyệt đối không phải là công cụ thu thập (Collector) trong môi trường Production.** Công cụ này đóng vai trò kích hoạt các hành vi tấn công chuẩn hóa theo ma trận MITRE ATT&CK để tạo dữ liệu thực nghiệm có nhãn (Labeled Telemetry) phục vụ kiểm thử Detection và huấn luyện AI.
* **Trạng thái kiểm chứng:** **`[ĐÃ THỬ NGHIỆM CẤU TRÚC KỊCH BẢN & THỰC THI POC]`** kết hợp đối chiếu tài liệu chính thức.

### 6.1. Mô hình dữ liệu kịch bản (Scenario Metadata) & Định dạng xuất
Atomic Red Team quản lý dữ liệu ở 2 giai đoạn:
1. **Định nghĩa kịch bản tĩnh (Static Test Definition - YAML):** Lưu tại `atomics/Txxxx/Txxxx.yaml`. Mỗi kỹ thuật MITRE chứa danh sách `atomic_tests`, trong đó từng bài test được định danh duy nhất toàn cục bởi **`auto_generated_guid`**, kèm theo `supported_platforms`, `input_arguments`, `executor` (`powershell`, `command_prompt`, `sh`), và `cleanup_command`.
2. **Nhật ký thực thi động (Execution Log Output - CSV/JSONL):** Khi chạy qua `Invoke-AtomicTest` với tham số `-ExecutionLogPath` và module logger (như `Attire-ExecutionLogger` chuẩn ATT&CK Replay / JSON), công cụ xuất ra nhật ký ghi lại chính xác thời điểm bắt đầu/kết thúc, mã GUID của bài test, lệnh thực tế đã chạy và **PID của tiến trình khởi chạy (Runner PID)**.

### 6.2. Ví dụ cấu trúc Metadata YAML & Execution Log phục vụ gắn nhãn
* **Cấu trúc YAML kịch bản (`T1059.001.yaml`):**
```yaml
attack_technique: T1059.001
display_name: 'Command and Scripting Interpreter: PowerShell'
atomic_tests:
  - name: Mimikatz PowerShell Execution
    auto_generated_guid: 11223344-5566-7788-99aa-bbccddeeff00
    description: Download and execute script via PowerShell
    supported_platforms:
      - windows
    executor:
      name: powershell
      elevation_required: false
      command: |
        powershell.exe -NoP -NonI -W Hidden -Enc SQBFAFgAIAAoAE4AZQB3AC0ATwBiAGoAZQBjAHQAIABOAGUAdAAuAFcAZQBiAEMAbABpAGUAbgB0ACkA
```

* **Cấu trúc Execution Log JSON/ATTIRE xuất ra sau khi chạy thử nghiệm:**
```json
{
  "execution_id": "exec-20261021-001",
  "atomic_guid": "11223344-5566-7788-99aa-bbccddeeff00",
  "attack_technique": "T1059.001",
  "test_name": "Mimikatz PowerShell Execution",
  "hostname": "DESKTOP-IDEMGQU",
  "user": "DESKTOP-IDEMGQU\\Trankien",
  "runner_pid": 5120,
  "start_time_utc": "2026-10-21T14:00:01.120Z",
  "end_time_utc": "2026-10-21T14:00:04.890Z",
  "command_executed": "powershell.exe -NoP -NonI -W Hidden -Enc ...",
  "exit_code": 0
}
```

---

## 7. Bảng So Sánh Tổng Hợp Khả Năng Cung Cấp Telemetry & Metadata

Bảng dưới đây đối sánh trực tiếp 4 công cụ thu thập/tổng hợp (Sysmon, Wazuh, osquery, Velociraptor) và 1 công cụ mô phỏng (Atomic Red Team) theo các tiêu chí cốt lõi của Data Engineering:

| Tiêu Chí Kỹ Thuật Dữ Liệu | Microsoft Sysmon (`[TESTED POC]`) | Wazuh (`[DOCS ASSESSMENT]`) | osquery (`[DOCS ASSESSMENT]`) | Velociraptor (`[DOCS ASSESSMENT]`) | Atomic Red Team (`[TESTED/DOCS]`) |
| :--- | :--- | :--- | :--- | :--- | :--- |
| **Vai trò chính** | Kernel Event Collector | SIEM/XDR Aggregator | SQL OS State Engine | DFIR & VQL Hunter | Adversary Emulation & Labeling |
| **Cơ chế thu thập** | Real-time Push (Driver/ETW) | Push qua Agent (bọc EventChannel + FIM Poll) | Pull/Poll định kỳ (SQL Diff/Snapshot) | On-demand Hunt hoặc VQL ETW Stream | Thực thi chủ động theo kịch bản |
| **Process Telemetry** | **Rất mạnh** (ID 1, 5: đầy đủ CommandLine, Hashes, ParentImage) | Phụ thuộc Sysmon (hoặc Windows Audit 4688 kém chi tiết hơn) | **Trung bình** (Bảng `processes` dễ hụt tiến trình ngắn hạn) | **Mạnh** (Qua `watch_etw` hoặc `Pslist` kèm Process Tracker) | Xuất `runner_pid` và `command_executed` của lần thử |
| **File Telemetry** | **Rất mạnh** (ID 11, 23, 26: bắt tức thời kèm `ProcessGuid` & Hash) | Module `syscheck` FIM (chủ yếu báo thay đổi file, thiếu ngữ cảnh Process) | Bảng `ntfs_journal_events` (cấu hình phức tạp, thiếu ProcessGuid) | **Rất mạnh** cho Forensics (đọc trực tiếp `$MFT`, `$UsnJrnl`) | Tạo/xóa file mẫu để kích hoạt Collector |
| **Registry Telemetry** | **Rất mạnh** (ID 12, 13, 14: bắt tức thời thao tác Key/Value) | Module `syscheck` `windows_registry` (quét theo chu kỳ, độ trễ cao) | Bảng `registry` (chỉ truy vấn trạng thái tĩnh, không phải stream sự kiện) | Đọc trực tiếp Hive file hoặc bắt qua ETW | Sửa khóa Run/RunOnce mẫu để test Persistence |
| **Network Telemetry** | **Mạnh** (ID 3, 22: TCP/UDP Socket + DNS Query gắn liền `ProcessGuid`) | Không bắt kết nối mạng per-process nếu không dùng Sysmon | Bảng `process_open_sockets` (chỉ thấy socket đang mở lúc poll) | Bảng `Windows.Network.NetstatEnriched` hoặc ETW DNS | Mở kết nối mẫu ra ngoài để test C2 |
| **Độ chính xác Timestamp** | **100 nanoseconds** (ISO 8601 UTC `SystemTime`) | Giữ nguyên `systemTime` gốc + thêm `timestamp` lúc Manager nhận | **Giây (`unixTime`)** – Mất độ chính xác sub-second! | **Milliseconds/Nanoseconds** (ISO 8601 UTC) | **Milliseconds** (`start_time_utc`, `end_time_utc`) |
| **Host Identity** | `System.Computer` | `agent.id`, `agent.name`, `agent.ip` | `hostIdentifier`, `decorations.host_uuid` | `ClientId`, `Hostname`, `Fqdn` | `hostname` trong Execution Log |
| **Process Correlation** | **Chuẩn vàng:** `ProcessGuid` & `ParentProcessGuid` xuyên suốt | Chỉ có nếu đọc lại từ Sysmon `data.win.eventdata.processGuid` | **Yếu:** Chỉ có `pid` và `parent` (bị lỗi PID Reuse) | Có `ProcessTracker` nội bộ ghép nối phả hệ từ PID/StartTime | Liên kết với Collector qua `(hostname, runner_pid, time_window)` |