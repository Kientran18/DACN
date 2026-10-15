# Week 1 — Endpoint Security Concepts

## 1. EPP — Endpoint Protection Platform

EPP (Endpoint Protection Platform) là lớp bảo vệ được triển khai trực tiếp trên endpoint như máy tính Windows, laptop hoặc workstation nhằm ngăn chặn các mối đe dọa trước hoặc trong thời điểm chúng thực thi.

Các chức năng thường gặp:

- Antivirus / Anti-malware
- Signature-based detection
- File reputation / hash checking
- Application control
- Host firewall
- Device/USB control
- Behavior-based blocking
- Quarantine
- Attack Surface Reduction

### Phần nền tảng cho Giai đoạn 1

```text
File/Process → Collect → Detect → Alert → Response
```

Ví dụ:

```text
abc.exe được chạy
    ↓
Agent thu thập process event
    ↓
Kiểm tra hash / whitelist / rule
    ↓
Phát hiện hành vi nghi ngờ
    ↓
Tạo alert
    ↓
Block / terminate / quarantine
```

Các chức năng EPP phù hợp Giai đoạn 1:

- Signature / Hash Detection
- Whitelist
- Process Monitoring
- File Monitoring
- Basic Behavioral Detection
- Block / Quarantine

## 2. EDR — Endpoint Detection and Response

EDR (Endpoint Detection and Response) tập trung vào việc liên tục quan sát hoạt động trên endpoint, phát hiện hành vi bất thường, hỗ trợ điều tra và thực hiện các hành động phản ứng sau khi có dấu hiệu tấn công.

Một EDR thường thu thập telemetry như:

- Process creation
- Parent-child process
- Command line
- File creation / modification
- Registry changes
- Network connection
- Login activity
- Security event

### EDR flow tổng quát

```text
Endpoint
   ↓
Telemetry Collector
   ↓
Event Storage
   ↓
Detection Engine
   ↓
Alert
   ↓
Investigation
   ↓
Response
```

### Trọng tâm EDR trong Giai đoạn 1

```text
Windows Endpoint
   ↓
Event Collector
   ↓
Local Event Store
   ↓
Detection Engine
   ↓
Alert
   ↓
Investigation Information
   ↓
Response
```

## 3. Detection

Detection là quá trình xác định một event hoặc chuỗi event có khả năng liên quan đến hành vi độc hại.

Detection có thể dựa trên:

- **Signature:** Hash của file malware đã biết
- **IOC:** IP/domain/hash độc hại
- **Rule-based:** PowerShell chạy với tham số bất thường
- **Behavioral:** Process tạo nhiều file rồi thay đổi chúng nhanh
- **Anomaly:** Hành vi khác đáng kể baseline
- **ML/AI:** Mô hình đánh giá mức độ bất thường

Giai đoạn 1 ưu tiên:

1. Signature Detection
2. Rule-based Detection
3. Behavior-based Detection

### Output tối thiểu của Detection

- Timestamp
- Process Name
- PID
- Parent PID
- Executable Path
- Hash
- Detection Rule
- Severity
- Reason
- Related Events

## 4. Investigation

Investigation là bước phân tích alert để trả lời:

- Điều gì đã xảy ra?
- Quá trình nào gây ra?
- Bắt đầu từ đâu?
- Những process/file nào liên quan?
- Hành vi có thực sự nguy hiểm không?
- Phạm vi ảnh hưởng là gì?

Ví dụ, thay vì chỉ có detection:

```text
powershell.exe suspicious
```

Investigation cần bổ sung context:

```text
winword.exe
    ↓
cmd.exe
    ↓
powershell.exe
    ↓
download.exe
```

Kèm theo:

- Command line
- File path
- Hash
- Timestamp
- Network destination
- Created files
- Registry changes

## 5. Response

Response là hành động được thực hiện sau khi threat được phát hiện hoặc xác nhận.

Ở endpoint, response có thể bao gồm:

- Terminate process
- Block execution
- Quarantine file
- Block hash
- Delete malicious file
- Disable persistence
- Network isolation
- Restore affected file

Giai đoạn 1 nên hỗ trợ:

- Terminate Process
- Quarantine File
- Block Hash
- Add Whitelist

## 6. Threat Hunting

Threat Hunting là hoạt động chủ động tìm kiếm dấu hiệu compromise trong telemetry, thay vì chỉ chờ alert được hệ thống tạo ra.

Ví dụ:

- Detection: rule phát hiện `powershell.exe` → alert
- Threat Hunting: “Tìm tất cả PowerShell được spawn từ Office trong 7 ngày qua.”
- Threat Hunting: “Tìm process chạy từ `%TEMP%` nhưng tạo persistence.”

Với Giai đoạn 1, có thể xây dựng dưới dạng:

- Search events
- Filter by process
- Filter by hash
- Filter by time
- Filter by severity
- Filter by rule

Một số predefined hunt:

- Suspicious PowerShell
- Unknown executable from Temp
- Unusual process tree
- Persistence behavior
- Repeated malicious events
