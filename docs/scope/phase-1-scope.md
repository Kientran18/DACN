# Phase 1 Scope — Windows Endpoint Security Prototype

> Nguồn: `WEEK_1_CYBER.docx` — các phần định hướng Giai đoạn 1 và Preliminary Windows Endpoint Threat Model.

## 1. System Scope

Threat model ban đầu giới hạn trong:

```text
1 Windows Endpoint
        +
Endpoint Security Agent
        +
Local Detection Engine
        +
Local Security Database
```

## 2. Chức năng nằm trong phạm vi Giai đoạn 1

### EPP

- Signature / Hash Detection
- Whitelist
- Process Monitoring
- File Monitoring
- Basic Behavioral Detection
- Block / Quarantine

### EDR flow cục bộ

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

### Detection ưu tiên

- Signature Detection
- Rule-based Detection
- Behavior-based Detection

### Response cần hỗ trợ

- Terminate Process
- Quarantine File
- Block Hash
- Add Whitelist

### Threat Hunting cơ bản

- Search events
- Filter by process
- Filter by hash
- Filter by time
- Filter by severity
- Filter by rule
- Suspicious PowerShell
- Unknown executable from Temp
- Unusual process tree
- Persistence behavior
- Repeated malicious events

## 3. Assets cần bảo vệ

- **User files:** Không bị ransomware/xóa/sửa trái phép
- **Credentials:** Không bị đánh cắp
- **Windows OS:** Không bị chiếm quyền
- **Processes:** Không bị malicious process lợi dụng
- **Registry:** Không bị persistence trái phép
- **Security Agent:** Không bị disable/tamper
- **Detection rules:** Không bị thay đổi
- **Signature database:** Không bị chỉnh sửa
- **Security logs:** Không bị xóa hoặc giả mạo

## 4. Threat Actors

Giả định các nguồn threat:

- Malware
- Ransomware
- Malicious executable
- Malicious script
- Potentially unwanted program
- Compromised application
- Local malicious process

## 5. Attack Vectors

- Downloaded executable
- Browser download
- Email attachment
- USB/removable media
- Malicious script
- PowerShell / CMD
- Compromised software
- Malicious document
- Network-delivered payload

## 6. Assumptions và giới hạn

- OS: Windows 10/11
- User-space monitoring là chính
- Agent đang hoạt động bình thường
- Prototype chạy trên một endpoint
- Không có central server trong Phase 1
- Không yêu cầu enterprise-scale detection

> Lưu ý: tài liệu gốc còn một câu bắt đầu bằng “Internet có thể được sử dụng nhưng detection chính...” nhưng câu này bị dừng giữa chừng, nên không tự bổ sung phần còn thiếu.
