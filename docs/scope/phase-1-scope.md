# Phạm vi giai đoạn 1 nghiên cứu và thiết kế Endpoint Security

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

## Cập nhật phạm vi theo kế hoạch 12 tuần

Phần chức năng ở trên là mục tiêu thiết kế của hệ thống đề xuất. Trong Đồ án Chuyên ngành, nhóm nghiên cứu, thiết kế và kiểm chứng bằng PoC tối thiểu; không cam kết hiện thực đầy đủ EPP/EDR, response, AI và dashboard trong 12 tuần. Phần hiện thực và triển khai thử nghiệm đầy đủ chuyển sang Luận văn Tốt nghiệp.

Đầu ra bắt buộc gồm tài liệu, schema/mapping, mẫu telemetry thật và minimal collector tuần 3. PoC mở rộng đến 2–5 detection rules/alert/dashboard là tùy tiến độ. Windows và một endpoint là phạm vi khảo sát chính. Linux, cloud/Fabric, enterprise-scale, kernel driver, GNN và triển khai backend tập trung trong các tài liệu nghiên cứu cũ là tham khảo hoặc Phase 2, chưa phải quyết định sử dụng.

Backlog hiện hành: [12 tuần](../project/research-backlog-12-weeks.md). Owner/reviewer và bằng chứng: [review tuần 1–3](../project/week-01-03-review-and-ownership.md).
