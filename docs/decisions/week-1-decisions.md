# Week 1 — Recorded Technical Decisions

> File này gom lại các lựa chọn đã được ghi rõ cho Giai đoạn 1 trong `WEEK_1_CYBER.docx`. Không bổ sung quyết định mới ngoài tài liệu gốc.

| Khu vực | Quyết định / lựa chọn cho Giai đoạn 1 |
|---|---|
| Nền tảng | Windows 10/11 |
| Quy mô prototype | Một Windows endpoint |
| Kiến trúc triển khai | Endpoint Security Agent + Local Detection Engine + Local Security Database |
| Monitoring | User-space monitoring là chính |
| Central management | Không có central server trong Phase 1 |
| Scale | Không yêu cầu enterprise-scale detection |
| EPP | Signature/Hash Detection, Whitelist, Process Monitoring, File Monitoring, Basic Behavioral Detection, Block/Quarantine |
| EDR | Event Collector → Local Event Store → Detection Engine → Alert → Investigation Information → Response |
| Detection ưu tiên | Signature Detection + Rule-based Detection + Behavior-based Detection |
| Detection output tối thiểu | Timestamp, Process Name, PID, Parent PID, Executable Path, Hash, Detection Rule, Severity, Reason, Related Events |
| Response | Terminate Process, Quarantine File, Block Hash, Add Whitelist |
| Threat Hunting | Search/filter events và một số predefined hunt |

## Predefined hunt đã nêu

- Suspicious PowerShell
- Unknown executable from Temp
- Unusual process tree
- Persistence behavior
- Repeated malicious events

## Điểm chưa chốt trong tài liệu

- Câu về Internet trong phần Assumptions bị dừng ở “Internet có thể được sử dụng nhưng detection chính...”.
- Threat Model có **Network Events**, trong khi sơ đồ Preliminary Security Architecture chỉ vẽ **Process, File và Registry Events**.
