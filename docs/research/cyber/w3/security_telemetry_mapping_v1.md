# W03 Cyber — Security Telemetry Mapping v1

Issue: #14. Phạm vi: 13 kỹ thuật MITRE ATT&CK đã chọn ở W02; Windows 10/11, Sysmon 15.x. Đánh giá ngày 19/10/2026.

**Quy ước:** Observed = đã có mẫu sự kiện tương ứng (không phải tấn công); Supported = có nguồn sự kiện nhưng chưa xác minh tình huống; Gap = không đủ bằng chứng. Mức khả thi không đồng nghĩa tỷ lệ phát hiện.

| MITRE | Hành vi | Telemetry chính | Mức khả thi | Ghi chú |
|---|---|---|---|---|
| T1204.002 | User execution of malicious file | Sysmon 11,29,1; 15 hỗ trợ | Một phần | Không chứng minh hành động người dùng |
| T1059.001 | PowerShell | Sysmon 1; 3,22 hỗ trợ | Khá | CommandLine/ParentImage; thiếu script block |
| T1059.003 | Windows Command Shell | Sysmon 1 | Khá | Cần ngữ cảnh parent/arguments |
| T1218 | Signed binary proxy execution | Sysmon 1; 7 hỗ trợ | Một phần | Event 7 chưa bật |
| T1547.001 | Registry Run Keys/Startup Folder | Sysmon 12,13,14,11 | Khá | Chưa có mẫu Run/RunOnce thực |
| T1053.005 | Scheduled Task | Sysmon 1,12,13; Security 4698/4702 | Một phần | Security auditing chưa thu |
| T1562.001 | Impair Defenses | Sysmon 5,4,16; System 7036/7040 | Một phần | Cần watchdog/heartbeat |
| T1082 | System Information Discovery | Sysmon 1 | Khá | Chỉ phát hiện các công cụ/lệnh nhìn thấy |
| T1083 | File and Directory Discovery | Sysmon 1 | Yếu | Thiếu file enumeration events |
| T1105 | Ingress Tool Transfer | Sysmon 3,22,11,29 | Một phần | Correlation, không có nội dung tải |
| T1071.001 | Web Protocols | Sysmon 3,22 | Một phần | Không xác nhận HTTP/C2 qua port 443 |
| T1070.004 | File Deletion | Sysmon 11,1,26 | Khá | Có chuỗi PoC drop-execute-delete |
| T1486 | Data Encrypted for Impact | Sysmon 1,11,26 | Yếu | Không có telemetry write/rename liên tục |

## Đối chiếu mẫu thật

Mẫu ngày 18/10/2026: Windows 10 build 19045, Sysmon 15.22; 17 event trong manifest, thuộc các ID 1,5,11,26,29,12,13,3,22,4,16. Các file ở `references/samples/raw/` và `references/samples/json/`. Đây là hoạt động PoC lành tính, không phải kiểm thử kỹ thuật tấn công.

- Event 1: `Image`, `CommandLine`, `ParentImage`, `ParentProcessGuid`, `Hashes` có trong mẫu.
- Event 11/29/1/26: quan sát chuỗi tạo executable tại Temp → phát hiện PE → thực thi → xóa; khớp file path/hash trong mẫu.
- Event 12/13: có `EventType`, `TargetObject`, `Details`; HKCU xuất hiện dạng HKU\\SID.
- Event 3/22: chung `ProcessGuid`, một IP của `QueryResults` khớp `DestinationIp`; chưa chứng minh lưu lượng C2.

**Kết luận:** Có mapping 13/13 kỹ thuật, nhưng T1083 và T1486 có độ phủ yếu; chưa được tuyên bố detection hoàn chỉnh.
