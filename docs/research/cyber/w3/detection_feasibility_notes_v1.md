# W03 Cyber — Detection Feasibility Notes v1

Issue #14. Các rule sau là đặc tả detection sơ bộ, **chưa phải detection đã benchmark**.

| Rule | Logic/telemetry đề xuất | Đánh giá |
|---|---|---|
| DET-001 | Event 1: PowerShell với parent bất thường hoặc command-line indicators; 3/11 bổ trợ | Khả thi |
| DET-002 | Event 1: CMD trong process tree bất thường | Khả thi |
| DET-003 | Event 13: Run/RunOnce trỏ tới script/executable ở vị trí user-writable | Khả thi; thiếu mẫu Run thật |
| DET-004 | Event 1: schtasks /create,/change; bổ sung Security 4698/4702 | Một phần |
| DET-005 | Event 3/22 + 11/29 cùng process hoặc quan hệ parent-child | Một phần |
| DET-006 | Event 3/22: repeated outbound/DNS theo cửa sổ, destination rarity | Heuristic |
| DET-007 | Event 5/4/16 + watchdog và System service logs | Một phần |
| DET-008 | Event 11/26 tăng bất thường; không kết luận mã hóa file | Yếu |
| DET-009 | Event 1: discovery command sequences | Một phần |
| DET-010 | Event 11 → Event 1 → Event 26 cùng file path, host, thời gian; hash nếu có | Đã có chuỗi PoC |

## Logic ưu tiên

### DET-001: Suspicious PowerShell

```text
PROCESS_START AND image_path endswith powershell.exe/pwsh.exe
AND (parent_image thuộc ứng dụng Office bất thường
     OR command_line chứa tín hiệu đáng ngờ như -EncodedCommand, -WindowStyle Hidden)
```

Không coi một flag đơn lẻ là tấn công; có thể có script quản trị hợp pháp.

### DET-003: Registry Persistence

```text
REGISTRY_SET_VALUE AND target_object thuộc Run/RunOnce
AND details tham chiếu executable/script ở Temp/AppData/Downloads hoặc path bất thường
```

Đòi hỏi normalize HKU/SID, whitelist hợp lý và kiểm thử benign startup apps.

### DET-010: Drop–Execute–Delete

```text
FILE_CREATE(path A) -> PROCESS_START(image_path A) -> FILE_DELETE(path A)
AND same hostname AND ordered timestamps
AND hash matches when available
```

Ngưỡng thời gian cần hiệu chỉnh bằng dữ liệu benign và malicious-like lab. Không chỉ dựa PID; sử dụng process GUID để quy thuộc tác nhân và hash/path để nối file với executable.

## Quy tắc đánh giá

- Ghi rõ event evidence, process lineage, time window, matched indicators, missing fields trong alert.
- Severity phải dựa vào tổ hợp bằng chứng; port 443, PowerShell hoặc registry set riêng lẻ không đủ xác nhận tấn công.
- Chưa có precision/recall/FPR; không công bố hiệu quả detection.
- Chỉ nâng trạng thái rule sau khi có positive/negative tests và kiểm tra false positives.
