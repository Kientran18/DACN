# JSON Event Sample

**Trạng thái: ĐÃ CÓ MẪU THẬT** tại [references/samples/json](../../../../references/samples/json). Ví dụ bên dưới là minh họa lịch sử; JSON thật và schema hiệu chỉnh là nguồn đối chiếu. Sau khi có dữ liệu thật, chạy collector ở file mode và lưu kết quả vào `samples/json/process_event.json` (và các loại khác).

## 1. Cấu trúc đầu ra (mỗi sự kiện)

| Trường | Ý nghĩa | So với Silver `BaseEvent` / envelope của Data |
|---|---|---|
| `event_id` | UUIDv5 ổn định | Spec ghi ULID/UUIDv4 (Q-X3) |
| `timestamp` | UTC, giữ nguyên độ phân giải 100 ns | Silver dùng `TIMESTAMP`; cần quy đổi khi nạp |
| `source` | `SYSMON` | Enum envelope chưa có giá trị này |
| `event_type` | Ví dụ `PROCESS_START` | Tên theo envelope; Cyber dùng `PROCESS_CREATE` |
| `sysmon_event_id`, `channel`, `record_id` | Nguồn gốc, khóa chống trùng `(channel, record_id)` | Không có trong Silver |
| `hostname` | Tên máy từ `<Computer>` | Thiếu `host_id`, `os_version`, `agent_version`, `primary_ip` của `host_context` |
| `process_guid` | Bỏ `{}` | Có trong Silver |
| `data` | Trường đã ánh xạ theo loại sự kiện | Một phần chưa có cột Silver (Q-D6) |
| `raw_data` | Toàn bộ trường `EventData` gốc | Dùng cho Bronze |

## 2. Ví dụ từ sự kiện **giả lập** (KHÔNG phải dữ liệu thật; rút gọn `raw_data`)

```json
{
  "event_id": "b5e2f113-264f-5385-ad69-2a584aa3177a",
  "timestamp": "2026-10-14T02:15:30.1234567Z",
  "source": "SYSMON",
  "event_type": "PROCESS_START",
  "sysmon_event_id": 1,
  "channel": "Microsoft-Windows-Sysmon/Operational",
  "record_id": 1001,
  "hostname": "LAB-HOST",
  "process_guid": "AAAAAAAA-0000-0000-0000-000000000001",
  "data": {
    "pid": 4321,
    "ppid": 1234,
    "parent_guid": "AAAAAAAA-0000-0000-0000-000000000002",
    "image_path": "C:\\Windows\\System32\\cmd.exe",
    "command_line": "cmd.exe /c echo EDR_POC_SYNTH step1_normal",
    "user_name": "LAB-HOST\\LABUSER",
    "integrity_level": "Medium",
    "session_id": 1,
    "parent_image": "C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe",
    "file_sha256": "0123456789ABCDEF0123456789ABCDEF0123456789ABCDEF0123456789ABCDEF"
  },
  "raw_data": { "...": "toàn bộ trường EventData gốc" }
}
```

## 3. Mẫu thật (dán vào đây sau khi chạy)
```json
// PASTE REAL JSON OUTPUT HERE (also commit the file under samples/json/)
```
