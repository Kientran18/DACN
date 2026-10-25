# Chia sẻ mẫu với Cyber và Data

**Cảnh báo hiện trạng:** mẫu thật hiện diện ở `references/samples/raw/` và `references/samples/json/`, nhưng `references/samples/raw/export_manifest.json` ghi `sanitized: false`. **Chưa có bằng chứng ẩn danh**; cần tạo bản chia sẻ đã khử định danh riêng và kiểm tra repository public/lịch sử commit.

## 1. Thông báo mẫu

> **[W03][Software] Mẫu sự kiện Sysmon thật từ VM lab (Issue #16)**
> Đã có mẫu thô (XML) và JSON cho process (Event 1, 5), file (11, 26, 29), registry (12, 13), network (3, 22) tại `samples/raw/` và `samples/json/`. Cấu hình: `configs/sysmon/sysmon-config.xml` v1.0, Sysmon <phiên bản>, Windows <build>.
> Nhờ **Data** kiểm tra mẫu với Pydantic Silver schema; nhờ **Cyber** kiểm tra mẫu có đủ để viết DET-001, 002, 003, 005, 010. Câu hỏi cụ thể ở bên dưới. Mong phản hồi trước <ngày>.

## 2. Checklist cho Data

- [ ] `ProcessEvent` validate được mẫu Event 1 thật? Trường nào bị từ chối?
- [ ] Silver cần thêm cột nào: `parent_image`, `parent_command_line`, `integrity_level`, `session_id`, `end_time`, `operation`, `dns_query_name` (Q-D6)?
- [ ] `process_guid` của Sysmon qua được validation UUID (Q-D1)?
- [ ] Chấp nhận `event_id` UUIDv5, `source = SYSMON`, `event_type` theo bảng quy đổi (Q-X3)?
- [ ] Tên channel trong `collector.py` là `Microsoft-Windows-Sysmon/Operational` (Q-D7)?
- [ ] Số liệu volume (E9) có phù hợp với ngân sách RAM/CPU (Q-D5)?

## 3. Checklist cho Cyber

- [ ] Mẫu Event 1 (`ParentImage`, `CommandLine`) đủ để viết DET-001/002?
- [ ] Mẫu registry (Event 13) đủ cho DET-003? Danh sách key cần theo dõi (Q-C3).
- [ ] Mẫu Event 3 + 22 đủ cho DET-005/006? Kết quả E7 về correlate DNS.
- [ ] Kết quả E1 đến E3 (ghi đè, nối thêm, đổi tên) thay đổi định nghĩa DET-008 thế nào (Q-C1)?
- [ ] Event 23 hay 26 (Q-C2); Network có nằm trong sơ đồ kiến trúc (Q-C6)?

## 4. Biên bản review (điền sau khi họp)

| Bên | Ngày | Người tham gia | Kết quả / yêu cầu thay đổi | Link |
|---|---|---|---|---|
| Data | | | | |
| Cyber | | | | |

## 5. Commit mẫu vào repo

Theo convention của team (nhánh `feature/16-sysmon-collector-poc`):

```text
config(sysmon-config): add Sysmon config v1.0 for PoC
feat(collector): add minimal Sysmon collector PoC with file and live modes
docs(samples): add raw Sysmon event samples from lab VM (Refs #16)
```
Vị trí: `configs/sysmon/`, `scripts/poc/`, `poc/` (hoặc `src/collector/` khi thống nhất với Data), `samples/raw/`, `samples/json/`, `docs/`.
