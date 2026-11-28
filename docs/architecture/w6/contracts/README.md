# W06 contracts — proposal for Data/Cyber review

- `rule.schema.json`, `detection-result.schema.json`: export nguyên trạng từ `src/detection/schema.py`; kết quả schema integer version của rule, không tạo Bronze envelope mới.
- `detection-error.schema.json`: đặc tả envelope lỗi thực thi; runtime hiện dùng Core health/log, chưa có error publisher riêng.
- `examples.json`: MATCH, NO_MATCH, INSUFFICIENT, PENDING và lỗi synthetic, không raw hay định danh thật.

`allowed_lateness_seconds` là field tùy chọn mới trong rule schema. Không đổi các field bắt buộc cũ. Đổi required fields/meaning cần contract major và review. Xem [thiết kế module](../detection-module-architecture-v1.md) và [loader/config](../../../research/software/w6/02-rule-loading-and-config-design.md).

Bổ sung 2026-11-28 (field tùy chọn, không đổi field bắt buộc cũ; hạng mục 5 của `docs/architecture/w8/telemetry-defender-powershell-proposal.md`):
`source_events` (rule đọc kênh Windows khác Sysmon; loại trừ lẫn nhau với `sysmon_event_ids`), `severity_by`, `context_fields`,
`group_by_field`, `detection_source` (`EXTERNAL_DEFENDER`). `source_events` và `detection_source` người dùng duyệt (D7) thay cho
Data/Cyber; `severity_by`, `context_fields`, `group_by_field` là quyết định triển khai chờ duyệt.
