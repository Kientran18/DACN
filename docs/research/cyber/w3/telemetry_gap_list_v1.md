# W03 Cyber — Telemetry Gap List & Cross-Team Review

Issue #14. P1 = ảnh hưởng đáng kể tới detection/độ đúng dữ liệu; P2 = mở rộng độ phủ.

| Gap | Thiếu hụt | Ảnh hưởng | Ưu tiên | Hướng xử lý |
|---|---|---|---|---|
| GAP-01 | Không có full file write/rename telemetry | T1486, T1083 | P1 | Đánh giá ETW/USN hoặc nguồn khác |
| GAP-02 | Chưa thu scheduled-task audit | T1053.005 | P1 | Security 4698/4702 |
| GAP-03 | Không có watchdog/agent heartbeat độc lập | T1562.001 | P1 | Watchdog, System service logs |
| GAP-04 | Không có HTTP/HTTPS payload/SNI/bytes | T1071.001 | P2 | Metadata correlation, ghi giới hạn |
| GAP-05 | Sysmon 7 chưa bật | T1218 | P2 | Đánh giá ImageLoad có lọc |
| GAP-06 | Chưa thu PowerShell script block 4104 | T1059.001 | P2 | Cân nhắc bật logging |
| GAP-07 | Không có bằng chứng trực tiếp user click | T1204.002 | P2 | MotW/Event 15 + correlation |
| GAP-08 | File filters không phủ mọi đường dẫn | T1105/T1070.004/T1486 | P1 | Review sysmon-config.xml |
| GAP-09 | Chưa có mẫu Sysmon 14,15 | Registry/file stream | P2 | Thu mẫu lab |
| GAP-10 | Chênh SystemTime vs UtcTime trong Event 3/22 | Correlation | P1 | Điều tra timestamp semantics |
| GAP-11 | Schema ép process_guid và network fields cho event không phù hợp | Pipeline | P1 | Schema riêng DNS/state/config |
| GAP-12 | Thiếu positive/negative detection benchmark | Toàn bộ DET | P1 | Test benign/suspicious có nhãn |

## Yêu cầu review với Software

- Xác minh E1–E3: overwrite, append, rename có sinh Sysmon 11 hay event nào khác.
- Thu Event 14/15 và xác nhận Event 29 trên cấu hình đang chạy.
- Đánh giá file filter, event volume, quyền đọc channel và agent health monitoring.
- Điều tra chênh lệch `System.TimeCreated`/`EventData.UtcTime`.

## Yêu cầu review với Data

- Cho phép `process_guid` NULL với Sysmon 4/16; không ép DNS 22 vào network connection schema.
- Hỗ trợ event 29, hash của 26, các trường DNS 22 và registry HKU/SID.
- Chuẩn hóa UTC, correlation bằng (hostname, process_guid), giữ raw_data.
- Phân biệt `event_id` UUIDv5 và `sysmon_event_id`.

## Bảo mật mẫu

`references/samples/raw/export_manifest.json` ghi `sanitized: false`. Các mẫu chứa hostname, tên tài khoản và SID lab. Cần tạo mẫu đã ẩn danh trước khi chia sẻ công khai và rà soát lịch sử commit chứa dữ liệu gốc.

## Definition of Done

- [x] Mapping 13/13 kỹ thuật MITRE W02 sang nguồn telemetry.
- [x] Event reference và required detection fields được mô tả.
- [x] Đánh giá khả thi và ghi nhận telemetry gaps.
- [x] Đối chiếu các mẫu XML/JSON PoC hiện có.
- [ ] Software xác nhận các giả định còn mở bằng thử nghiệm.
- [ ] Data xác nhận thay đổi schema/mapping.
- [ ] Cyber/Data/Software thống nhất nghiệm thu issue #14.

**Trạng thái:** tài liệu hoàn thành bản v1 để review; chưa tuyên bố các detection được kiểm thử hay đóng issue.

Nguồn: `docs/research/software/w3/`, `docs/architecture/w3/`, `references/samples/raw/`.
