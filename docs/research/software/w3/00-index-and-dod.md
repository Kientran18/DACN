# Tuần 3 Windows Telemetry PoC và trạng thái nghiệm thu

Cập nhật 2026-10-19. Đã có mẫu thật trong repository. File mode của collector đã tái tạo đúng bốn JSON; chưa có bằng chứng Python live mode hoặc full pipeline/DuckDB.

## Môi trường và mẫu

- Windows: 10.0.19045; Sysmon: 15.22.
- Marker: EDR_POC_20261018_021142.
- Thời gian lần thử UTC: 2026-10-18T09:11:42.5934411Z đến 09:12:02.0878180Z.
- Báo cáo: [poc_run](../../../../references/samples/evidence/poc_run_20261018_021142.json).
- [Manifest](../../../../references/samples/raw/export_manifest.json): exported_utc 2026-10-18T09:14:37.0816904Z, sanitized=false.
- Config thu mẫu lưu tại [evidence](../../../../references/samples/evidence/sysmon-config.xml).
- Bộ raw: [references/samples/raw](../../../../references/samples/raw); JSON: [references/samples/json](../../../../references/samples/json).

## Kết quả

| Nhóm | Raw ID | JSON chính | Số mẫu JSON |
|---|---|---|---|
| Process | 1,5 | process.json (ID 1) | 3 |
| File | 11,26,29 | file.json (ID 11) | 2 |
| Registry | 12,13 | registry.json (ID 13) | 2 |
| Network/DNS | 3,22 | network.json (ID 3) | 1 |
| Quản trị Sysmon | 4,16 | Chưa xuất JSON riêng | Không áp dụng |

Báo cáo activities ghi đủ 5 bước ok. PowerShell export đã đọc Event Log; điều này không chứng minh collector Python live mode đã chạy. Raw/JSON vẫn chứa thông tin môi trường máy ảo; chưa thực hiện sanitize.

## Tiêu chí có bằng chứng

- [x] Có log Sysmon thực tế và thông tin phiên bản.
- [x] Có raw XML Process/File/Registry/Network.
- [x] Đọc Event Log qua PowerShell và xuất XML.
- [x] Collector Python file mode xuất JSON thật của bốn nhóm.
- [x] Mẫu đã commit vào repository.
- [ ] Có kết quả thử Python live mode trên Windows.
- [ ] Hoàn tất review Cyber/Data/Software có người, ngày, link.
- [ ] Ghi kết quả thí nghiệm giới hạn E1–E10 đầy đủ.

Hai mục live mode/E1–E10 là trạng thái kiểm chứng cần công khai, không tự mở rộng yêu cầu triển khai production. Chưa tuyên bố nghiệm thu 100% issue #16 hoặc #13 khi review còn thiếu.

## Tái lập

Từ thư mục gốc repo:

```powershell
python .\poc\sysmon-collector\sysmon_collector_poc.py --mode file --input .\references\samples\raw\raw_process_create_event1.xml --output .\tmp\process.json
python -m pytest -q .\poc\sysmon-collector\test_sysmon_collector_poc.py
```

File mode chỉ cần Python standard library. pytest chỉ cần trên máy phát triển khi chạy test. Live mode mới cần pywin32 và quyền đọc channel. Xem [schema](../../../architecture/w3/endpoint_event_schema_v1.md), [ma trận v2](../../cyber/mitre-detection-matrix-v2.md), [review](../../../project/week-01-03-review-and-ownership.md).

Các trang hướng dẫn cũ được giữ để tham khảo thao tác; phần trạng thái lịch sử không thay thế bằng chứng hiện tại ở trang này.
