# Week 3 – Issue #16: Windows Telemetry Collection PoC – Index và trạng thái DoD

**Trạng thái tổng thể:** Đã viết xong cấu hình, script, mã PoC và tài liệu. **Chưa có dữ liệu thật**: các mẫu sự kiện, kết quả cài đặt Sysmon và buổi review phải thực hiện trên VM lab.

## Những gì đã và chưa được kiểm tra

| Thành phần | Đã kiểm tra | Chưa kiểm tra |
|---|---|---|
| `sysmon_collector_poc.py` (parse, normalize, CLI) | 13 unit test đạt (pytest), chạy trên **sự kiện giả lập** viết tay | Chạy live với `pywin32` trên Windows |
| `sysmon-config.xml` | XML hợp lệ về cú pháp | Chưa cài trên Sysmon thật; chưa kiểm tra `Sysmon64.exe -s` và tên phần tử (`DnsLookup`, `FileExecutableDetected`...) |
| `run-poc-activities.ps1`, `export-samples.ps1` | Đọc lại cú pháp bằng mắt | **Chưa chạy lần nào** (container không có PowerShell/Windows) |
| Các giả định về hành vi Sysmon (ghi đè, rename, registry...) | — | Cần thí nghiệm E1 đến E10 trong file 09 |

## Deliverables

| Deliverable | File | Trạng thái |
|---|---|---|
| Windows Telemetry Lab Setup Notes | `docs/01-windows-telemetry-lab-setup-notes.md` | Viết xong, chưa thực hành |
| Sysmon Configuration v1 | `configs/sysmon/sysmon-config.xml` + `docs/02-sysmon-configuration-v1.md` | Viết xong, chưa cài thử |
| Raw Process Event Sample | `docs/03-raw-process-event-sample.md` → `samples/raw/` | **Chờ thu thập** |
| Raw File Event Sample | `docs/04-raw-file-event-sample.md` → `samples/raw/` | **Chờ thu thập** |
| Raw Registry Event Sample | `docs/05-raw-registry-event-sample.md` → `samples/raw/` | **Chờ thu thập** |
| Raw Network Event Sample | `docs/06-raw-network-event-sample.md` → `samples/raw/` | **Chờ thu thập** |
| Minimal Event Collector PoC | `poc/sysmon_collector_poc.py` + `docs/07-minimal-event-collector-poc.md` | Code xong, test giả lập đạt |
| JSON Event Sample | `docs/08-json-event-sample.md` → `samples/json/` | Chỉ có mẫu giả lập; **chờ mẫu thật** |
| Collection Limitations v1 | `docs/09-collection-limitations-v1.md` | Viết xong dưới dạng giả thuyết, chờ xác minh |
| (Task) Share samples with Cyber and Data | `docs/10-share-samples-with-cyber-and-data.md` | Có mẫu thông báo và checklist |

## Definition of Done

- [ ] Sysmon is installed and operational
- [ ] Sysmon events are visible in Windows Event Log
- [ ] Real process event has been collected
- [ ] Real file event has been inspected or collected
- [ ] Real registry event has been inspected or collected
- [ ] Real network event has been inspected or collected
- [ ] At least one event type can be read programmatically *(code sẵn sàng, mới test giả lập)*
- [ ] At least one raw event can be exported to JSON *(như trên)*
- [ ] Sample events are committed to the repository
- [ ] Required permissions and limitations are documented *(đã viết, chưa xác minh)*
- [ ] Cyber and Data have reviewed the collected samples

Chỉ tick khi đã làm thật trên VM. Issue #16 ở trạng thái Open cho đến khi hoàn tất.

## Thứ tự thực hiện trên VM lab

1. Chụp snapshot sạch, cài Sysmon với config v1 (file 01, mục 3 đến 5).
2. Chạy `run-poc-activities.ps1` (không cần Admin) và ghi lại marker `EDR_POC_<timestamp>`.
3. Chạy `export-samples.ps1 -Sanitize` bằng Admin để xuất XML thô vào `samples/raw/`.
4. Dán sự kiện thật vào các file 03 đến 06, đánh dấu bảng kiểm tra trường.
5. Chạy collector: `python poc/sysmon_collector_poc.py --mode file --input samples/raw/recent_events_all.xml ...`, rồi thử `--mode live` bằng Admin.
6. Làm các thí nghiệm E1 đến E10 (file 09), cập nhật file 02 và 09 theo kết quả.
7. Commit mẫu, gửi cho Cyber và Data (file 10).

*Ghi chú:* issue #16 có một dòng task trống ở cuối danh sách, nên xóa đi.
