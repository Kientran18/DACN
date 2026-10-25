# Báo cáo W03 Data — Endpoint Event Schema và Sysmon Raw-to-Silver Mapping

**Issue:** [#15](https://github.com/Kientran18/DACN/issues/15) · **Đối chiếu:** 25/10/2026 · **Trạng thái:** Đã có đặc tả và mapping W3, **không chứng nhận 100% DoD hoặc toàn bộ pipeline đã chạy**.

## 1. Sản phẩm đã có

- [Common envelope + 4 category schemas v1](../architecture/w3/endpoint_event_schema_v1.md).
- [Mapping Sysmon Raw → Silver v1](../architecture/w3/sysmon_raw_to_silver_mapping_v1.md).
- [Data Dictionary / Quality Notes](../architecture/w3/data_dictionary_and_quality_notes_v1.md).
- ADR [UUIDv5](../decisions/0001_deterministic_event_id_strategy.md), [ProcessGuid](../decisions/0002_process_correlation_via_guid.md), [raw preservation](../decisions/0003_raw_data_preservation_strategy.md).

Bộ tài liệu v1 là baseline lịch sử, không phải hợp đồng cuối cùng khi kết nối pipeline. Các khác biệt đã được phát hiện và chuẩn hóa tại [W5 Schema v1.1](../architecture/w5/schema_reconciliation_and_dictionary_v1_1.md) / [ADR 0006](../decisions/0006_schema_v1_1_reconciliation_and_dns_support.md).

## 2. Đối chiếu với dữ liệu thu thật

Bộ mẫu được tạo từ Windows lab ngày 18/10/2026, manifest ghi Sysmon 15.22. Các đường dẫn tại [raw XML](../../references/samples/raw/export_manifest.json), [JSON](../../references/samples/json/process.json) và [evidence run](../../references/samples/evidence/poc_run_20261018_021142.json).

| Nhóm | Mẫu hiện có | Ý nghĩa xác minh | Không được kết luận |
|---|---|---|---|
| Process | Event 1, 5 | Process GUID, image, PID, parent với Event 1; **Event 5 không có parent** | Không chứng minh malware/đủ tất cả rule |
| File | Event 11, 26, 29 | File create/delete/executable detect theo config | Không chứng minh full writes/rename/ransomware |
| Registry | Event 12, 13 | Key event, SetValue/Details | Không có tất cả loại registry, không ép suy luận type thành sự thật |
| Network | Event 3, 22 | Socket metadata, DNS fields | **Event 22 không có socket tuple**, không chứng minh C2 |

File-mode collector có code và output JSON; chưa có bằng chứng trong repository xác minh chạy live mode trên Windows bằng pywin32 hoặc Pydantic/DuckDB ingestion W3 end-to-end. Đừng dùng manifest activity run như log kết quả ETL.

## 3. Các sửa đổi cần cho tính tương thích

- Thống nhất tên `hostname` (không phải `host_id` trong JSON collector), `src_ip/src_port` (không phải `source_ip/source_port`).
- `timestamp` lấy `System.TimeCreated.SystemTime`; giữ `event_utc_time` từ `EventData.UtcTime` riêng vì mẫu Event 3/22 chênh ~12 giây.
- ID 5 không bắt buộc `ppid/parent_guid`, ID 22 không ép `src/dest` IP/port; Event 29 có payload riêng.
- `file.operation` là giá trị adapter chuẩn hóa từ Event ID, không giả định collector JSON đã xuất trường này.
- `event_id` UUIDv5 giúp idempotence khi đầu vào ổn định; log reset/RecordID reuse và DB unique/upsert vẫn cần xử lý.
- Raw XML/JSON được giữ ở Bronze; Silver có `raw_data` phục vụ tái xử lý, không đồng nhất hai dạng bảo toàn.

## 4. Review và DoD

| Tiêu chí | Bằng chứng | Đánh giá |
|---|---|---|
| Common envelope, 4 nhóm, field types | 3 tài liệu W3 | **Có tài liệu** |
| Real event samples bốn nhóm | `references/samples/` | **Có mẫu** |
| Schema v1 khớp mọi Event ID | Phát hiện nullability/naming/time gaps | **Chưa đạt ở v1**, có thiết kế chỉnh ở W5 |
| Chạy ETL/Pydantic/DuckDB E2E tại W3 | Chưa có log/artefact test rõ ràng | **Chưa xác minh** |
| Cyber và Software xác nhận độc lập | Chưa có review approval trên PR chính được kiểm tra | **Chưa xác minh** |

## 5. Đầu vào chuyển tiếp

W4 nghiên cứu công cụ theo kiến trúc/dữ liệu/security; W5 chốt event-specific contract, retention/lineage và schema v1.1. Không đưa chức năng Gold/AI chưa thực hiện vào bằng chứng W3.

**Lưu ý bảo mật:** manifest mẫu ghi `sanitized: false`, cần che thông tin định danh lab trước khi chia sẻ rộng.
