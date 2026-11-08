---
name: dacn-contract-review
description: Rà soát tương thích hợp đồng dữ liệu DACN. Tự dùng khi code hoặc tài liệu chạm bronze-event/1.0, bronze_contract, bronze-event.schema.json, bronze_to_silver_adapter, validator_poc, event_id UUIDv5, raw_xml và event_data, mã lỗi ERR_ hoặc C-00x, hoặc khi cần biết một thay đổi có phá vỡ tương thích giữa Software, Data, Cybersecurity không. Chỉ đọc và báo cáo, không sửa schema hay mapping. Không dùng để thiết kế pipeline mới (dacn-data-pipeline-storage).
---

# Rà soát hợp đồng dữ liệu DACN

Mục đích: phát hiện sớm sai lệch và nguy cơ breaking change giữa các module trong luồng dữ liệu, dựa trên **tài liệu và code thực tế**, không dựa trí nhớ.

## Nguyên tắc bất biến

- **Chỉ đọc và báo cáo.** Không sửa schema, field mapping, `EVENT_ID_NAMESPACE`, `HOST_NAMESPACE`, quy tắc sinh `event_id`, cơ chế raw preservation hay quy tắc chuẩn hóa. Muốn đổi thì nêu đề xuất và hỏi người dùng (`CLAUDE.md` mục 8.3).
- Phân biệt trạng thái: ADR 0001, 0002, 0003, 0005, 0006 là **Accepted**; ADR 0004 cần xác nhận liên nhóm; ADR 0007 là **PROPOSED**. Hợp đồng Bronze chung (`docs/architecture/w5/contracts/README.md`) là **đề xuất, chưa được phê duyệt chéo**. Không coi chúng là đã chốt khi chưa đúng như vậy.
- Mâu thuẫn giữa tài liệu và code: báo cáo rõ trước khi đề xuất bất kỳ thay đổi nào ảnh hưởng kiến trúc (`CLAUDE.md` mục 8.13).
- Không chạy lệnh xóa, reset, ghi đè; không cài gói hay tải mã từ Internet. Lệnh chỉ đọc hoặc test là đủ.

## Nguồn sự thật cần đọc trước (đọc thật, không suy đoán)

| Chủ đề | File |
|---|---|
| Hợp đồng Bronze chung, ownership, câu hỏi còn mở | `docs/architecture/w5/contracts/README.md` |
| JSON Schema Bronze | `poc/sysmon-collector/bronze-event.schema.json` |
| Dựng và validate Bronze | `poc/sysmon-collector/bronze_contract.py` |
| Chuẩn hóa collector, event identity | `poc/sysmon-collector/sysmon_collector_poc.py` |
| Adapter Bronze → Silver | `poc/sysmon-collector/bronze_to_silver_adapter.py` |
| Silver validator, DLQ | `src/pipeline/validator_poc.py` |
| DDL Silver/Gold (chưa có code thực thi) | `src/pipeline/sql/silver_gold_schema_and_views_v1_1.sql` |
| Ví dụ vàng (synthetic) | `docs/architecture/w5/contracts/examples/` |
| Đối chiếu field | `poc/sysmon-collector/contract_check.py` |
| Quyết định kiến trúc | `docs/decisions/0001`, `0002`, `0003`, `0005`, `0006` |
| Schema/từ điển, chất lượng, lineage | `docs/architecture/w5/schema_reconciliation_and_dictionary_v1_1.md`, `validation_quality_lineage_and_governance_v1.md` |

Cấu trúc có thể đã thay đổi; xác minh đường dẫn bằng `ls` trước khi dẫn chiếu.

## Luồng dữ liệu cần kiểm tra

```
Raw Sysmon XML
  → bronze_contract.build_bronze_record()    → bản ghi bronze-event/1.0 (JSON Schema)
  → bronze_to_silver_adapter.to_silver_input() → dict phẳng (fail closed)
  → validator_poc.SilverValidatorEngine      → Silver (4 nhóm) hoặc quarantine_dlq (ERR_*)
```

## Danh sách rà soát

### 1. Event identity (ADR 0001)
- [ ] `event_id = uuid5(EVENT_ID_NAMESPACE, "Computer|Channel|EventRecordID")`.
- [ ] Giá trị `EVENT_ID_NAMESPACE` trong `sysmon_collector_poc.py` và `EDR_NAMESPACE` trong `validator_poc.py` **giống hệt nhau** (logic nhân bản có chủ ý). Đối chiếu bằng cách đọc hai file, và bằng test `test_01_deterministic_uuidv5_matches_w3_real_samples`.
- [ ] Adapter tính lại `event_id` và `host_id` từ `hostname/channel/record_id`; sai lệch gây `BRONZE_IDENTITY_MISMATCH`.
- [ ] `host_id` dùng `HOST_NAMESPACE` trên hostname viết thường (`bronze_contract.host_id_for`); `host_id` không thay thế `hostname`.
- [ ] Rủi ro đã biết, ghi nhận không "giải quyết hộ": log reset/RecordID reuse và đổi hostname (ADR 0001, contracts README: epoch chưa có thiết kế).

### 2. Raw preservation (ADR 0003)
- [ ] Bronze giữ nguyên `raw_xml` và `event_data` (tên field gốc EventData).
- [ ] Adapter parse lại `raw_xml` và so với `event_data`, `hostname`, `channel`, `record_id`, `sysmon_event_id`, `time_created`; sai lệch gây `BRONZE_RAW_MISMATCH`.
- [ ] Silver giữ `raw_data` là bản sao của `event_data`; không field nào bị bỏ hay điền giá trị giả (Zero Data Fabrication).
- [ ] `time_created` lấy từ `System.TimeCreated.SystemTime`, không thay bằng `EventData.UtcTime`.

### 3. JSON Schema (`bronze-event/1.0`)
- [ ] Danh sách `required` và `properties` của schema khớp các key mà `build_bronze_record` thực sự sinh ra (cả hai chiều).
- [ ] Mọi field thêm vào bản ghi đều có trong schema; kiểm tra `additionalProperties` của schema trước khi kết luận.
- [ ] `schema_version` là `bronze-event/1.0` ở schema, `SCHEMA_VERSION` và ví dụ.

### 4. Adapter Bronze → Silver
- [ ] Tên field đầu ra khớp những gì `SilverValidatorEngine.process_record` đọc (`timestamp`, `sysmon_event_id`, `event_type`, `event_id`, `channel`, `record_id`, `hostname`, `process_guid`, `raw_data`).
- [ ] `process_guid` có thể vắng với Sysmon 4/16, và Event 5/22 có các ràng buộc riêng; kiểm tra theo contracts README, không tự khẳng định.
- [ ] `bronze_source` là metadata tham chiếu, **chưa phải cột Silver được lưu**.

### 5. Silver validator và Quarantine/DLQ
- [ ] `SUPPORTED_SYSMON_IDS` so với các ID mà collector có thể phát (collector có thêm 4, 16; validator hiện không hỗ trợ) - báo cáo chênh lệch, không tự khẳng định đó là lỗi.
- [ ] Bản ghi không qua kiểm tra vào `quarantine_dlq` với mã `ERR_*`; không bị bỏ âm thầm.
- [ ] Tên event type: collector (`REGISTRY_RENAME_KEY`, `NETWORK_ACCEPT`, `FILE_STREAM_CREATE`...) và `EVENT_ID_TO_TYPE_DEFAULT` của validator (`REGISTRY_RENAME`, `FILE_STREAM_HASH`...) **không hoàn toàn trùng**; đây là quyết định chờ Q-X3. Báo cáo vị trí lệch, không tự thống nhất.
- [ ] Mã lỗi collector (`C-001`, `C-002`) so với mã lỗi validator (`ERR_*`) và test kỳ vọng chúng.

### 6. Ảnh hưởng liên nhóm
Với mỗi sai lệch hoặc thay đổi đề xuất, ghi nhóm bị ảnh hưởng: **Software** (collector, Bronze), **Data** (adapter, validator, Silver/Gold), **Cybersecurity** (traceability, Detection/Alert).

## Phân loại nguy cơ breaking change

| Mức | Ví dụ | Hành động |
|---|---|---|
| **Breaking** | Đổi namespace UUID, công thức `event_id`, tên/kiểu field trong schema, bỏ `raw_xml`/`event_data`, đổi `schema_version` | Dừng, báo cáo, cần phê duyệt liên nhóm |
| **Có thể breaking** | Thêm field bắt buộc, siết kiểu dữ liệu, đổi tên event type, đổi mã lỗi `ERR_*` | Báo cáo kèm danh sách consumer bị ảnh hưởng |
| **Tương thích** | Thêm field tùy chọn có mặc định rõ, thêm test, sửa tài liệu | Ghi nhận |

Để kiểm tra consumer bị ảnh hưởng, dùng Grep tên field/hằng số trong `poc/`, `src/`, `tests/`, `docs/`.

## Cách chạy kiểm chứng (chỉ đọc/test, từ thư mục gốc repository)

```bash
python -m pytest -q poc/sysmon-collector
python -m pytest -q tests/
python poc/sysmon-collector/contract_check.py --samples references/samples --out /tmp/coverage_report.md
```

Lệnh cuối ghi báo cáo ra file ngoài repository; không ghi vào thư mục dự án. Kết quả test phải kèm lệnh và thời điểm chạy; không sao chép số liệu từ `CLAUDE.md` mà không chạy lại. Dữ liệu trong `references/samples/` chưa khử định danh hoàn toàn: không trích tên máy/người dùng vào báo cáo.

## Mẫu báo cáo

```markdown
# Báo cáo rà soát hợp đồng — [phạm vi], [ngày]
## Phạm vi và tài liệu đã đọc
## Kết quả theo hạng mục (Đạt / Lệch / Không xác minh được, kèm file:dòng)
## Nguy cơ breaking change (mức, consumer, nhóm bị ảnh hưởng)
## Mâu thuẫn giữa tài liệu và code
## Kết quả test (lệnh, thời điểm, số pass/fail)
## Đề xuất (chỉ đề xuất; thay đổi contract cần phê duyệt)
```

Phân biệt rõ phần CURRENT STATE (có code và test) với TARGET (segment sealing, manifest, replay, epoch: chưa tồn tại).

## Phối hợp với skill khác
- Trước đó: dacn-edr-architecture hoặc dacn-data-pipeline-storage khi đề xuất đổi
- Cùng lúc: dacn-sysmon-telemetry
- Sau đó: dacn-end-to-end-acceptance
