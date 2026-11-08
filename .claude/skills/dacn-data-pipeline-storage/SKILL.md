---
name: dacn-data-pipeline-storage
description: Pipeline và lưu trữ dữ liệu DACN. Tự dùng khi phát triển hoặc đánh giá Bronze, Silver, Gold, ingestion, validation, dedup, Quarantine và DLQ, replay, DuckDB và Parquet, truy vấn, retention, lineage về raw, và chất lượng dữ liệu như quarantine ratio, time skew, event loss. Không đổi canonical contract khi chưa được duyệt. Không dùng chỉ để đối chiếu tương thích hợp đồng (dacn-contract-review).
---

# Data Pipeline và lưu trữ

## Ranh giới
- Rà soát tương thích hợp đồng: `dacn-contract-review`. Skill này lo **phát triển/đánh giá pipeline, lưu trữ, chất lượng và quan sát dữ liệu**.
- Chi tiết chỉ số chất lượng: [references/data-quality-metrics.md](references/data-quality-metrics.md).

## Hiện trạng (xác minh lại bằng code)
`validator_poc.py` là PoC trong bộ nhớ (`SilverValidatorEngine`, bảng DuckDB in-memory); DDL `src/pipeline/sql/silver_gold_schema_and_views_v1_1.sql` chưa có code thực thi. Chưa có: sealed segment writer, manifest, ingest ledger, replay bền vững, Gold/feature store, retention job (`CLAUDE.md` mục 3.1, kiến trúc v2 mục 4, 10).

## Đọc trước
ADR 0001, 0002, 0003, 0005, 0006; `docs/architecture/w5/data_pipeline_architecture_and_contracts_v1.md`, `schema_reconciliation_and_dictionary_v1_1.md`, `validation_quality_lineage_and_governance_v1.md`, `contracts/README.md`; `docs/research/data/w5/duckdb_olap_indexing_and_feature_windowing.md`; `docs/research/software/w5/03-local-storage-and-pipeline-integration-design.md`; `src/pipeline/validator_poc.py`.

## Quy trình
1. **Xác định tầng và hợp đồng:** Bronze (canonical `bronze-event/1.0`, bất biến sau seal) → Silver (4 nhóm process/file/registry/network-DNS) → Gold (feature/alert, thiết kế). Ghi owner từng giao diện.
2. **Validation theo từng loại sự kiện:** field bắt buộc khác nhau (Event 5 không có parent, DNS 22 không có socket, Event 4/16 không có ProcessGuid). Thiếu field bắt buộc → Quarantine với mã `ERR_*`, **không điền mặc định**.
3. **Dedup và replay:** khóa `event_id` xác định; nạp idempotent (`INSERT OR IGNORE` / `ON CONFLICT DO NOTHING` theo tài liệu thiết kế); replay chạy trên segment đã seal với `run_id` mới. Rủi ro reset `EventRecordID`/đổi hostname chỉ ghi nhận, giải pháp epoch là P0 cần review.
4. **Lineage hai chiều:** Silver → Bronze (`segment_id`, offset/dòng, hash, `mapper_version`) → raw XML; mọi Gold/alert giữ `source_event_ids[]`. `bronze_source` hiện chỉ là metadata PoC, chưa phải cột Silver.
5. **Lưu trữ:** DuckDB single-writer; UI/Detection đọc snapshot/read-only; Parquet cho Gold. Index và truy vấn theo `process_guid` + host + thời gian, không JOIN theo PID (ADR 0002). Kiểm tra hành vi file lock/rename trên Windows trước khi chốt.
6. **Retention:** theo tầng với quota và `RAW_EXPIRED`/evidence hold; số ngày trong tài liệu là **đề xuất**, không phải mặc định. Dữ liệu lab có thể chứa định danh thật: không công bố.
7. **Chất lượng và quan sát:** thu chỉ số theo reference (completeness, validity, uniqueness, consistency, timeliness, quarantine ratio, event loss, time skew). Ngưỡng SLO trong tài liệu là mục tiêu đề xuất; chỉ báo "đạt" khi có số đo thật từ lần chạy cụ thể.

## Nguyên tắc không được vi phạm
- Zero Data Fabrication: không tạo GUID, hash, IP, timestamp để bản ghi qua kiểm tra; không bỏ bản ghi âm thầm.
- Giữ nguyên `raw_xml`/`event_data`/`raw_data` (ADR 0003). Không đổi UUIDv5, namespace, schema, mapping khi chưa được duyệt; không sửa Bronze đã seal; reprocess = dựng lại Silver từ Bronze.
- Không import chéo giữa collector và validator để "gộp logic nhân bản" khi chưa có quyết định; ghi nhận thay vì sửa.
- Không tuyên bố pipeline chạy bền vững/liên tục khi mới có PoC trong bộ nhớ.

## Kiểm tra kết quả
Test dùng `references/samples/` hoặc fixture synthetic gắn nhãn; chạy `python -m pytest -q poc/sysmon-collector` và `python -m pytest -q tests/` từ thư mục gốc. Kiểm tra truy vết hai chiều trên ít nhất một chuỗi sự kiện cụ thể. Báo cáo số liệu kèm lệnh, dữ liệu đầu vào và thời điểm.

## Đầu ra
Thiết kế/patch theo yêu cầu cụ thể kèm: sơ đồ luồng và hợp đồng giao diện, bảng mã lỗi → hành vi, kế hoạch migration schema (nếu có), kết quả chỉ số chất lượng (có nguồn đo), ảnh hưởng tới Software/Cyber.

## Cần hỏi người dùng
Trước khi đổi bảng/cột Silver hay DDL, thêm bảng lineage/ledger, đổi công thức `event_id`, chọn công cụ lưu trữ mới (ví dụ SQLite cho state), hoặc đặt ngưỡng retention/SLO chính thức.

## Phối hợp với skill khác
- Trước đó: dacn-contract-review
- Cùng lúc: test-driven-development
- Sau đó: dacn-detection-engine, dacn-end-to-end-acceptance
