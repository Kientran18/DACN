# Báo cáo W02 Data — Behavior-to-Telemetry Mapping và yêu cầu dữ liệu

**Issue:** [#8](https://github.com/Kientran18/DACN/issues/8) · **Trạng thái:** Bộ tài liệu nghiên cứu đã có, review liên nhóm cần xác minh. Không tuyên bố benchmark hay ETL/Gold Layer đã vận hành.

## 1. Mục tiêu và nguồn tham chiếu

Ánh xạ [13 MITRE techniques](../scope/selected_mitre_techniques_v1.md) do Cyber lựa chọn sang observable behavior, nguồn telemetry Windows/Sysmon, trường dùng rule detection và ứng viên trích xuất đặc trưng AI.

Tài liệu bàn giao gốc: [Behavior-to-Telemetry Mapping](week_02_behavior_telemetry_mapping.md), [Windows source mapping](../research/software/w2/02-telemetry-source-mapping-table%20(1).md), [local architecture mapping](../architecture/w2/phase_1_local_data_architecture_mapping.md).

## 2. Kết quả phân tích

- **Process:** Sysmon Event 1 (command line, image, parent lineage, hashes khi có); Event 5 chỉ có dữ liệu terminate, không bắt buộc parent.
- **File:** Event 11/26/29 cho tạo, xóa, PE creation theo config; không phải full file write/rename. Event 11 thường không cung cấp file size/hash.
- **Registry:** Event 12/13/14 theo cấu hình, phân loại thao tác và key path; `Details` không luôn đủ để suy ra registry native type.
- **Network/DNS:** Event 3 là socket metadata; Event 22 chỉ có DNS name/results/status, **không** chứa đầy đủ IP/port socket.
- **Common:** `hostname`, `timestamp`, `source`, `sysmon_event_id`, `record_id`, `event_id`, `process_guid` *nếu nguồn có*, `raw_data`. Những quyết định W3 được đối chiếu mẫu thực W3 và hiệu chỉnh tại [schema W5 v1.1](../architecture/w5/schema_reconciliation_and_dictionary_v1_1.md).

Bộ rule DET-001..010 của Cyber là **ý tưởng thiết kế**. Mô hình AI/Gold mới có ứng viên như command-line entropy, process tree và sliding-window counters; không có bằng chứng tất cả đã được hiện thực hoặc benchmark trong W2.

## 3. Nghiên cứu thuật toán, không phải benchmark

Có ba tài liệu nghiên cứu: [Recursive CTE](../research/data/w2/duckdb_process_tree_recursive_cte.md), [Window Aggregations](../research/data/w2/duckdb_sliding_window_aggregations.md), [Shannon Entropy](../research/data/w2/shannon_entropy_feature_extraction.md). Chúng minh họa cách tính/toán, **không phải log chạy kiểm thử hay số liệu đo CPU, RAM, truy vấn < 50 ms**. Vì vậy không chấp nhận phát biểu “PoC performance passed” hoặc “DoD đạt 100%” khi chưa có bằng chứng review.

## 4. Review và kế hoạch

Đề nghị Cyber xác nhận technique↔detection fields, Software xác nhận những Event ID bật trong cấu hình/lab và mọi giới hạn collection. Giữ các gap như task auditing, file write/rename, timestamp drift, event-specific nullable fields cho W3–W5. **Kết luận W2:** các sản phẩm thiết kế chính hiện diện; hồ sơ approval liên nhóm và kiểm chứng thực nghiệm còn thiếu.

**Nguồn:** [Issue #8](https://github.com/Kientran18/DACN/issues/8), [W3 gaps](../research/cyber/w3/telemetry_gap_list_v1.md), [W3 samples](../../references/samples/raw/export_manifest.json).
