---
name: dacn-detection-engine
description: Dùng khi thiết kế hoặc phát triển Detection Engine của DACN - rule model và registry, evaluation contract (MATCH / NO_MATCH / INSUFFICIENT_TELEMETRY / PENDING_LATE_EVENTS), correlation theo process_guid và cửa sổ thời gian, IOC/hash matching, severity, versioning rule, DetectionResult và kết nối với Silver. Chỉ dùng trường dữ liệu thực sự có; Detection Engine hiện chưa tồn tại.
---

# Detection Engine

## Hiện trạng
**Chưa có engine, rule engine hay alert store** (`CLAUDE.md` mục 3.1). Có: đặc tả DET-001..010 và yêu cầu trường (tài liệu Cyber), DDL `gold_process_features`, `gold_security_alerts`, các view lineage, contract nháp trong kiến trúc v2 mục 6. Issue Detection (ví dụ #38–#40) nên đọc bằng công cụ GitHub, không dựa danh sách trong `CLAUDE.md`.

## Đọc trước
`docs/architecture/local-edr-reference-architecture-v2.md` mục 6 (rule contract nháp, evaluation contract), `docs/research/cyber/w5/01-detection-required-fields-and-mitre-to-data.md` (mục 3: điều kiện tối thiểu DET-001..010), `04-telemetry-gaps-and-w06-w09-backlog.md`, `02-alert-to-source-traceability-requirements.md`, `docs/research/cyber/initial_detection_notes.md`, `docs/scope/selected_mitre_techniques_v1.md`, `src/pipeline/sql/silver_gold_schema_and_views_v1_1.sql`, ADR 0002 (dùng `process_guid`, không dùng PID).

## Quy trình
1. **Xác định rule cần thiết kế** và liệt kê **trường bắt buộc** cho từng event type, đối chiếu cột Silver có thật (`silver_process_events`, `silver_file_events`, `silver_registry_events`, `silver_network_events`) và `raw_data`. Trường chưa có cột → ghi "chỉ có trong `raw_data`" hoặc "không có".
2. **Rule model:** `rule_id` (khuyến nghị namespace `DACN-DET-xxx`, giữ `legacy_id`), `rule_version`, `event_types`, `required_fields`, `correlation_keys`, `time_window`, `severity`, `response_policy`. Cửa sổ thời gian ghi `TBD` cho đến khi có test có nhãn; mặc định `alert_only`.
3. **Evaluation contract:** bốn kết quả `MATCH | NO_MATCH | INSUFFICIENT_TELEMETRY | PENDING_LATE_EVENTS`. Thiếu dữ liệu **không** là `NO_MATCH`. `DetectionResult` mang `rule_id/version`, `matched_fields`, `missing_fields`, `coverage_status`, `contributing_event_ids[]`, tham chiếu raw, `severity` kèm lý do.
4. **Correlation:** khóa `(hostname, process_guid, parent_guid)` hoặc `(hostname, normalized_path)` + cửa sổ + watermark cho sự kiện đến muộn. Xử lý time skew (SystemTime vs UtcTime). Trạng thái correlation phải replay-safe và idempotent.
5. **IOC/Signature:** so khớp hash SHA-256 và allowlist có nguồn và version; không tự gọi feed bên ngoài.
6. **Tích hợp pipeline:** đọc Silver snapshot/read-only (DuckDB single-writer), ghi kết quả vào bảng alert; mỗi kết quả resolve được về Silver `event_id` rồi Bronze.
7. **Migration từ PoC:** từ một rule đơn sự kiện (ví dụ DET-003) → rule correlation (DET-010) → state/late events; mỗi bước có fixture dương/âm/thiếu dữ liệu.

## Nguyên tắc không được vi phạm
- Chỉ dùng trường có trong hợp đồng Silver/Bronze hoặc `raw_data` đã giữ. Không bịa field, GUID, hash, IP; không dùng PID làm khóa JOIN.
- Không nâng severity Critical từ một sự kiện lẻ; không tuyên bố ransomware/C2 từ Sysmon 11/26 hay cổng 443 (tài liệu Cyber đánh dấu DET-008 bị chặn do thiếu telemetry).
- Không thay đổi canonical contract hay schema Silver/Gold; thay đổi cột chỉ ở mức đề xuất.
- Không coi tên `DETxxxx` của MITRE Detection Strategy là rule nội bộ (xem `dacn-detection-rules-mitre`).
- Response luôn qua policy gate; Detection không tự thực thi hành động (`dacn-response-safety`).

## Kiểm tra kết quả
Mỗi rule có: bảng trường bắt buộc, ba nhóm fixture (match / no-match / thiếu telemetry), kiểm tra truy vết (`contributing_event_ids` tồn tại), kiểm tra replay không sinh alert trùng. Cách đo chất lượng: `dacn-detection-validation`. Test theo `test-driven-development`.

## Đầu ra
Tài liệu thiết kế hoặc code theo yêu cầu: rule model, evaluation contract, sơ đồ luồng, danh sách trường cần thêm ở Silver (đề xuất), phụ thuộc Data/Software, rủi ro và câu hỏi mở.

## Cần hỏi người dùng
Đặt ID rule và schema `DetectionResult` chính thức (chạm Cyber + Data), thêm cột Silver/Gold, đổi ngưỡng/cửa sổ, chọn thư viện (ví dụ cho Sigma/YARA), hoặc đưa rule vào repository thật.
