---
name: dacn-alert-incident-management
description: Dùng khi thiết kế hoặc phát triển alert và incident của DACN - alert schema, severity, deduplication, correlation, vòng đời incident, bằng chứng sự kiện, timeline điều tra, acknowledgement, audit trail, truy vết alert về Silver và Bronze. Alert store hiện chưa tồn tại; chỉ dùng trường thực có.
---

# Alert và Incident

## Hiện trạng
Chưa có Alert Manager hay alert store chạy được. Có DDL `gold_security_alerts` trong `src/pipeline/sql/silver_gold_schema_and_views_v1_1.sql` (thiết kế) và yêu cầu truy vết của Cyber. Đọc lại DDL trước khi dẫn cột; nội dung dưới là điểm cần đối chiếu, không phải kết luận.

## Đọc trước
`docs/research/cyber/w5/02-alert-to-source-traceability-requirements.md`, `04-telemetry-gaps-and-w06-w09-backlog.md` (mục 2: alert/investigation), `docs/architecture/local-edr-reference-architecture-v2.md` mục 6.3, 7.1; DDL ở trên; `docs/scope/phase-1-scope.md`; NIST SP 800-61r3 (vòng đời xử lý sự cố, tham khảo khái niệm).

## Quy trình
1. **Schema alert:** bắt đầu từ `DetectionResult` (`dacn-detection-engine`) và DDL hiện có. Trường tối thiểu để truy vết: `alert_id`, `rule_id`, `rule_version`, `severity` + lý do, `hostname`, `contributing_event_ids[]`, tham chiếu Bronze (segment/offset/hash), `matched_fields`, `missing_fields`, `coverage_status`, thời gian first/last seen.
2. **Điểm cần đối chiếu với DDL (ghi nhận, không tự sửa):**
   - `process_guid`/`image_path` đang `NOT NULL`: health alert hoặc rule không gắn với một process sẽ không lưu được.
   - `mitre_technique_id` đơn trị trong khi rule contract nháp có danh sách technique.
   - Chưa thấy cột `rule_version`, `coverage_status`, `missing_fields`, trạng thái incident, người xử lý.
   - Chưa thấy bảng audit/approval/incident.
3. **Severity:** có lý do ghi lại; không Critical từ một sự kiện đơn; `confidence` chỉ ghi khi đã định nghĩa cách tính.
4. **Deduplication/grouping:** khóa gợi ý `rule_id + host + subject (process_guid hoặc path) + cửa sổ có giới hạn`; ghi lý do gộp (suppression reason); không gộp actor/host khác nhau; replay không tạo alert trùng.
5. **Correlation sang incident:** liên kết nhiều alert theo process tree, host, thời gian; giữ `alert_ids[]`.
6. **Vòng đời:** `NEW → TRIAGED → INVESTIGATING → (FALSE_POSITIVE | CONFIRMED | CLOSED)` (kiến trúc v2 mục 7.1), mỗi chuyển trạng thái có người, thời điểm, ghi chú; không ghi "confirmed" khi chỉ có một chỉ báo.
7. **Bằng chứng và retention:** alert mở → evidence hold; raw hết hạn → `RAW_EXPIRED`/`PARTIAL`, không xóa tham chiếu.
8. **Audit trail:** mọi thao tác (acknowledge, đổi trạng thái, override, approval) append-only, có actor và lý do.
9. **Health alert tách khỏi threat alert.**

## Nguyên tắc không được vi phạm
- Alert phải truy vết được về `event_id` Silver và raw XML Bronze, hoặc đánh dấu PARTIAL; không tạo event giả để lấp.
- Không đổi DDL hay contract khi chưa được phê duyệt; đề xuất thay đổi kèm ảnh hưởng tới Data/Cyber/Software.
- Không tự thực thi response từ alert (`dacn-response-safety`).
- Không đưa dữ liệu nhận dạng thật vào ví dụ.

## Kiểm tra kết quả
Test truy vết hai chiều (TRC-01 trong kiến trúc v2): từ `alert_id` đến từng `contributing_event_ids` và raw; từ một event ra các alert liên quan. Test dedup/replay idempotent. Test chuyển trạng thái hợp lệ/không hợp lệ.

## Đầu ra
Đặc tả hoặc code theo yêu cầu: schema alert/incident, máy trạng thái, quy tắc dedup, bảng trường thiếu so với DDL, test truy vết đề xuất.

## Cần hỏi người dùng
Đặt schema alert chính thức, thêm bảng incident/audit, đổi ràng buộc `NOT NULL`, chọn quy tắc dedup và cửa sổ.
