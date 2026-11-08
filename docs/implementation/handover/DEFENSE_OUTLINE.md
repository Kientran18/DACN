# EDR — Dàn ý báo cáo và bảo vệ (PH12-T05)

> Dàn ý để cả nhóm hoàn thiện; số liệu lấy từ báo cáo sinh tự động. Chỉ nêu những gì có bằng chứng.

1. **Vấn đề và mục tiêu:** EPP/EDR local-first cho Windows 10/11; chuỗi telemetry → pipeline → detection → alert → investigation → safe response → dashboard.
2. **Kiến trúc:** modular monolith, Medallion (Bronze sealed JSONL → Silver DuckDB), lineage về raw_xml, ADR 0001–0007 ([EDR_TARGET_ARCHITECTURE.md](../EDR_TARGET_ARCHITECTURE.md)).
3. **Điểm nhấn thiết kế:**
   - at-least-once + dedup `event_id` UUIDv5; replay xác định.
   - Kết quả phát hiện 4 trạng thái, trong đó `INSUFFICIENT_TELEMETRY` tách khỏi alert đe dọa.
   - Response an toàn: dry-run, hai khóa, phê duyệt, xác minh danh tính, thư mục lab.
   - Dashboard không dùng CDN, dữ liệu chỉ vào DOM qua `textContent`, CSP chặt.
4. **Demo** ([DEMO_RUNBOOK.md](../acceptance/DEMO_RUNBOOK.md)): SC-06 → SC-01 → SC-03 → SC-08 → SC-07. Nếu dùng dữ liệu lưu sẵn, nói rõ trên màn hình.
5. **Kiểm thử:** 201 test, 43 AT; trình bày thẳng thắn PASS/PARTIAL/NOT RUN ([TEST_REPORT.md](TEST_REPORT.md)).
6. **Bài học:** lỗi chỉ lộ khi chạy tiến trình thật hoặc nhìn ảnh chụp; giá trị của việc tách mức bằng chứng L và W.
7. **Hạn chế và hướng phát triển** ([LIMITATIONS_AND_RISKS.md](LIMITATIONS_AND_RISKS.md)): Windows, hiệu chỉnh rule, ML, retention, dịch vụ Windows.
8. **Câu hỏi dự kiến:** "Có phát hiện được malware thật không?" → chỉ khẳng định trên tập kịch bản đã chạy, chưa có tỷ lệ. "Có chống bị tắt không?" → không, user-space. "Vì sao không có TLS?" → loopback.
