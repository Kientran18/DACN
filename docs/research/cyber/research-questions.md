# Câu hỏi nghiên cứu bảo mật cần chốt

Ngày bổ sung 2026-10-19. Owner Cyber; cần review Data/Software, chưa phải các quyết định đã thống nhất.

| Câu hỏi | Đầu ra cần chốt | Mốc |
|---|---|---|
| Hành vi nào quan sát được bằng Sysmon và hành vi nào chỉ có proxy? | MITRE Matrix v2 và telemetry gaps | Tuần 3/M1 |
| DET-008 dùng create/delete ra sao khi thiếu write/rename/entropy file? | Điều kiện, giới hạn, false positives và nhu cầu nguồn bổ sung | Tuần 3–6 |
| DET-007 phân biệt process exit với tampering bằng nguồn nào? | Service/watchdog design, heartbeat và giới hạn | Tuần 6/9 |
| Dùng/tham khảo/loại công cụ nào theo tiêu chí bảo mật? | Ma trận tuần 4, quyết định có dẫn nguồn | Tuần 4 |
| Rule có metadata, severity và traceability thế nào? | Rule/alert model, liên kết source events | Tuần 6 |
| Whitelist, signature và static analysis phối hợp ra sao? | Schema, review workflow và giới hạn tin cậy | Tuần 7 |
| AI hỗ trợ quyết định nào và đo chất lượng thế nào? | Risk/anomaly design, baseline, dataset và metrics | Tuần 8 |
| Response nào an toàn và cần người xác nhận? | Investigation/response design và quyền | Tuần 9 |
| Kịch bản nào kiểm chứng đúng telemetry và expected alert? | Test Scenario Matrix có cleanup và ground truth | Tuần 10 |

Không coi đủ field là đủ phát hiện technique. Các chỉ số độ chính xác/tài nguyên chỉ được báo cáo là kết quả khi có phép đo và dữ liệu tái lập.
