# Backlog nghiên cứu 12 tuần

Bám kế hoạch 12 tuần cập nhật do nhóm cung cấp ngày 2026-10-19. Đây là backlog mục tiêu, không phải bảng xác nhận hoàn thành. Giai đoạn này ưu tiên nghiên cứu và thiết kế; triển khai đầy đủ chuyển sang Luận văn Tốt nghiệp.

| Tuần | Mục tiêu và đầu ra | Lead | Đầu vào | Liên kết |
|---|---|---|---|---|
| 1 | Scope, phân công, backlog, repository/board, architecture v0.1 | Cả nhóm | Bài toán | #1–#4 |
| 2 | 10–15 MITRE techniques, Threat Model, behavior/telemetry mapping, Matrix v1 | Cyber | Scope | #6–#9 |
| 3 | Telemetry catalogue, mẫu thật, schema/mapping v1, collector PoC/JSON, Matrix v2 | Software PoC; Cyber/Data xác minh | Tuần 2 | #13–#16 |
| 4 | So sánh Wazuh, Sysmon, osquery, Velociraptor, Atomic Red Team; chốt dùng/tham khảo/loại và review M1 | Cả nhóm | Tuần 1–3 | #19–#22 |
| 5 | Thiết kế pipeline Bronze/Silver/Gold, dictionary, validation, retention, lineage | Data | Schema và đánh giá công cụ | Chưa tạo issue |
| 6 | Detection architecture, rule model, severity và alert traceability | Cyber | Mapping và pipeline | Chưa tạo issue |
| 7 | Static features, whitelist/signature schema, suspicious candidate review | Cyber/Data; Software interface | Detection design | Chưa tạo issue |
| 8 | AI risk scoring/anomaly design, feature/dataset/baseline/evaluation plan | Data/AI | Features và detection | Chưa tạo issue |
| 9 | Process tree, timeline, incident, hunting queries, response và wireframe | Cyber; Data/Software hỗ trợ | Schema, detection | Chưa tạo issue |
| 10 | Test Scenario Matrix, expected telemetry/alert, môi trường và demo plan | Cả nhóm | MITRE và thiết kế | Chưa tạo issue |
| 11 | Review dependency/interface; hoàn thiện component/data/sequence diagrams và ADR | Cả nhóm | Thiết kế các module | Chưa tạo issue |
| 12 | Validation, báo cáo, slide, architecture package và backlog Phase 2 | Cả nhóm | Tuần 1–11 | Chưa tạo issue |

## Các mốc

- M1 cuối tuần 4: nền tảng EPP/EDR, MITRE, telemetry thực tế và đánh giá công cụ.
- M2 cuối tuần 8: thiết kế lõi Data Pipeline, Detection, Static/Whitelist/Signature, AI.
- M3 cuối tuần 10: Investigation/Response và kịch bản kiểm thử/demo.
- M4 cuối tuần 12: kiến trúc, báo cáo và chuyển giao Phase 2.

PoC mở rộng từ collector đến normalize, 2–5 rules, alert/dashboard chỉ làm nếu đủ thời gian. Minimal collector và mẫu thật của tuần 3 vẫn là đầu ra cần có.
