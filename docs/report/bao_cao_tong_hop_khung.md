# Khung báo cáo tổng hợp đồ án chuyên ngành (Giai đoạn 1)

> Đề tài: *Tìm hiểu và hiện thực một hệ thống bảo mật cho thiết bị đầu cuối*. Đây là **khung** (2026-11-25): đề mục và nguồn tư liệu cho từng chương. Số liệu phải lấy từ báo cáo kiểm thử và nghiệm thu tại thời điểm viết, kèm ngày đo; không chép con số trong khung này như kết quả. Các chỗ `[CẦN SỐ ĐO]` là phần chưa có bằng chứng.

## Chương 1. Giới thiệu
1.1. Bối cảnh: tấn công vào endpoint, giới hạn của antivirus truyền thống, vai trò EPP/EDR.
1.2. Mục tiêu đề tài (theo đề cương): giám sát hành vi, phát hiện bằng quy tắc, AI hỗ trợ phát hiện bất thường, tổng hợp rủi ro, phản ứng có kiểm soát, quản lý tập trung trên giao diện.
1.3. Phạm vi Giai đoạn 1: Windows 10/11, local-first, một endpoint, user-space (`docs/scope/phase-1-scope.md`). Các nội dung ngoài phạm vi: XDR, SOAR, cụm máy chủ, kernel driver.
1.4. Cấu trúc báo cáo.

## Chương 2. Cơ sở lý thuyết
2.1. EPP và EDR; telemetry endpoint; Sysmon (`docs/research/cyber/endpoint-security-concepts.md`).
2.2. MITRE ATT&CK và cách ánh xạ rule ↔ technique có căn cứ (`docs/research/cyber/w5/`).
2.3. Kiến trúc dữ liệu Medallion (Bronze/Silver/Gold), định danh sự kiện UUIDv5, bảo tồn dữ liệu thô (ADR 0001–0003).
2.4. Phát hiện bằng chữ ký, rule, correlation và hành vi; IOC và allowlist.
2.5. AI cho bảo mật endpoint: mô hình tĩnh và mô hình hành vi, anomaly detection, UEBA, risk scoring (`docs/research/ai/01-ai-cho-bao-mat-endpoint.md`).
2.6. Quy trình xử lý sự cố NIST SP 800-61 và quản lý cấu hình NIST SP 800-128 (`docs/implementation/NIST_MAPPING.md`).
2.7. Khảo sát công cụ: Wazuh, Sysmon, so sánh lưu trữ (`docs/report/week_04_tool_evaluation_report.md`).

## Chương 3. Phân tích và thiết kế
3.1. Yêu cầu chức năng và phi chức năng; ràng buộc VM 2 GB.
3.2. Kiến trúc tổng thể: modular monolith; data plane, control plane, operations (`docs/implementation/EDR_TARGET_ARCHITECTURE.md`, ADR 0007 đề xuất).
3.3. Hợp đồng dữ liệu: Bronze `bronze-event/1.0`, Silver DDL v1.1 (đã duyệt) và v1.2 (đề xuất), `DetectionResult`.
3.4. Detection Engine: rule model, evaluation contract (`MATCH / NO_MATCH / INSUFFICIENT_TELEMETRY / PENDING_LATE_EVENTS`), correlation, outbox.
3.5. Alert và Incident: máy trạng thái, dedup, audit hash-chain, truy vết bằng chứng.
3.6. **Tổng hợp rủi ro**: công thức, cấu hình có phiên bản, giải thích (`docs/implementation/RISK_SCORING.md`).
3.7. **AI hỗ trợ**: ML_STATIC (EMBER2024) và ML_BEHAVIOR (độ hiếm), feature contract (`docs/implementation/ML_SIGNALS.md`).
3.8. Response an toàn: dry-run, hai khóa, duyệt hai người, rollback; điểm rủi ro và ML không kích hoạt response.
3.9. API, phân quyền và Dashboard.
3.10. Mô hình đe dọa nhắm vào chính EDR (STRIDE) và giới hạn của agent user-space.

## Chương 4. Hiện thực
4.1. Cấu trúc mã nguồn (`src/…`) và công nghệ (Python, DuckDB, FastAPI, JS thuần).
4.2. Agent và collector (Event Log, checkpoint, Bronze sealed).
4.3. Pipeline Silver (dedup, quarantine/DLQ, replay, lineage).
4.4. Detection, static analysis, ML signals, risk.
4.5. Alert, API, Dashboard (kèm ảnh chụp màn hình gắn nhãn dữ liệu synthetic hoặc dữ liệu VM).
4.6. Triển khai trên Windows 10 VM (`docs/implementation/EDR_INSTALL_GUIDE.md`).

## Chương 5. Kiểm thử và đánh giá
5.1. Chiến lược: unit test, integration test, Playwright, nghiệm thu AT (`tests/acceptance/at_catalog.yaml`).
5.2. Kết quả trên Linux (lấy từ `docs/implementation/handover/TEST_REPORT.md`, ghi rõ ngày và lệnh).
5.3. Kết quả trên Windows 10 VM: những gì đã quan sát (agent live, alert DET-001/003/010 từ kịch bản lab, thủ công một lần) và những gì chưa chạy.
5.4. Chất lượng phát hiện: `[CẦN SỐ ĐO]` TP/FP/FN theo kịch bản; số alert mỗi ngày trên tải lành tính.
5.5. AI: `[CẦN SỐ ĐO]` trên dữ liệu của DACN. Số EMBER2024 (AUC) chỉ được trình bày như số đo trên EMBER2024.
5.6. Hiệu năng: `[CẦN SỐ ĐO]` CPU, RAM, độ trễ trên VM 2 GB.
5.7. Thảo luận: điều gì đã và chưa được chứng minh (`docs/implementation/handover/LIMITATIONS_AND_RISKS.md`).

## Chương 6. Kết luận và hướng phát triển
6.1. Kết quả đạt được, đối chiếu từng mục tiêu của đề cương (bảng: mục tiêu → thành phần → mức kiểm chứng).
6.2. Hạn chế: rule `synthetic_only`; trọng số rủi ro chưa hiệu chỉnh; ML nháp; response chưa từng chạy thật; contract chưa được phê duyệt liên nhóm; agent user-space không chống can thiệp.
6.3. **Hướng phát triển** (Giai đoạn 2 — luận văn):
- **Đo và hiệu chỉnh.** Thu dữ liệu lành tính và kịch bản lab trên VM; đo TP/FP/FN, số alert mỗi ngày; hiệu chỉnh trọng số rủi ro (tăng `version`) và ngưỡng ML trên tệp lành tính.
- **Hoàn thiện Windows.** Chạy `execute` của response trên VM lab có duyệt; Windows service và watchdog; đo CPU/RAM.
- **Mở rộng telemetry.** PowerShell 4104 (ScriptBlock), AMSI, WMI; đánh giá ETW. Bỏ chặn DET-007/008 khi có đủ telemetry.
- **AI.** Lớp Gold/feature theo cửa sổ thời gian; Isolation Forest hoặc mô hình chuỗi khi đủ dữ liệu; train lại định kỳ để xử lý drift; giải thích bằng SHAP cho mô hình tĩnh; mô hình Win32; kết hợp static ML với static analysis (hash, entropy, pattern).
- **Control plane.** Rule, IOC và policy có chữ ký số; cảnh báo khi cấu hình Sysmon thay đổi (Event 16); so sha256 cấu hình với baseline (NIST SP 800-128).
- **Đa endpoint** (ngoài phạm vi Giai đoạn 1): máy chủ quản trị tập trung, tương quan nhiều host.

## Phụ lục
A. Danh mục ADR và trạng thái. B. Hợp đồng dữ liệu và schema. C. Danh sách rule kèm MITRE. D. Hướng dẫn cài đặt và chạy. E. Báo cáo nghiệm thu AT.
