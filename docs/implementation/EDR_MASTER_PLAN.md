# EDR — Master Plan (kế hoạch thực thi cho Claude Code)

> **PROPOSAL — chờ phê duyệt** (2026-11-08). Chưa phase nào bắt đầu. Kế hoạch này **không** thay đổi kế hoạch 12 tuần gốc, ADR, data contract hay schema; mọi điều chỉnh chỉ ở dạng đề xuất (mục 9).
> Tài liệu liên quan: [Audit](EDR_AUDIT_REPORT.md) · [Kiến trúc đích](EDR_TARGET_ARCHITECTURE.md) · [Backlog](EDR_TASK_BACKLOG.md) · [Tiến độ](EDR_PROGRESS.md) · [Ma trận nghiệm thu](EDR_ACCEPTANCE_MATRIX.md) · [Demo](EDR_DEMO_PLAN.md) · [Hướng dẫn AI](AI_TRAINING_GUIDE.md).

## 1. Mục tiêu và tiêu chí thành công

**MVP hoàn thành chỉ khi có bằng chứng thực tế cho chuỗi:**
`Windows Telemetry → Data Pipeline → Detection → Alert → Investigation → Safe Response → Dashboard`
trên Windows 10 VM lab, với các kịch bản mô phỏng an toàn đã định nghĩa, lặp lại được từ snapshot sạch.

- Unit test xanh **không** đủ. Cần chạy thực tế trên Windows (bằng chứng do người dùng cung cấp).
- Không tuyên bố phát hiện mọi malware; phạm vi phát hiện = tập kịch bản đã chạy.
- Phân biệt: **EDR phát hiện** · **Windows Defender phát hiện trước** · **rule kích hoạt bởi simulator** · **chỉ chạy trên fixture**.

## 2. Hiện trạng tóm tắt (chi tiết ở Audit)

IMPLEMENTED/VERIFIED (Linux, dữ liệu mẫu): parse+normalize Sysmon, Bronze contract + schema, adapter, validator PoC (dedup/DLQ/4 nhóm Silver), DDL v1.1 chạy được và khớp validator. **BROKEN:** 2 test (nguyên nhân đã xác minh). **PLANNED/chưa tồn tại:** agent liên tục, segment writer, Silver bền vững, replay, lớp truy vấn, detection engine (0 rule thực thi), alert/incident, response, API, dashboard, config/logging, CI. **UNKNOWN:** live mode trên Windows.

## 3. Phạm vi so với kế hoạch 12 tuần

Kế hoạch 12 tuần (bản PR #36, chưa merge) đặt Giai đoạn 1 chủ yếu là **nghiên cứu/thiết kế**; PoC thực thi (collector → vài rule → alert/dashboard đơn giản) là **tùy chọn nếu đủ tiến độ**; hiện thực đầy đủ thuộc Luận văn. Mục tiêu mới của người dùng (EDR chạy được, có response, API, dashboard) **lớn hơn** nội dung đó. Xem quyết định **D-01**.

| Phase | Liên hệ với kế hoạch 12 tuần |
|---|---|
| PH1–PH3 | nền cho PoC tùy chọn W6–W10 (collector → pipeline) |
| PH4 | W6 (thiết kế rule) được hiện thực; DET-001/003/010 là ưu tiên W6 |
| PH5, PH7 (thiết kế) | W9–W10 (kịch bản, response an toàn) |
| PH6, PH8, PH9 | W9 (investigation, dashboard wireframe) → hiện thực |
| PH10–PH12 | W10–W12 (demo, báo cáo, bàn giao) |
| ML | W8 (thiết kế AI) → nhánh song song, không nằm trên critical path |

## 4. Phân loại ưu tiên

- **P0 (MVP):** PH1 (sửa lỗi, quyết định hợp đồng, config/log), PH2 (agent + segment + Windows), PH3 (Silver bền vững, DLQ, replay, truy vấn, lineage), PH4 (engine, DET-001/003/010, IOC), PH5 (kịch bản), PH6 (alert, evidence), PH7 (policy, executor, terminate + quarantine thử nghiệm, audit), PH8 (API cốt lõi), PH9 (dashboard cốt lõi), PH10–PH12.
- **P1:** rule bổ sung, ML interface, auto-response có cổng, block hash, rules/settings UI, chất lượng dữ liệu nâng cao, fixture đã khử định danh, diễn tập lỗi.
- **P2:** Windows service, retention, ML training/tích hợp/thử, tối ưu hiệu năng sâu.
- **ML training không nằm trên critical path.**

## 5. Quy ước dùng trong các phase

Mỗi phase liệt kê: mục tiêu, phạm vi, điều kiện tiên quyết (Pre), phụ thuộc (Dep), file/module, thứ tự task (chi tiết ở [Backlog](EDR_TASK_BACKLOG.md)), skill nên dùng, test, tiêu chí nghiệm thu (AC), sản phẩm, rủi ro, cổng chuyển phase (Gate), việc cần người dùng. Skill chung cho **mọi** task: `writing-plans` (khi cần), `test-driven-development`, `verification-before-completion`, `systematic-debugging` (khi lỗi), `dacn-issue-workflow` (khi làm theo issue).

---

## PH1 — Stabilization & Technical Debt `[P0]`
- **Mục tiêu:** sửa lỗi đã xác minh, chốt quyết định hợp đồng còn mở, tạo nền kỹ thuật (config, logging, test infra).
- **Phạm vi:** `poc/sysmon-collector/`, `src/pipeline/`, `tests/`, tài liệu quyết định. Không đổi `bronze-event/1.0` hay UUIDv5.
- **Pre:** phê duyệt D-01, D-03, D-05, D-09. **Dep:** không.
- **File:** `poc/sysmon-collector/sysmon_collector_poc.py`, `src/pipeline/validator_poc.py`, `tests/`, `src/common/`, `conftest.py`/`pytest.ini`.
- **Task (thứ tự):** T01 → (T02 ∥ T03) → T08 → T11 → T09; quyết định T04/T05/T06/T10 song song; T07, T12 (P1) sau.
- **Skill:** `systematic-debugging`, `dacn-contract-review`, `dacn-sysmon-telemetry`, `dacn-data-pipeline-storage`.
- **Test:** `python -m pytest -q poc/sysmon-collector`, `python -m pytest -q tests/`, test tái dựng `event_id` từ cột Silver, test config/log.
- **AC:** 2 test lỗi đã được sửa hoặc có quyết định ghi lại; toàn bộ suite xanh trên Linux; `import` module mới từ `src/` hoạt động; config/log dùng được; quyết định hostname/event type/Event 4/16 có phê duyệt.
- **Sản phẩm:** mã sửa, ADR đề xuất, `EDR_PROGRESS.md` cập nhật.
- **Rủi ro:** quyết định chậm làm trượt PH3; sửa test vì cho xanh (cấm).
- **Gate → PH2/PH3:** AC đạt + D-07/D-08 đã quyết.
- **Người dùng:** duyệt quyết định, phản hồi review Data/Software/Cyber.

## PH2 — Windows Endpoint Agent `[P0]`
- **Mục tiêu:** thu thập Sysmon liên tục, ghi Bronze sealed bền, checkpoint, health.
- **Phạm vi:** `src/agent/`; nguồn Windows qua `pywin32` sau lớp mỏng; ưu tiên chạy được (script/CLI) trước service.
- **Pre:** PH1 xong T08/T09/T11. **Dep:** hợp đồng Bronze 1.0 (không đổi).
- **File:** `src/agent/**`, `poc/sysmon-collector/bronze_contract.py` (dùng nguyên), `poc/sysmon-collector/configs/sysmon-config.xml` (đề xuất đổi qua PR).
- **Task:** T01 → T02 → T03 → T04 → T07; T05 (spike Windows, **làm sớm, song song PH1**) → T06; T08; T09 (Windows); T10; T11 (P2).
- **Skill:** `dacn-windows-agent`, `dacn-sysmon-telemetry`, `dacn-windows-integration-test`, `test-driven-development`.
- **Test:** unit (segment, checkpoint, recovery) trên nguồn giả 10.000 sự kiện + dừng giữa chừng; **Windows** (PH2-T09): so Bronze với `wevtutil`, kill/restart, quyền.
- **AC:** segment sealed có manifest hợp lệ; dừng đột ngột không mất bản ghi; Windows: nhận sự kiện mới liên tục, khớp export; live mode chỉ `VERIFIED` khi có đầu ra thật.
- **Sản phẩm:** agent CLI, hướng dẫn cài/chạy, báo cáo kiểm thử Windows.
- **Rủi ro:** API bookmark khác dự kiến; Defender khóa file khi `os.replace`; kích thước channel Event Log nhỏ gây mất sự kiện; quyền đọc log.
- **Gate → PH3 (Windows phần), PH10:** PH2-T01..T04, T07 pass trên Linux; T09 có bằng chứng.
- **Người dùng:** cung cấp VM, cài Sysmon/Python/pywin32, chạy T05/T09, áp dụng cấu hình Sysmon.

## PH3 — Data Pipeline & Storage `[P0]`
- **Mục tiêu:** nạp bền vững Bronze → Silver, DLQ, replay, truy vấn, lineage.
- **Pre:** PH2-T02 (định dạng segment), D-06/D-07. **Dep:** PH1.
- **File:** `src/pipeline/*`, DDL v1.1 (dùng nguyên) và v1.2 (đề xuất).
- **Task:** T01 → T02 → T03 → T05; T06; T07; T04 (sau D-06); T08 (P1); T09 (P2).
- **Skill:** `dacn-data-pipeline-storage`, `dacn-contract-review`.
- **Test:** nạp hai lần không trùng; chết giữa transaction; segment hỏng 1 byte → quarantine; replay trùng Silver gốc; tổng đọc = valid + dedup + DLQ.
- **AC:** Silver bền vững dùng trực tiếp được bởi engine; mọi bản ghi có đường truy vết về Bronze (sau D-06); không đổi contract.
- **Rủi ro:** khóa tệp DuckDB; chuẩn hóa hostname; hiệu năng chưa đo.
- **Gate → PH4:** T02, T03, T06 xong + test.
- **Người dùng:** duyệt DDL v1.2.

## PH4 — Detection Engine `[P0]`
- **Mục tiêu:** engine rule + tương quan + IOC, `DetectionResult` có bằng chứng.
- **Pre:** PH3-T06; D-05, hợp đồng `DetectionResult` (PH4-T02). **Dep:** PH3.
- **File:** `src/detection/**`, `rules/*.yaml`, `tests/detection/**`. Liên quan issue #38, #39, #40.
- **Task:** T01 ∥ T02 → T03 → (T04 ∥ T05 ∥ T07) → T06 → T08 → T09; T10, T11 (P1).
- **Skill:** `dacn-detection-engine`, `dacn-detection-rules-mitre`, `dacn-detection-validation`, `test-driven-development`.
- **Mỗi rule phải có:** mục đích, telemetry cần, điều kiện, false positive có thể, test case (dương/lành tính/thiếu dữ liệu), kết quả kỳ vọng, bằng chứng chạy thực tế (từ PH5). Không thêm rule để tăng số lượng; rule thiếu telemetry ghi `blocked`.
- **AC:** DET-001/003/010 + IOC chạy trên Silver; thiếu telemetry cho `INSUFFICIENT_TELEMETRY`; replay không sinh kết quả trùng; tắt ML không đổi hành vi.
- **Rủi ro:** rule dựa trên giả định field; cửa sổ thời gian chưa có dữ liệu có nhãn; mẫu Run key thật chưa có.
- **Gate → PH5/PH6:** T09 harness xanh.
- **Người dùng:** Cyber duyệt `DetectionResult`, điều kiện rule.

## PH5 — Malware Test Detection & Validation `[P0]`
- **Mục tiêu:** kiểm chứng phát hiện bằng kịch bản mô phỏng **an toàn** trên VM (chi tiết: [Demo plan](EDR_DEMO_PLAN.md)).
- **Pre:** PH2-T09, PH4 (rule DET-001/003/010 + IOC), D-10, D-11. **Dep:** PH4.
- **File:** `scripts/lab/**` (đề xuất), `tests/e2e/**`.
- **Task:** T01 → T02 → T03 → **T04 (người dùng chạy)** → T05.
- **Skill:** `dacn-detection-validation`, `dacn-windows-integration-test`, `dacn-detection-rules-mitre`.
- **AC:** bảng expected↔observed cho mọi kịch bản đã chạy, ghi nguồn phát hiện (EDR/Defender/không); tỷ lệ chỉ trên tập này kèm cỡ mẫu.
- **Rủi ro:** Defender chặn/xóa mẫu; kịch bản gây nhiễu; cleanup thất bại → khôi phục snapshot.
- **Gate → PH11:** có kết quả thật cho SC-01..SC-04.
- **Người dùng:** duyệt từng kịch bản và script, chạy trên VM, khôi phục snapshot, quyết định về EICAR.

## PH6 — Alert & Incident Management `[P0]`
- **Mục tiêu:** alert từ `DetectionResult`, severity, evidence, trạng thái, timeline, audit.
- **Pre:** PH4-T02, D-06. **Dep:** PH4, PH3.
- **File:** `src/alerts/**`, `src/pipeline/sql/…_v1_2_proposal.sql`.
- **Task:** T01 (duyệt DDL) → T02 → T03 → T04 → T05; T06 (P1).
- **Skill:** `dacn-alert-incident-management`, `dacn-threat-hunting`.
- **AC:** từ `alert_id` ra sự kiện Silver, segment Bronze, `raw_xml` (hoặc `PARTIAL/RAW_EXPIRED`); dedup + replay idempotent; máy trạng thái chặn chuyển sai.
- **Rủi ro:** thay đổi DDL; `process_guid NOT NULL` cản alert không gắn process.
- **Gate → PH7/PH8:** T03, T04 xong.

## PH7 — Response Engine `[P0]` (chỉ kiểm soát, dry-run mặc định)
- **Mục tiêu:** hành động phòng thủ có kiểm soát: terminate và quarantine **tiến trình/tệp thử nghiệm** khi được phép, audit, hoàn tác.
- **Pre:** PH6-T01..T03, D-12. **Dep:** PH6, PH8-T06 (responder).
- **File:** `src/response/**`, `config/response-policy.example.yaml`.
- **Task:** T01 → T02 → T03 → T06 → (T04 ∥ T05) → T07 → **T10 (Windows, người dùng)**; T08, T09 (P1).
- **Skill:** `dacn-response-safety`, `dacn-security-review`, `dacn-security-threat-modeling`.
- **Bắt buộc:** dry-run mặc định; chỉ endpoint lab; allowlist bảo vệ tiến trình/tệp hệ thống; kiểm quyền và xác thực; không tắt Defender; auto-response tắt cho tới khi người dùng phê duyệt kịch bản cụ thể; log chứng minh hành động; tách bạch detection / prevention / response.
- **AC (test):** thiếu approval → từ chối; mục tiêu bảo vệ → từ chối; PID tái sử dụng → từ chối; dry-run không đổi hệ thống; quarantine rồi restore khớp hash; audit đủ trường.
- **Rủi ro:** thao tác nhầm; TOCTOU; mất dữ liệu; quyền.
- **Gate → PH11:** T10 có bằng chứng; kiểm tra âm tính (yêu cầu dừng tiến trình hệ thống bị từ chối).
- **Người dùng:** bật `execute`, chỉ trong phạm vi lab được duyệt; quan sát log hệ điều hành.

## PH8 — Backend API `[P0]`
- **Mục tiêu:** API cục bộ phục vụ dashboard và responder.
- **Pre:** D-04; PH3-T06, PH6-T03. **Dep:** PH6.
- **File:** `src/api/**`, `tests/api/**`.
- **Task:** T01 → T02 → T03 → T04 → T05 → T06 → T08; T07, T09 (P1).
- **Skill:** `dacn-backend-api`, `dacn-security-review`.
- **AC:** mỗi endpoint có test dương/âm; xác thực + phân quyền; validate input; lỗi không lộ stack; bind localhost.
- **Rủi ro:** thêm dependency; khóa DuckDB; lộ raw XML.
- **Gate → PH9, PH7-T07.**

## PH9 — EDR Dashboard `[P0]`
- **Mục tiêu:** UI vận hành: Overview, Endpoint, Event Explorer, Detections, Alerts/Incidents, Investigation, Response Actions, Rules (đọc).
- **Pre:** PH8-T01. **Dep:** PH8.
- **File:** `src/dashboard/static/**`, `tests/dashboard/**`.
- **Task:** T01 → (T02 ∥ T03 ∥ T04) → T05 → T06; T07, T08 (P1).
- **Skill:** `dacn-dashboard`, `dataviz`.
- **AC:** dữ liệu lấy từ API thật; có tìm/lọc/chi tiết; nguồn bằng chứng và kết quả response hiển thị; trạng thái loading/lỗi/rỗng; **không hardcode dữ liệu giả rồi báo đã tích hợp**; dữ liệu fixture gắn nhãn.
- **Rủi ro:** sai lệch giữa fixture và dữ liệu thật; hiệu năng trên VM.
- **Gate → PH10.**

## PH10 — End-to-End Integration `[P0]`
- **Mục tiêu:** chạy toàn hệ thống bằng một quy trình khởi động tài liệu hóa.
- **Pre:** PH2, PH3, PH4, PH6, PH8 (và PH7/PH9 cho đầy đủ). **Dep:** các phase trên.
- **File:** `src/edr_ctl.py`, `config/edr.example.yaml`, `tests/e2e/**`.
- **Task:** T01 → T02 → T03 (Linux, nguồn giả) → **T04 (Windows)** → T06; T05 (P1).
- **Skill:** `dacn-end-to-end-acceptance`, `dacn-windows-integration-test`, `dacn-performance-reliability`.
- **AC:** Linux: nguồn giả → alert → API → evidence xanh; Windows: `edr_ctl start` rồi SC-01 phát hiện và hiển thị trên Dashboard; hướng dẫn cài đặt làm theo được.
- **Rủi ro:** lỗi liên module chỉ lộ trên Windows; quyền.
- **Gate → PH11.**

## PH11 — Acceptance Testing & Demo `[P0]`
- **Mục tiêu:** bộ nghiệm thu đầy đủ và demo lặp lại được.
- **Task:** T01 → T02 (người dùng chạy) → T03 → T04.
- **AC:** mỗi test trong [Ma trận nghiệm thu](EDR_ACCEPTANCE_MATRIX.md) có Preconditions/Steps/Expected/Actual/PASS|FAIL|NOT RUN/Evidence/Known limitations; demo chạy hai lần liên tiếp từ snapshot sạch.
- **Người dùng:** thực hiện trên VM, cung cấp đầu ra.

## PH12 — Finalization & Handover `[P0]`
- **Task:** T01..T06. **AC:** tài liệu kiến trúc cuối, user guide, hướng dẫn triển khai, báo cáo kiểm thử, tổng hợp hạn chế, nội dung bảo vệ; trạng thái Implemented / Tested / Designed / Future chính xác. **Skill:** `dacn-documentation-handover`.

## ML — Nhánh AI/ML (song song, tùy chọn)
- Claude: thiết kế đặc trưng, tiền xử lý, giao diện, mã huấn luyện/đánh giá khung, nạp mô hình, hướng dẫn. Người dùng: dataset, môi trường, huấn luyện, metrics, cung cấp artifact. Chi tiết: [AI_TRAINING_GUIDE.md](AI_TRAINING_GUIDE.md). Không khẳng định độ chính xác khi chưa huấn luyện và đánh giá.

---

## 6. Phụ thuộc, song song, critical path

**Có thể làm song song:** PH2 phần nguồn giả/segment ∥ PH1 quyết định; PH2-T05 (spike Windows) ∥ PH1; PH3 (sau khi định dạng segment chốt) ∥ PH2-T05/T06; PH4-T01/T02 ∥ PH3; PH5-T01/T02 ∥ PH4; PH7-T01..T03 ∥ PH6; PH9 ∥ PH8 (sau khung API); ML ∥ mọi phase sau PH3.
**Có thể trì hoãn:** Windows service, retention, ML training/tích hợp, rule bổ sung, auto-response, block hash, UI rules.

**Critical path tới MVP chạy được:**
`PH1-T01 → PH1-T08 → PH1 quyết định hostname → PH2-T01 → PH2-T02 → PH3-T01 → PH3-T02 → PH3-T06 → PH4-T02/T01 → PH4-T03 → PH4-T04 → PH6-T01 → PH6-T02 → PH6-T03 → PH6-T04 → PH8-T01 → PH8-T04/T05 → PH9-T01 → PH9-T05 → PH10-T01 → PH10-T03 → PH10-T04 (Windows) → PH11-T02 (Windows)`.
PH5 và PH7 chạy song song với đoạn PH6–PH9 và hội tụ ở PH10/PH11.
**Ước lượng thô theo critical path** (cộng effort từng task, một người làm tuần tự): ≈ **64 ngày công**; chưa gồm thời gian chờ Windows/phê duyệt. Ba thành viên + Claude làm song song có thể rút ngắn nhưng **không kiểm chứng**.

### Tổng hợp effort tương đối (cộng từ [Backlog](EDR_TASK_BACKLOG.md); S=0,5 · M=1,5 · L=4 · XL=8 ngày công, ước lượng thô)

| Phase | Số task | Ngày công thô | Ghi chú |
|---|---|---|---|
| PH1 | 12 | 13 | gồm 4 quyết định |
| PH2 | 11 | 23,5 | gồm 3 bước Windows |
| PH3 | 9 | 18,5 | |
| PH4 | 11 | 23 | |
| PH5 | 5 | 12,5 | 1 bước Windows |
| PH6 | 6 | 14 | |
| PH7 | 10 | 25 | 3 bước Windows |
| PH8 | 9 | 11,5 | |
| PH9 | 8 | 14,5 | |
| PH10 | 6 | 15,5 | 2 bước Windows |
| PH11 | 4 | 12,5 | 2 bước Windows |
| PH12 | 6 | 7 | |
| ML | 7 | 22 | ngoài critical path |
| **Tổng** | **104** | **≈ 212** (P0 ≈ 156) | cộng tuần tự, **chưa tính song song** |

Tổng P0 (77 task) lớn so với thời gian còn lại của đồ án; nếu cần cắt: bỏ PH7-T05 hoặc giữ chỉ terminate, giữ chỉ DET-001 + IOC, dashboard tối giản (Overview + Alerts + Investigation). Xem D-01.

## 7. Phân công theo vai trò

| Vai trò | Chủ trì | Review |
|---|---|---|
| **Software** | PH2, PH7 (executor/responder), PH8, PH9, PH10, hạ tầng PH1 | Data (contract), Cyber (an toàn) |
| **Data** | PH3, DDL v1.2, DetectionResult schema (cùng Cyber), ML | Software, Cyber |
| **Cybersecurity** | PH4 (rule), PH5, PH6, policy PH7, threat model | Data (trường), Software (khả thi) |

## 8. Phân loại theo môi trường thực thi

| Loại | Task |
|---|---|
| **Claude làm trọn vẹn trên cloud/Linux** (nguồn giả) | phần lớn PH1–PH4, PH6, PH8–PH10 (Linux), PH12, ML-T01..T04 |
| **Cần Windows thật, người dùng chạy** | PH2-T05, T09; PH5-T04; PH7-T10; PH10-T04, T05; PH11-T02, T03; ML-T07 |
| **Cần người dùng quyết định/thao tác** | D-01…D-13; cài Sysmon/Python/pywin32; áp dụng cấu hình Sysmon; quyết định EICAR; bật `execute`; ML-T05 |

**Các bước người dùng thực hiện trên Windows (tổng hợp):** (1) chuẩn bị VM Windows 10 có snapshot sạch; (2) cài Python và dependency theo hướng dẫn, `pywin32`; (3) cài Sysmon với cấu hình của repository; (4) chạy script kiểm tra đọc-only của Claude (PH2-T05) và gửi đầu ra; (5) chạy agent live và so với `wevtutil`; (6) đọc và duyệt script kịch bản, chạy `-WhatIf`, rồi chạy thật trên VM; (7) quan sát Defender; (8) bật `execute` cho response thử nghiệm; (9) gửi lại log/ảnh chụp (đã che định danh); (10) khôi phục snapshot sau mỗi lượt.

## 9. Điều chỉnh đề xuất cho kế hoạch 12 tuần (không tự áp dụng)

Nếu D-01 chọn làm MVP trong thời gian đồ án: đề xuất (a) giữ nguyên deliverables thiết kế W6–W8 (các tài liệu `DetectionResult`, rule, static/whitelist) như tài liệu đi kèm các phase PH4/PH6; (b) dùng PH1–PH4 + PH6 + Overview/Alerts nhỏ làm "PoC tùy chọn" của W10–W12; (c) PH7 thực thi thật và ML chuyển sang Luận văn. Chỉ ghi vào kế hoạch gốc sau khi người dùng phê duyệt.

## 10. Quyết định cần phê duyệt

| ID | Quyết định | Phương án | Đề xuất |
|---|---|---|---|
| D-01 | Phạm vi MVP so với kế hoạch 12 tuần | (a) MVP đầy đủ trong đồ án; (b) tập con P0 làm PoC tùy chọn, phần còn lại cho Luận văn; (c) chỉ thiết kế | **(b)**, mở rộng dần nếu còn thời gian |
| D-02 | Chiến lược branch/PR | **Đã người dùng chỉ định (2026-11-08):** nhánh tích hợp dài hạn `claude_implement` (tạo từ `main`) chứa kế hoạch và mọi hiện thực của Claude; chỉ đưa vào `main` ở bản cuối cùng, do người dùng quyết định. Đề xuất bổ sung: mỗi task/issue một nhánh con theo `docs/conventions/02-branch-convention.md` tạo từ `claude_implement`, PR nhỏ vào `claude_implement`; định kỳ cập nhật `claude_implement` từ `main` | Như đã chỉ định |
| D-03 | Chia sẻ code `poc/` ↔ `src/` | (a) shim `pythonpath` + `conftest.py`; (b) chuyển thành package | **(a)** cho MVP, (b) ở P2 |
| D-04 | Stack API/UI | stdlib / **FastAPI + trang tĩnh** / Streamlit | **FastAPI + tĩnh** |
| D-05 | Định dạng rule | **YAML** (+PyYAML) / JSON thuần | YAML (khớp kiến trúc v2) |
| D-06 | DDL v1.2 (lineage, detection_results, alerts mở rộng, incidents, response, audit) | duyệt/sửa đề xuất | Duyệt sau PH6-T01 |
| D-07 | Chuẩn hóa hostname (TD-03) | giữ nguyên hoa/thường; thêm `hostname_norm`; chuẩn hóa từ Bronze | Thêm `hostname_norm`, giữ `hostname` gốc |
| D-08 | Tên event type và Event 4/16 | thống nhất bảng (Q-X3); health events riêng | Bảng thống nhất + health events |
| D-09 | Tệp dependency | thêm `requirements.txt` ghim phiên bản (tệp gốc mới) | Đồng ý |
| D-10 | Vị trí script lab và đổi `sysmon-config.xml` | `scripts/lab/`; đổi Sysmon qua PR | Như mô tả |
| D-11 | EICAR/Defender | (a) bỏ EICAR; (b) tùy chọn, người dùng tự quản lý loại trừ thư mục lab trên VM; Claude không tắt/bỏ qua Defender | **(b) tùy chọn** |
| D-12 | Phạm vi response thật | terminate + quarantine tiến trình/tệp có marker lab; auto-response tắt | Như mô tả |
| D-13 | Môi trường Windows | VM, phiên bản Windows/Sysmon/Python, ai chạy các bước W | Người dùng xác nhận |
| D-14 | Thời điểm bắt đầu nhánh ML | sau PH3 / sau MVP | Sau PH3, không chặn MVP |

## 11. Thứ tự GitHub Issues đề xuất

Issue hiện có: #26–#29 (W05, sign-off hợp đồng), #38–#40 (W06–W07, thiết kế Cyber/Data/Software). **Không tạo issue khi chưa được phép.** Mỗi issue mới nên liên kết issue cũ tương ứng, tránh trùng:

1. (hiện có) #26–#29: hoàn tất sign-off Bronze/Silver — điều kiện cho PH2–PH3.
2. `[collector] Ổn định nền: sửa C-002, entropy test, quyết định hostname/event type/Event 4-16` (PH1).
3. `[collector] Agent: nguồn giả, segment writer, checkpoint, recovery` (PH2-T01..T04, T07).
4. `[collector] Spike pywin32 và nguồn Windows Event Log; kiểm chứng trên VM` (PH2-T05, T06, T09).
5. `[silver] Silver bền vững, DLQ, replay, lớp truy vấn, lineage` (PH3).
6. `[rule-engine] Rule registry, engine, IOC, DACN-DET-001/003/010` (PH4; liên kết #38, #39, #40).
7. `[silver] DDL v1.2: detection_results, alerts, incidents, response, audit` (PH6-T01).
8. `[aggregator] Alert, incident, evidence resolver, timeline` (PH6).
9. `[rule-engine] Kịch bản mô phỏng an toàn và đánh giá phát hiện` (PH5).
10. `[aggregator] Response engine có kiểm soát (dry-run mặc định)` (PH7).
11. `[dashboard] Backend API` (PH8).
12. `[dashboard] EDR Dashboard` (PH9).
13. `[collector] Launcher, tích hợp end-to-end, hướng dẫn cài đặt` (PH10).
14. `[dashboard] Nghiệm thu, demo, bàn giao` (PH11–PH12).
15. `[ai-scoring] Giao diện ML, đặc trưng, hướng dẫn huấn luyện` (nhánh ML).

## 12. Task đầu tiên sau khi kế hoạch được duyệt

1. **PH1-T01** — ghi baseline kiểm thử vào `EDR_PROGRESS.md` (S).
2. **PH1-T02** — sửa mã `C-002` bằng TDD trên branch riêng (ví dụ `fix/c002-collector-reason-code`), chỉ đổi thông báo lỗi; chạy lại cả hai bộ test; báo cáo; **không commit/push cho đến khi người dùng yêu cầu**.
3. Song song, chờ người dùng: trả lời D-01, D-03, D-04, D-05, D-07, D-13 và chạy PH2-T05 trên VM.

## 13. Quy trình mỗi phiên làm việc của Claude Code

1. Đọc `CLAUDE.md`. 2. Đọc [Master Plan](EDR_MASTER_PLAN.md) (tệp này). 3. Đọc [EDR_PROGRESS.md](EDR_PROGRESS.md) (trạng thái mới nhất). 4. Chọn task `TODO` có phụ thuộc đã `DONE` đầu tiên trong [Backlog](EDR_TASK_BACKLOG.md) (hoặc task người dùng chỉ định). 5. `git status`, `git branch --show-current`, kiểm tra branch/PR. Nhánh nền là `claude_implement` (không làm việc trên `main`); nhánh con cho từng task tạo từ `claude_implement`; nếu PR của nhánh con đã merge vào `claude_implement` thì tạo nhánh mới từ `claude_implement` đã cập nhật. 6. Xác minh Pre (phê duyệt D-xx, phụ thuộc). 7. Gọi skill phù hợp (theo bảng skill của phase). 8. Triển khai trong phạm vi task, TDD. 9. Chạy kiểm thử phù hợp (lệnh trong task + toàn bộ suite). 10. Đối chiếu AC/DoD. 11. Ghi kết quả. 12. Cập nhật `EDR_PROGRESS.md`, `EDR_TASK_BACKLOG.md` (trạng thái), `EDR_ACCEPTANCE_MATRIX.md` (nếu có bằng chứng). 13. Báo cáo thay đổi, kết quả test, vấn đề tồn đọng. 14. Chuyển task tiếp theo chỉ khi được phép và điều kiện đã đáp ứng.

**Quy tắc cứng:** không `DONE` khi chưa có bằng chứng; không tự merge PR; không tự chạy thao tác Windows nhạy cảm; task bị chặn → `BLOCKED` kèm hướng dẫn kiểm chứng cụ thể cho người dùng; không âm thầm bỏ task; không đổi data contract/ADR/kế hoạch 12 tuần khi chưa phê duyệt; commit/push/PR chỉ khi người dùng yêu cầu.

## 14. Ranh giới an toàn

Chỉ trong môi trường lab được phép (Windows 10 VM VirtualBox có snapshot). Không malware thật; không tải/chạy mã độc; không kiểm thử phá hoại dữ liệu, duy trì truy cập trái phép, tắt công cụ bảo mật, hay xâm nhập mạng; không thử trên máy người khác; không ngăn tiến trình hệ thống; response thật chỉ trong phạm vi người dùng duyệt, có log và khôi phục. Mọi kịch bản demo phải lặp lại an toàn từ snapshot sạch.
