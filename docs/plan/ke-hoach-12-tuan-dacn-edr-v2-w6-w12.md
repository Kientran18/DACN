# KẾ HOẠCH THỰC HIỆN ĐỒ ÁN CHUYÊN NGÀNH — 12 TUẦN (BẢN ĐỒNG BỘ EDR v2)

**Đề tài:** Tìm hiểu và hiện thực một hệ thống bảo mật cho thiết bị đầu cuối (Endpoint Security)  
**Nhóm:** 03 thành viên — Cyber Security, Data Engineering/AI, Software Engineering/System Architecture  
**Phiên bản:** 2.0 (cập nhật ngày 04/11/2026; **chỉ điều chỉnh từ W6**)  
**Trạng thái:** Kế hoạch đề xuất cho nhóm review; chưa phải báo cáo kết quả thực hiện W6–W12.  
**Nguồn gốc:** Tệp kế hoạch do nhóm cung cấp: \`Ke_hoach_12_tuan_DACN_Endpoint_Security_Cap_Nhat(2).docx\`.  
**Đối chiếu kiến trúc:** [Local EDR Architecture v2](../architecture/local-edr-reference-architecture-v2.md) · [ADR 0007](../decisions/0007_local_edr_modular_architecture.md) · [Sơ đồ](../../diagrams/edr-v2-architecture.md).

> **Nguyên tắc giữ kế hoạch gốc:** W1–W5 không thay đổi mục tiêu/nội dung chính. W6, W7, W8, W9, W10, W11, W12 giữ nguyên **trọng tâm và sản phẩm đầu ra ban đầu**; chỉ bổ sung độ chi tiết cho kiến trúc EDR v2, phụ thuộc liên nhóm, acceptance criteria và ranh giới thiết kế/PoC. **Giai đoạn 1 ưu tiên nghiên cứu, thiết kế và kiểm chứng khả thi; triển khai toàn bộ sản phẩm chuyển sang Luận văn Tốt nghiệp.**

## 1. Mục tiêu 12 tuần (giữ theo kế hoạch gốc)

1. Làm rõ bài toán, phạm vi và yêu cầu Endpoint Security trên Windows.
2. Khảo sát EPP/EDR, MITRE ATT&CK, Windows telemetry và công cụ/mã nguồn mở.
3. Xây dựng mô hình dữ liệu và pipeline raw → normalized → feature → detection → alert.
4. Thiết kế detection bằng rule, static analysis, whitelist/signature và AI hỗ trợ risk scoring/anomaly detection.
5. Thiết kế investigation, process tree, incident timeline, threat hunting và response cơ bản.
6. Hoàn thiện kiến trúc tổng thể và bộ tài liệu bàn giao cho Luận văn Tốt nghiệp.

**Phạm vi:** 01 Windows endpoint, Windows 10/11, local-first. Không thêm server XDR tập trung, cloud/multi-tenant, message broker phân tán hoặc phản ứng tự động nguy hiểm vào 12 tuần.

## 2. Phân công xuyên suốt (giữ vai trò)

| Vai trò | Ownership |
| --- | --- |
| **Cyber Security** | EPP/EDR, Threat Model/ATT&CK, telemetry requirements, rules, static analysis/IOC policy, alert/risk policies, investigation, response requirements, safe lab scenarios |
| **Data Engineering / AI** | Bronze/Silver/Gold, event/data schemas, validation, lineage, feature engineering, dataset/model evaluation, risk/anomaly design |
| **Software Engineering / Architecture** | Windows collector/agent PoC, interface/contracts, module boundaries, checkpoint/replay feasibility, local storage access, UI/response design, test environment |

Mỗi interface/contract có **owner + reviewer** của hai mảng còn lại; merged documentation không tự thay cho cross-team sign-off.

## 3. Kế hoạch theo tuần

### W1–W5 — GIỮ NGUYÊN theo kế hoạch gốc (mốc đã lập)

| Tuần | Trọng tâm gốc | Nội dung và sản phẩm theo kế hoạch ban đầu |
| --- | --- | --- |
| **W1** | Chốt bài toán, phạm vi và cách làm việc | Problem Statement, In/Out Scope, RACI/Role Matrix, Research Backlog, repository/project board và Architecture v0.1. |
| **W2** | MITRE ATT&CK và Threat Model | Chọn 10–15 techniques (thực tế nhóm chọn 13), Threat Model v1, Behavior-to-Telemetry Mapping, MITRE Detection Matrix v1; Data/Software xác minh trường/nguồn. |
| **W3** | Xác minh Windows telemetry thực tế | Sysmon, Windows Event Log, sample process/file/registry/network; Windows Telemetry Catalogue v1, Endpoint Event Schema v1, Raw-to-Normalized Mapping, Minimal Collector PoC và JSON. |
| **W4** | Đánh giá công cụ/mã nguồn mở | Khảo sát Wazuh/Sysmon/osquery/Velociraptor/Atomic Red Team; Tool Comparison Matrix, Security/Data/Architecture Evaluation, Reusable Insights và Decision Notes. |
| **W5** | Thiết kế Data Pipeline | Endpoint → Raw/Bronze → Validation → Silver → Feature → Detection/AI → Alert/Gold; Data Dictionary, Data Quality/Lineage và retention; Data lead, Cyber + Software review. |

**Lưu ý:** phần này thể hiện **kế hoạch**, không tự khẳng định tất cả issue/review của W1–W5 đã được đóng.

### W6 — Detection Engine Design — Cyber lead

**Mục tiêu gốc giữ nguyên:** thiết kế Rule Model và các nhóm rule process/file/registry/network/parent-child anomaly, severity/risk contribution, trigger và truy vết alert về source event.

**Công việc W6:**
- Thiết kế module **Rule Loader/Registry, Event Matcher, Behavioral Correlator, Detection Evaluator, Alert Builder interface** theo EDR v2.
- Chuẩn hóa rule metadata: \`rule_id\`, \`rule_version\`, required fields theo Event ID, category, severity, MITRE technique, correlation keys, evidence, time window, confidence rationale.
- Đặc tả **DET-001..DET-010** từ W03/W05; ưu tiên ví dụ **DET-001** (PowerShell), **DET-003** (Registry persistence), **DET-010** (drop→execute→delete). Phân biệt yêu cầu telemetry đã có, thiếu và chỉ mang tính giả thuyết.
- Thiết kế trạng thái \`MATCH / NO_MATCH / INSUFFICIENT_TELEMETRY / PENDING_LATE_EVENTS\`; missing data không đồng nghĩa benign.
- Chốt giao diện \`DetectionResult → Alert\`, \`contributing_event_ids[]\`, \`bronze_raw_references[]\` và process GUID; xác định phương án rule namespace tránh nhầm MITRE Detection Strategy.
- Cyber sở hữu rule/evidence, Data xác nhận feature/schema/timestamp, Software xác nhận feasibility và module contract.

**Deliverables W6:** Detection Architecture v1, Rule Model & Categories, Initial Rule Set (10 đặc tả), Alert Traceability & Severity/Risk Model, test fixtures/scenarios (positive, benign, missing evidence); bản vẽ và review liên nhóm.

**DoD:** Có đặc tả đầu vào/đầu ra một rule; mọi required field mapping tới W05; DET-010 thiếu Event26 phải nhận partial/pending; không quảng cáo detection accuracy khi chưa benchmark. **PoC thực thi 1–3 rule là tùy chọn**, không thay DoD thiết kế.

### W7 — Static Analysis, Whitelist & Threat Knowledge — Cyber+Data, Software interface

**Mục tiêu gốc giữ nguyên:** static feature hash/entropy/PE metadata/digital signature/path/publisher; Local Whitelist, Threat Signature/Pattern Store, Suspicious Candidate Review.

**Công việc W7:**
- Xác định đặc trưng và nguồn: SHA-256, file size/extension, optional PE headers/imports/signature status, entropy, path/user/publisher; phân biệt **observed vs inferred**.
- Thiết kế schema \`static_file_features\`, \`signature_iocs\`, \`local_allowlist\`, \`candidate_reviews\`, version/updated_at/expiration/source + audit metadata.
- IOC/hash matcher nhận dữ liệu file có sẵn; policy whitelist ưu tiên **trusted/known-good**, tránh vô hiệu hóa rule quan trọng từ một path wildcard.
- Xây candidate lifecycle: NEW → TRIAGED → ALLOWLISTED / SUSPICIOUS / REJECTED, có review reason, người duyệt và lịch sử thay đổi.
- Thiết kế giao diện Static Result → Risk Aggregator/Alert v2 và việc xử lý file bị thiếu hash hoặc quyền đọc.

**Deliverables W7:** Static Feature List, Whitelist/Signature Schema, Suspicious Candidate Workflow, Review State Model, integration/interface notes.

**DoD:** Có 2 ví dụ file benign/suspicious synthetic và một case allowlist; có ranh giới: hash detection không tự chứng minh malicious; chữ ký số hợp lệ không bảo đảm file vô hại. **Không chuyển W7 sang làm Collector/Bronze**.

### W8 — AI Risk Scoring / Anomaly Detection Design — Data/AI lead

**Mục tiêu gốc giữ nguyên:** chọn bài toán AI (risk scoring và/hoặc anomaly detection), feature set, dataset/training plan, model baselines, output và evaluation metrics.

**Công việc W8:**
- Feature definitions từ Silver: process tree, command entropy, event counts/time window, network frequency, registry changes, evidence completeness; giữ \`source_event_ids[]\`.
- Thiết kế dataset/ground truth, partition train/validation/test theo host/run/time để hạn chế leakage; ghi rõ dữ liệu W03 chưa đủ cho mô hình đáng tin.
- Đề xuất baseline: Logistic Regression/Random Forest khi có nhãn; Isolation Forest cho anomaly candidate khi phù hợp; quy trình test/threshold calibration.
- Thiết kế \`AnomalyResult\` và \`RiskAggregator\` (input rule/static/AI score; output risk + explanation + version), tránh tự gán confidence nếu thiếu hiệu chỉnh.
- Review fairness/false positives, out-of-distribution, drift, model version/rollback; không tự kích hoạt response từ anomaly score.
- Data/AI lead; Cyber kiểm tra ý nghĩa security; Software kiểm tra inference interface/resource budgets.

**Deliverables W8:** AI Design, Feature List, Dataset Plan, Model Baseline Plan, Precision/Recall/F1/FPR Evaluation Plan, Risk Score Contract.

**DoD:** Có baseline **kế hoạch đánh giá** với dữ liệu/nhãn/threshold/limitations; có pseudo-pipeline, không bắt buộc mô hình production. PoC model khi có dữ liệu và thời gian là tùy chọn.

#### MILESTONE 2 — cuối W8

**Bắt buộc ở mức thiết kế:** Data Pipeline (W5), Detection Engine (W6), Static/Whitelist/Signature (W7), AI/Risk/Anomaly (W8), và interface/ownership liên nhóm. Có architecture diagram và tài liệu giới hạn thực nghiệm. **Không** yêu cầu end-to-end EDR production hoặc mô hình ML đã train trên dataset lớn.

### W9 — Investigation, Threat Hunting & Response — Cyber lead

**Mục tiêu gốc giữ nguyên:** Process Tree, Incident Timeline, Alert/Incident Model, Hunting Queries, response cơ bản/an toàn và dữ liệu cần lưu để điều tra.

**Công việc W9:**
- Sơ đồ investigator workflow: DetectionResult → Alert → Case → Timeline/Tree/Hunt → Evidence; có truy vết \`alert_id → event_id → Bronze raw XML\` hoặc báo \`PARTIAL/RAW_EXPIRED\`.
- Thiết kế query catalog process_guid/parent, time, registry, file path/hash, DNS, IP/port khi có, missing telemetry.
- Incident/Alert lifecycle, reviewer/status, evidence retention hold và access audit.
- **Response Safety:** manual approval, authorization, protected path/process allowlist, verify target identity, dry-run, audit, rollback metadata; Phase 1 mặc định **alert-only**. Terminate/quarantine/block hash chỉ ở mức thiết kế hoặc PoC có kiểm soát theo khả năng.
- Cyber lead, Data query/schema/lineage, Software UI/module/OS API.

**Deliverables W9:** Investigation & Response Design, Incident Schema, Threat Hunting Query Set, Dashboard Wireframe, Response Policy/Approval/Audit Contract.

**DoD:** Có luồng analyst điều tra đến raw evidence, 1 tình huống response được duyệt/từ chối và kịch bản false positive. Không tuyên bố host isolation hoặc tamper-resistant agent.

### W10 — Test Scenarios & Demo Plan — Cyber scenarios, Data expected, Software VM

**Mục tiêu gốc giữ nguyên:** Test Scenario Matrix theo MITRE/Atomic Red Team, expected telemetry, detection và alert; VM/sandbox chỉ là môi trường kiểm thử, không phải runtime production.

**Công việc W10:**
- Chốt kịch bản PowerShell, Run Key, drop→execute→delete, benign/negative tests; ưu tiên những trường hợp **an toàn** và có dữ liệu mẫu.
- Ghi preconditions, test execution/run marker, Event ID/required fields, expected DetectionResult/Alert, evidence link và observed status. Không đồng nhất một Event ID với phát hiện thành công technique.
- Thiết kế bổ sung case resiliency: collector restart, duplicate replay, bad JSON, Event5/22 nullable, late Event26, log reset, disk quota/health alert.
- Nếu các PoC hoạt động, demo XML/VM → Collector → JSON/Bronze → Validator Silver → 1–3 rule → alert trace; ghi phần nào live, phần nào fixture/simulation.
- Báo cáo đo lường theo bộ test có nhãn; không tạo số liệu precision/recall/MTTD chưa test.

**Deliverables W10:** Test Scenario Matrix, Demo Plan, Expected Telemetry/Alert Set, Test Environment Notes, observed-vs-expected sheets (nếu thực nghiệm).

**DoD:** Mỗi scenario có expected source, expected decision, cách ghi nhận evidence và limit; demo có fallback từ real VM sang fixture đã lưu.

#### MILESTONE 3 — cuối W10

Hoàn thành **thiết kế Investigation/Response + bộ kịch bản kiểm thử/demo**, không nhất thiết đã triển khai live response/AI.

### W11 — Architecture Integration & Design Freeze — Cả nhóm

**Mục tiêu gốc giữ nguyên:** ghép Agent/Collector, Data Pipeline, Detection, AI, Storage, Risk Aggregator, Alert/Incident, Investigation, Dashboard; review dependency/interface và giải quyết open questions.

**Công việc W11:**
- Hợp nhất **Local EDR v2** theo component / trust boundary / deployment / data flow / event-alert sequence.
- Đối chiếu điều kiện W05 canonical Bronze v1.0, Silver v1.1, process GUID, channel epoch, provenance, single-writer DuckDB; cập nhật mapping và quyết định còn mở.
- Review Cyber/Data/Software, ADR và tài liệu interface để phân định hiện thực vs proposed. Ghi open decisions không thể xác nhận.
- Đóng băng thiết kế đã review, lập danh sách known gaps, acceptance outcomes và phụ thuộc Luận văn.

**Deliverables W11:** Architecture Final v1, Component Diagram, Data Flow, Data Model, Sequence Flow, Architecture Decision Records, Freeze & Open-Issues Log.

**DoD:** Diagram hợp lệ, data/permission paths nhất quán, các module đều có owner + status + interfaces; không mở thêm module mới ngoài scope.

### W12 — Final Validation, Report & Handover — Cả nhóm

**Mục tiêu gốc giữ nguyên:** đối chiếu design với requirement/MITRE/test scenarios; hoàn thiện báo cáo/slide/appendix, backlog Luận văn; demo PoC nếu ổn định.

**Công việc W12:**
- Traceability matrix: scope/requirement → design → issue/file/PR → test evidence hoặc missing coverage.
- Tổng kết 13 selected ATT&CK techniques: covered telemetry / candidate rule / tested positive/negative / gaps, tuyệt đối không suy ra detection rate.
- Gói tài liệu: versioned diagrams, schema contracts, rule/static/AI/alert/response designs, ADR, test matrix và guide chạy PoC Windows 10 VirtualBox.
- Tổng kết rủi ro: telemetry gap, privacy/retention, resource budget thực tế nếu đo, false positive handling, limit của EDR user-space.
- Lập backlog cho Luận văn: collector service durable, detection implementation đầy đủ, AI model, investigation UI, response executor an toàn, performance/security hardening; XDR/cloud chỉ là hướng mở rộng tùy chọn.

**Deliverables W12:** Final Report, Presentation, Final Architecture Package, Phase 2/Thesis Backlog, Optional PoC Demo.

**DoD:** Demo hoặc dẫn chứng có thể lặp lại; ghi rõ **Implemented / Tested / Designed / Future**, không quảng cáo tính năng chỉ có trên sơ đồ.

## 4. Công việc xuyên suốt để đáp ứng EDR v2 (không thay mục tiêu tuần)

| Workstream bổ sung | Chủ sở hữu | Thời điểm review / lý do |
| --- | --- | --- |
| **P0: Chốt Bronze contract** | Data + Software, Cyber review | Trước khi tích hợp W6/W10: chọn canonical \`bronze-event/1.0\`, mapping và event-specific NULL; tránh hai nguồn sự thật |
| **P0: Evidence lineage & identity** | Data + Software, Cyber review | W6 contract, W9 investigation, W10 test: raw ref, segment/line/hash, log epoch, replay |
| **Durable Collector / Checkpoint / Replay** | Software + Data | Spike/PoC W7–W10 nếu còn thời gian; **không thay thế W7 Static** |
| **Health / DLQ / Privacy / Retention** | Software + Data + Cyber | Đặc tả W6/W9, failure tests W10, policy freeze W11 |
| **Rule/config versioning + auth/audit** | Cyber + Software | W6, W9, W11; không cần central management |
| **Alert safety, response approval** | Cyber + Software | W9 design; W10 safe validation; không auto-terminate từ PoC |
| **Performance & test evidence** | Cả nhóm | Windows 10 VM, W10–W12; đặt threshold sau đo thực tế |

## 5. Mốc kiểm tra chính (giữ kế hoạch gốc)

1. **M1 — cuối W4:** nghiên cứu nền tảng, telemetry thực tế, Sysmon/Collector PoC, đánh giá mã nguồn mở.
2. **M2 — cuối W8:** thiết kế lõi Data Pipeline + Detection + Static/Whitelist/Signature + AI.
3. **M3 — cuối W10:** thiết kế Investigation/Response và bộ kịch bản kiểm thử/demo.
4. **M4 — cuối W12:** kiến trúc tổng thể, báo cáo và backlog hiện thực Luận văn.

## 6. Deliverable cuối Giai đoạn 1 (giữ danh mục gốc, bổ sung phân lớp v2)

1. Scope & Problem Statement, RACI/Role Matrix, Research Backlog.
2. EPP/EDR Research, MITRE ATT&CK Detection Matrix, Threat Model.
3. Windows Telemetry Catalogue, real samples, normalized Event Schema, Raw-to-Normalized Mapping.
4. Đánh giá Wazuh, Sysmon, osquery, Velociraptor, Atomic Red Team.
5. Data Pipeline Architecture, Data Model, Dictionary, Quality/Lineage.
6. Detection Architecture và initial proposed rules (+ rule contract / coverage semantics).
7. Static Analysis / Whitelist / Threat Signature / Candidate Review designs.
8. AI Risk Scoring / Anomaly Detection Design + Evaluation Plan.
9. Investigation, Threat Hunting, Incident Timeline và Response Design (+ safety gate).
10. Test Scenario Matrix dựa trên MITRE/Atomic Red Team (+ evidence/resilience cases).
11. Final Architecture Package, Mermaid diagrams, ADR, interfaces và thesis backlog.
12. Final report và slide Giai đoạn 1.

## 7. PoC tùy chọn / kỳ vọng thực nghiệm

**Giữ nguyên mục tiêu PoC gốc:** Sysmon/Windows Event Log → minimal Collector → raw JSON → normalize → **2–5 detection rules** → alert/dashboard đơn giản **nếu đủ tiến độ**.

EDR v2 bổ sung yêu cầu **trung thực dữ liệu** cho PoC: đầu ra có contributing_event_ids, missing/partial coverage, source refs và log của positive/negative fixtures. Không đặt checklist service 24/7, advanced response, production AI, 256 endpoints hay enterprise XDR thành tiêu chí nghiệm thu bắt buộc.

## 8. Đối chiếu thay đổi từ plan ban đầu

| Tuần | Giữ nguyên | Bổ sung hợp lý từ v2 | Không đưa vào mục tiêu chính |
| --- | --- | --- | --- |
| W6 | Detection Architecture, Rule Model, Initial Rule Set | Versioning, evidence/coverage, correlation semantics | Live detection service hoàn chỉnh |
| W7 | Static/Whitelist/Signature | IOC matcher, review lifecycle, integrity metadata | Full persistent collector thay thế W7 |
| W8 | AI/Risk/Anomaly design | Feature lineage, risk aggregator interface, evaluation/leakage constraints | Full ML training/deployment bắt buộc |
| W9 | Investigation/Response design | Approval, audit, restore, retention hold | Auto host isolation, remote shell |
| W10 | Test/demo plan | Failure/late events, observed-vs-expected matrix | Năng lực/benchmark chưa đo |
| W11 | Architecture freeze | Trust boundaries, versioned contracts, owner sign-off | Thêm module vượt scope |
| W12 | Final validation/handover | Evidence-based status, thesis backlog theo v2 | Gọi thiết kế là sản phẩm production |

**Nguyên tắc phiên bản:** nếu tài liệu khác trong repo (đặc biệt Architecture v2 Section 11) có timeline trái bảng này, lấy **kế hoạch 12 tuần đã được nhóm duyệt** làm nguồn lịch; architecture roadmap chỉ diễn giải cách triển khai tương ứng.
