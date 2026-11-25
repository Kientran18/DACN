# Ánh xạ DACN sang NIST SP 800-61 (xử lý sự cố) và NIST SP 800-128 (quản lý cấu hình)

> Cập nhật 2026-11-25. Tài liệu đối chiếu **những gì DACN đang có trong code** với khung NIST, kèm khoảng trống. Đây không phải tuyên bố tuân thủ: DACN là đồ án local-first một endpoint, chưa được đánh giá độc lập, và phần lớn mới kiểm chứng trên Linux với dữ liệu synthetic (xem `CLAUDE.md` mục 3.1).

## 1. NIST SP 800-61 — vòng đời xử lý sự cố

**Phiên bản.** SP 800-61 Rev. 2 (2012) chia vòng đời thành bốn pha: (1) Preparation; (2) Detection & Analysis; (3) Containment, Eradication & Recovery; (4) Post-Incident Activity. SP 800-61 Rev. 3 (04/2025) thay Rev. 2 và tổ chức khuyến nghị theo các chức năng của NIST CSF 2.0 (Govern, Identify, Protect, Detect, Respond, Recover). Bảng dưới dùng bốn pha của Rev. 2 vì dễ đối chiếu với luồng alert/incident; cột cuối ghi chức năng CSF 2.0 tương ứng mà Rev. 3 dùng.

| Pha (Rev. 2) | Thành phần DACN (code) | Trạng thái kiểm chứng | Khoảng trống | CSF 2.0 (Rev. 3) |
|---|---|---|---|---|
| **Preparation** | Sysmon config `poc/sysmon-collector/configs/sysmon-config.xml`; rule YAML có `rule_version` (`src/detection/rules/`); `config/response-policy.yaml` (dry_run, hai khóa execute, danh sách bảo vệ); token và 4 vai trò (`src/api/auth.py`); audit hash-chain; script kiểm tra môi trường `scripts/windows/verify_windows_env.py`; hướng dẫn cài đặt `EDR_INSTALL_GUIDE.md` | Linux có test; Windows VM: agent đọc Sysmon thật (một lần, thủ công) | Chưa có playbook xử lý theo loại sự cố; chưa có kênh liên lạc hay phân công vai trò ngoài hệ thống; chưa diễn tập | Govern, Identify, Protect |
| **Detection & Analysis** — phát hiện | Agent → Bronze sealed → Silver (`src/agent`, `src/pipeline`); Detection Engine: rule, correlation DET-010, IOC DET-101, static `DACN-STATIC-001`; kết quả `MATCH / NO_MATCH / INSUFFICIENT_TELEMETRY / PENDING_LATE_EVENTS`; tín hiệu ML (tắt mặc định) | Rule `synthetic_only`; lab sinh alert DET-001/003/010 trên VM (thủ công một lần) | Chưa có TP/FP/FN; chưa có nguồn ngoài (feed IOC, log khác ngoài Sysmon) | Detect |
| **Detection & Analysis** — phân tích, ưu tiên | Alert có `severity_reason`, MITRE (khi rule có căn cứ), `coverage_status`, `missing_fields`; **điểm rủi ro tổng hợp** (`src/risk`, [RISK_SCORING.md](RISK_SCORING.md)) để ưu tiên; evidence alert → Silver → Bronze → `raw_xml`; timeline và process tree; `coverage_gaps` tách khỏi alert | Linux có test | Trọng số rủi ro chưa hiệu chỉnh; chưa có tương quan nhiều host | Detect (Adverse Event Analysis) |
| **Detection & Analysis** — ghi nhận | Máy trạng thái alert (`NEW → TRIAGED → INVESTIGATING → CONFIRMED / FALSE_POSITIVE → CLOSED`) bắt buộc ghi chú; incident và liên kết alert; ghi chú incident; mọi thay đổi vào `audit_log` có chuỗi băm | Linux có test | Chưa có mức ưu tiên hay phân loại incident riêng (đang dựa vào severity/điểm rủi ro) | Respond (Incident Management) |
| **Containment** | `TERMINATE_PROCESS`, `QUARANTINE_FILE` qua Response Engine: yêu cầu → duyệt (người duyệt khác người yêu cầu) → responder tách tiến trình; mặc định `dry_run`; điểm rủi ro và điểm ML **không** kích hoạt response | Backend giả trên Linux; **chưa từng thực thi thật** | Chưa cô lập mạng; chưa chạy `execute` trên VM | Respond (Incident Mitigation) |
| **Eradication** | `ADD_WHITELIST/REMOVE_WHITELIST` (chưa chạy thật); IOC hash cục bộ; candidate static có duyệt | Linux có test | Không xóa mã độc hay sửa registry tự động (ngoài phạm vi an toàn của đồ án) | Respond |
| **Recovery** | `RESTORE_FILE` từ quarantine; mỗi hành động có `rollback`; replay Bronze → Silver; checkpoint agent | Linux có test; agent kill/restart trên VM (thủ công) | Chưa có kiểm thử khôi phục đầy đủ trên VM | Recover |
| **Post-Incident Activity** | `audit_log` (kiểm chuỗi qua `/health`); lịch sử trạng thái alert; báo cáo nghiệm thu `scripts/acceptance/run_acceptance.py`; rule có `false_positives` và `limitations`; cấu hình rủi ro có `changelog` | Linux | Chưa có mẫu báo cáo "lessons learned"; chưa có số đo thời gian phát hiện hay phản ứng | Identify (Improvement) |

Hai nguyên tắc lấy từ SP 800-61 mà DACN đang giữ trong code:

- **Bằng chứng gắn với nguồn.** Alert luôn truy được về sự kiện Silver, segment Bronze và `raw_xml`. Xem `raw_xml` đòi quyền riêng và được ghi audit.
- **Phản ứng có kiểm soát.** Containment phải được con người duyệt. Điểm tự động (rủi ro, ML) chỉ dùng để ưu tiên.

## 2. NIST SP 800-128 — quản lý cấu hình hướng bảo mật (SecCM)

SP 800-128 chia SecCM thành bốn pha: (1) Planning; (2) Identifying and Implementing Configurations, gồm baseline cấu hình an toàn; (3) Controlling Configuration Changes, gồm phân tích tác động bảo mật và phê duyệt thay đổi; (4) Monitoring. Các control tương ứng trong SP 800-53 là CM-2 (baseline), CM-3 (kiểm soát thay đổi), CM-4 (phân tích tác động), CM-6 (thiết lập cấu hình) và CM-9 (kế hoạch CM).

### 2.1. Danh mục cấu hình (configuration items) của DACN

| Mục cấu hình | Tệp hoặc vị trí | Phiên bản và toàn vẹn hiện có | Cách thay đổi (kiểm soát) | Khoảng trống |
|---|---|---|---|---|
| Baseline Sysmon | `poc/sysmon-collector/configs/sysmon-config.xml` (v1.0, schema 4.90) | Phiên bản ghi trong chú thích; lịch sử qua Git | Pull Request; tài liệu `docs/research/software/w3/02-sysmon-configuration-v1.md` | Agent **chưa** so cấu hình Sysmon đang chạy với baseline. Sysmon Event 16 (đổi cấu hình) có mẫu nhưng không có rule cảnh báo |
| Rule phát hiện | `src/detection/rules/*.yaml` | `rule_version`; schema kiểm khi nạp (`RuleError`); engine lưu dấu vân tay rule + IOC (`_sig`) và quét lại khi đổi; outbox đóng băng metadata rule | Pull Request; test harness `tests/detection/` | Chưa có quy trình duyệt của Cyber ghi trong repo; `validation_status: synthetic_only` |
| IOC và allowlist | `<EDR_HOME>/ioc/ioc.yaml` | `version`; mục có `expires` (UTC) | Sửa tệp, hoặc `ADD_WHITELIST/REMOVE_WHITELIST` qua duyệt và audit | Không có chữ ký số; không có lịch sử phiên bản ngoài audit |
| Knowledge static | `<EDR_HOME>/static-knowledge` | revision sha256, activate/rollback có CAS và audit | `POST /static/knowledge/activate`, `/rollback` (vai trò approver) | Chưa có chữ ký nguồn |
| Chính sách response | `config/response-policy.yaml` | Mặc định an toàn; hai khóa execute | Sửa tệp trên máy (không đổi được qua UI) | **Chưa có trường `version`** và chưa ghi hash vào audit khi nạp |
| Chấm điểm rủi ro | `config/risk-scoring.yaml` | `version`, `changelog`, `status` bị khóa ở `heuristic_uncalibrated`; sha256 kèm trong mọi kết quả | Sửa tệp, tăng version, ghi changelog, chạy `tests/risk` | Chưa có người duyệt Cyber |
| Nguồn ML | `config/ml-detectors.yaml`; `models/**/model_card.json` | `version`; mô hình kiểm `artifact_sha256` và `feature_schema_version` khi nạp | Sửa tệp; train lại tạo `model_version` mới | Mô hình đều là nháp chưa duyệt |
| Schema/DDL | `src/pipeline/sql/…v1_1.sql` (đã duyệt), `…v1_2_proposal.sql` (đề xuất) | Phiên bản trong tên tệp | Không sửa v1.1; v1.2 chờ Data duyệt | — |
| Cấu hình hệ thống | `edr.yaml` (`config/edr.example.yaml`) | Loader từ chối khóa lạ; ép API bind loopback | Sửa tệp | Không có phiên bản |

### 2.2. Đối chiếu bốn pha

| Pha SecCM | DACN hiện có | Đề xuất (chưa làm, cần duyệt) |
|---|---|---|
| Planning | Phạm vi Giai đoạn 1, ADR 0001–0006 (Accepted), quy ước nhánh, commit và PR (`docs/conventions/`) | Viết kế hoạch CM ngắn (CM-9): ai duyệt mục nào (Cyber duyệt rule và trọng số rủi ro; Data duyệt DDL/contract; Software duyệt policy) |
| Identifying & Implementing (baseline) | Bảng 2.1; giá trị mặc định an toàn (dry_run, ML tắt, loopback) | Gắn `version` cho `response-policy.yaml`; ghi hash Sysmon config đã triển khai vào báo cáo VM |
| Controlling Changes | Git + PR, không commit thẳng `main`; loader từ chối cấu hình sai; rule hoặc IOC đổi thì quét lại; knowledge có CAS và rollback; audit hash-chain | Mẫu "phân tích tác động" trong PR khi đổi rule, trọng số hoặc policy (ảnh hưởng tới số alert và điểm rủi ro) |
| Monitoring | `/health` (agent, pipeline, engine `rule_versions`, chuỗi audit, `core.ml`); `/risk/config` (version + sha256) | Rule cảnh báo Sysmon Event 16; định kỳ so sha256 các tệp cấu hình với baseline và đưa kết quả lên `/health` |

## 3. Tài liệu tham khảo

- NIST SP 800-61 Rev. 2, *Computer Security Incident Handling Guide*, 2012; và Rev. 3, *Incident Response Recommendations and Considerations for Cybersecurity Risk Management: A CSF 2.0 Community Profile*, 2025.
- NIST SP 800-128, *Guide for Security-Focused Configuration Management of Information Systems*, 2011 (bản cập nhật 2019).
- NIST SP 800-53 Rev. 5, họ control CM (Configuration Management).
- NIST Cybersecurity Framework (CSF) 2.0, 2024.
