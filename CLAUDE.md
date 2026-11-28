# CLAUDE.md

Tài liệu này hướng dẫn Claude Code (claude.ai/code) khi làm việc với mã nguồn trong repository này. Đây là bộ quy tắc làm việc cho AI Agent; README và tài liệu kiến trúc vẫn là nguồn chính thức.

## 1. Quy tắc ngôn ngữ

- Mọi phản hồi, giải thích, báo cáo tiến độ và tài liệu dự án viết bằng **tiếng Việt**.
- Giữ nguyên thuật ngữ chuyên môn khi cần: EDR, EPP, Sysmon, Telemetry, Bronze, Silver, Gold, Detection Engine, Response Engine, API, Schema, Pipeline, Unit Test, Integration Test, Git, Pull Request, Event ID, UUIDv5, GUID, Quarantine, DLQ.
- Không dịch tên file, đường dẫn, tên module, hàm, biến, class, mã lỗi, lệnh Terminal và đoạn code.
- Các lệnh cài đặt, build, chạy và kiểm thử giữ nguyên cú pháp.

## 2. Tổng quan dự án

DACN là đồ án về bảo mật endpoint (EPP/EDR) cho **Windows 10/11**, triển khai theo hướng **local-first**: một endpoint, agent chạy user-space, cơ sở dữ liệu cục bộ, không có server quản trị tập trung trong Giai đoạn 1.

**Mục tiêu cuối cùng** là xây dựng một ứng dụng EDR hoàn chỉnh trên Windows, có khả năng:
- Thu thập và giám sát telemetry (process, file, registry, network, DNS) trên endpoint.
- Chuẩn hóa, kiểm định chất lượng và lưu trữ dữ liệu theo kiến trúc Medallion (Bronze → Silver → Gold).
- Phát hiện hành vi đáng ngờ bằng Signature/Hash, Whitelist, Rule-based và Behavior-based Detection.
- Tạo, phân loại và quản lý cảnh báo kèm bằng chứng truy vết về sự kiện nguồn.
- Hỗ trợ điều tra: process tree, timeline, threat hunting theo process, hash, thời gian, rule và mức độ nghiêm trọng.
- Thực hiện các hành động phản ứng có kiểm soát: Terminate Process, Quarantine File, Block Hash, Add Whitelist.
- Cung cấp giao diện quản lý trực quan (Dashboard).

Các chức năng AI/ML (anomaly detection, risk scoring) mới có giao diện và bộ nạp mô hình (tắt mặc định). Có hai mô hình PE tĩnh EMBER2024 ở trạng thái **nháp** (xem 3.1); từ 2026-11-25 chúng được nối vào luồng như tín hiệu `ML_STATIC` tùy chọn, kèm một detector độ hiếm hành vi `ML_BEHAVIOR`. Cả hai tắt mặc định, chỉ góp vào điểm rủi ro tổng hợp, không tạo alert và không có số liệu chất lượng của DACN.

Phạm vi Giai đoạn 1 (đồ án chuyên ngành, 12 tuần) được ghi tại `docs/scope/phase-1-scope.md` và `docs/decisions/week-1-decisions.md`. Giai đoạn 2 (luận văn) tập trung hiện thực, tích hợp và đánh giá.

## 3. Trạng thái hiện tại và kiến trúc mục tiêu

Phân biệt rõ hai nhóm thông tin. **Không mô tả thành phần thuộc TARGET như thể đã hoàn thành.**

### 3.1. CURRENT STATE — đã triển khai và có bằng chứng

Căn cứ: mã nguồn trên nhánh tích hợp `claude_implement` và kết quả `pytest` và nghiệm thu AT ngày **2026-11-22** (Linux, Python 3.13, sau audit và sau khi merge phần issue #40 của BuiCuongTuan). Chi tiết: `docs/implementation/` (`EDR_PROGRESS.md`, `EDR_TASK_BACKLOG.md`, `handover/TEST_REPORT.md`, `handover/LIMITATIONS_AND_RISKS.md`).

| Thành phần | Vị trí | Mức độ kiểm chứng |
|---|---|---|
| Sysmon collector PoC, Bronze contract, adapter, validator W05 | `poc/sysmon-collector/`, `src/pipeline/validator_poc.py` | Có test; dữ liệu synthetic và mẫu lab. Bronze contract vẫn là **đề xuất**, chưa phê duyệt chéo |
| Agent (nguồn giả/tệp/Event Log, Bronze sealed + manifest, checkpoint, recover) | `src/agent/` | Có test trên Linux. Nguồn Event Log thật **đã chạy trên một Windows 10 VM** (2026-11-24, Sysmon v15.22): đọc 9.099 sự kiện không lỗi, C-006 khi thiếu quyền, kill/khởi động lại chạy tiếp; quan sát thủ công một lần, chưa đo mất/trùng sự kiện |
| Pipeline (Silver DuckDB, dedup, quarantine/DLQ, replay, ledger) | `src/pipeline/` | Có test trên Linux; dùng DDL v1.2 là **đề xuất chưa duyệt** |
| Detection Engine (DET-001/002/003/004/010/101 bật; DET-007/008 blocked; IOC, allowlist, correlation, 4 kết quả đánh giá). Từ issue #40: `run()` chạy trong một transaction, `_detection_outbox` bền vững (kết quả → alert → ack cùng transaction, metadata rule đóng băng), watermark theo host, `allowed_lateness_seconds` tùy chọn cho rule correlation, `process_context.py` (helper tham chiếu, chưa nối vào rule) | `src/detection/`, `config/` | Có test với fixture; mọi rule `synthetic_only`, chưa hiệu chỉnh. DET-003 lên **v3** (2026-11-26, người dùng duyệt): v2 nhận thêm RunOnceEx (đã thấy MATCH trên VM), v3 nhận thêm `\Policies\Explorer\Run` (A07 MATCH trên VM lần 3). Số liệu TP/FN đầu tiên chỉ từ một lượt Atomic Red Team nhỏ trên VM (dòng dưới), chưa có FP trên tải lành tính. Outbox/lateness chỉ có test fixture, không claim exactly-once streaming |
| Alert/Incident, audit hash-chain, truy vết alert→Silver→Bronze→raw_xml | `src/alerts/` | Có test trên Linux |
| Response Engine (mặc định `dry_run`, hai khóa execute, duyệt, quarantine/restore) | `src/response/`, `config/response-policy.yaml` | Có test với backend giả; **chưa từng thực thi hành động thật**; có ADD/REMOVE_WHITELIST (chưa chạy thật). Auto-response và block-hash nằm ở `experimental/`, chưa nối vào hệ thống |
| API FastAPI (loopback, 4 vai trò) và Dashboard tĩnh. Có thêm 8 endpoint `/static/*` (phân tích tệp, candidate, knowledge). Từ 2026-11-26: màn hình **Cây tiến trình** (`#/tree`) và 3 endpoint chỉ đọc `/investigation/process-tree`, `/investigation/process-events`, `/investigation/process-search` (theo hostname + process_guid, nút `NO_DATA` cho cha thiếu Event 1, alert/rủi ro/sự kiện theo nút, giới hạn nút/độ sâu) | `src/api/`, `src/dashboard/`, `src/alerts/process_view.py` | Có test (kể cả Playwright) trên Linux, dữ liệu synthetic. Dashboard **chưa có** màn hình cho `/static/*`. Cây tiến trình chưa chạy trên dữ liệu VM thật, hiệu năng chưa đo |
| Static analysis (issue #40): quan sát byte HIỆN TẠI của tệp trong `<EDR_HOME>/lab` (SHA-256, kích thước, entropy, header PE tối thiểu, khớp pattern literal), kho knowledge có phiên bản (activate/rollback/hết hạn), kho candidate có duyệt (vai trò, CAS, audit), kết quả `DACN-STATIC-001` chỉ alert, không response | `src/static_analysis/`, `scripts/contracts/export_issue40_contracts.py`, `scripts/poc/run_issue40_demo.py`, `docs/architecture/w6/`, `docs/architecture/w7/`, `docs/research/software/w6/`, `docs/research/software/w7/` | Có test (`tests/static_analysis/`, `tests/detection/test_issue40_correlation.py`, `tests/core/test_issue40_delivery.py`: 35 pass, 1 skipped trên Linux). Tác giả báo chạy trên Windows host (Python 3.12.8, gồm test khóa tệp thật); **chưa chạy trên Windows 10 VM với Sysmon live**. Chữ ký số trả `UNAVAILABLE`. Schema/contract W06–W07 là **đề xuất chưa được Data/Cyber duyệt** |
| Core service và launcher | `src/core/`, `src/edr_ctl.py` | Chạy nhiều tiến trình thật trên Linux; chưa trên Windows |
| Script lab (SC01–SC07) và kiểm tra môi trường Windows | `scripts/lab/`, `scripts/windows/` | Chỉ kiểm tra tĩnh; **chưa chạy trên Windows** |
| Mô hình ML PE tĩnh EMBER2024 (Dot_Net, Win64; **nháp**, `DRAFT_CHUA_DUYET`) và bộ chấm điểm tĩnh nháp chạy theo yêu cầu | `models/ember2024/`, `scripts/ml/train_ember2024.py`, `src/detection/ml/loader.py`, `src/detection/ml/static_scorer.py`, `requirements-ml.txt`, `docs/implementation/ML_EMBER2024_MODELS.md` | Có test nạp qua loader (`tests/detection/test_ember2024_models.py`, cần `lightgbm`, thiếu thì bỏ qua) và test bộ chấm điểm với PE synthetic, extractor/predictor giả (`tests/detection/test_static_scorer.py`). Số liệu (AUC test 0,998 và 0,999) chỉ đo trên EMBER2024, **không phải chất lượng phát hiện của DACN**; chưa nối vào Detection Engine, bộ chấm điểm chưa chạy với `thrember` thật (`thrember` không có trên PyPI), chưa có ngưỡng, kết quả chưa phải `DetectionResult`, chưa duyệt Cyber/Data. Phụ thuộc ML ở `requirements-ml.txt` (tùy chọn). Điểm ML không kích hoạt response. `static_scorer.py` (ML) và `static_analysis/` (hash/entropy/pattern) là hai module tĩnh riêng, chưa phối hợp với nhau |
| Điểm rủi ro tổng hợp (2026-11-25; cấu hình v2 ngày 2026-11-28 thêm `EXTERNAL_AV` cho alert Defender): gộp RULE/CORRELATION/IOC/STATIC (`DACN-STATIC-001`)/EXTERNAL_AV/ML theo tiến trình (`hostname`, `process_guid`) hoặc theo host trong cửa sổ thời gian dữ liệu; giải thích từng thành phần, ghi `not_evaluated` và `data_gaps`; tính khi truy vấn, không lưu; API chỉ đọc `/risk/*`, `/alerts/{id}/risk`; dashboard có tab Rủi ro | `src/risk/`, `config/risk-scoring.yaml`, `docs/implementation/RISK_SCORING.md` | Có test (`tests/risk/`, `tests/api/test_risk_api.py`, Playwright) trên Linux với dữ liệu synthetic. Trọng số là **heuristic chưa hiệu chỉnh** (loader khóa `status: heuristic_uncalibrated`); chưa được Cyber/Data duyệt; chưa chạy trên Windows. **Không kích hoạt response** (kiểm tra tĩnh bằng AST) |
| Tín hiệu ML tùy chọn (2026-11-25, **tắt mặc định**): `ML_STATIC` (bọc `static_scorer`, chỉ chấm ảnh trong `allowed_dirs`, hash lệch → `INSUFFICIENT_TELEMETRY`) và `ML_BEHAVIOR` (độ hiếm hành vi, feature contract `dacn-behavior-rarity/1`, CLI train/score tách cửa sổ, baseline JSON chỉ chứa sha256 của giá trị); lưu ở bảng nội bộ `_ml_signals` (không thuộc DDL); `runner.py` chạy trong `CoreService` khi bật | `src/detection/ml/` (`signals.py`, `static_signal.py`, `behavior.py`, `runner.py`), `config/ml-detectors.yaml`, `docs/implementation/ML_SIGNALS.md` | Có test với dữ liệu synthetic, extractor và predictor giả. **Không có số liệu chất lượng** (chưa có dữ liệu có nhãn); chỉ góp tối đa 24/100 vào điểm rủi ro; không tạo alert, không response; chưa chạy trên Windows; không thêm phụ thuộc |
| Đánh giá Atomic Red Team trên một Windows 10 VM (2026-11-26): 13 atomic an toàn ghim commit, Defender bật; công cụ đối chiếu theo cây tiến trình (pid + thời điểm → ProcessGuid → con cháu), không xuất định danh | `tests/e2e/atomic_compare.py`, `tests/e2e/atomic_expected.yaml` (kỳ vọng **đề xuất**, chưa Cyber duyệt), `docs/implementation/acceptance/ATOMIC_RED_TEAM_EVAL_GUIDE.md`, `docs/implementation/acceptance/ATOMIC_RED_TEAM_RESULTS_2026-11-26.md` | Người dùng chạy, mỗi test **một lần**. Lần 1: 5 TP (DET-001 ×1, DET-003 ×2, DET-004 ×2), 0 FN, 2 đối chứng TN / 0 FP, 4 FN dự kiến đúng lý do, 2 test Defender chặn khi tạo tiến trình (không đánh giá được). Lần 2 sau DET-003 v2 và cấu hình Sysmon thêm `\Policies\Explorer\Run`: A06 (RunOnceEx) thành TP, A07 có Event 13 nhưng v2 chưa có rule, đối chứng TN. Lần 3 sau DET-003 v3: A07 thành TP (đối chiếu với `--bronze` vì core chưa kịp nạp segment niêm phong lúc dừng). Sau ba lần: 7 TP, 0 FN trên các test có rule; A06/A07 là hồi quy cho bản sửa, không phải bằng chứng độc lập. Tập test chọn để khớp rule hiện có: **không phải tỷ lệ phát hiện chung** |
| Telemetry Windows Defender + PowerShell 4104, hạng mục 1–3, 5–7 (2026-11-28, thiết kế người dùng duyệt D1–D10 ngày 2026-11-26 thay cho Data/Cyber): `bronze-event/1.1` bổ sung (`source` WINDOWS_DEFENDER/POWERSHELL suy ra từ Channel; Sysmon giữ 1.0; kênh lạ → `C-007`), agent live đa kênh (`agent.channels`, mặc định chỉ Sysmon, kênh mới `enabled: false`; checkpoint/segment/health riêng, `degraded`); Silver DDL v1.3 **đề xuất** (`silver_defender_events`, `silver_powershell_scriptblock_events`, view ghép script block) với validator riêng route theo kênh; rule `DACN-DET-201` (Defender 1116/1117) và `DACN-DET-202` (5001/5007/5013, T1562.001) qua khóa rule `source_events`, alert `detection_source = EXTERNAL_DEFENDER`; rule type `scriptblock` với `DACN-DET-203` (chuỗi đáng ngờ trong script 4104 đã ghép) và `DACN-DET-204` (giải mã base64), alert không chứa văn bản script, evidence API không trả script; điểm rủi ro có cơ chế `EXTERNAL_AV` (cấu hình `risk-scoring.yaml` v2) cho alert Defender | `poc/sysmon-collector/windows_channels.py`, `bronze-event-1.1.schema.json`, `src/agent/multichannel.py`, `src/pipeline/validator_windows_channels.py`, `src/pipeline/sql/silver_schema_v1_3_proposal_defender_powershell.sql`, `docs/architecture/w8/telemetry-defender-powershell-proposal.md` | Test với nguồn giả và fixture synthetic trên Linux. Tên trường EventData **đã đối chiếu** với mẫu XML thật đã khử định danh từ VM (1116/1117/5007/4104; 5001/5013 chưa có mẫu); 28 sự kiện thật nạp file mode → Silver 28/28, DLQ 0 (một lần, trên Linux). **Agent live trên Windows chưa chạy** với hai kênh. DET-201/202 `synthetic_only`; trên 28 sự kiện thật (file mode, Linux, một lần): EICAR và A09 mỗi cái 1 alert DET-201, 4 sự kiện 5007 nội bộ ra 3 alert DET-202 `low` (nhiễu, chờ Cyber chọn loại trừ). DET-203/204 `synthetic_only`; 20 sự kiện 4104 lành tính thật → 0 kết quả (mẫu nhỏ, không phải số đo FP). Join tiến trình, che bí mật khi API trả script **chưa có**. Trọng số/trần `EXTERNAL_AV` (1.0/60) chờ duyệt. Rule type `scriptblock`, field `patterns`/`base64` chờ duyệt. Khóa rule `severity_by`, `context_fields`, `group_by_field` là quyết định triển khai chờ duyệt. `C-007`, `CFG-006`, trạng thái `degraded`: người dùng duyệt 2026-11-28 (thay cho Data/Software, chưa review độc lập) |
| Nghiệm thu | `tests/acceptance/at_catalog.yaml`, `scripts/acceptance/run_acceptance.py`, `docs/implementation/acceptance/` | 43 AT: 28 PASS, 1 PARTIAL, 0 FAIL, 14 NOT RUN (mức W chưa chạy; chạy lại 2026-11-18) |

**Chưa được chứng minh / chưa có:**
- Mọi thứ trên Windows thật: live Event Log, `WinProcessApi`, Sysmon config, script lab, hướng dẫn cài đặt, response `execute`.
- Chất lượng phát hiện ngoài lượt Atomic nhỏ ở trên (FP trên tải lành tính, độ trễ phát hiện, lặp lại nhiều lần), hiệu năng (CPU/RAM/độ trễ) trên VM 2 GB.
- Retention xóa thật (mới có dry-run), Windows service, Gold/Feature.
- Static analysis: chạy trên Windows 10 VM với Sysmon live, chữ ký số/offline trust provider, giao diện dashboard cho `/static/*`, nối kết quả ML với kết quả static.
- ML: chạy bộ chấm điểm tĩnh với `thrember` thật, ngưỡng đo trên tệp lành tính của VM, mô hình Win32, train `ML_BEHAVIOR` trên baseline thật của VM, mô hình trên Gold/feature; mọi phép đo ML trên Windows; mọi số liệu chất lượng ML của DACN.
- Điểm rủi ro: hiệu chỉnh trọng số và ngưỡng trên kịch bản lab và tải lành tính; Cyber duyệt cách gộp severity; hiệu năng khi có nhiều alert.
- Phê duyệt liên nhóm: DDL v1.2, schema `DetectionResult`, hostname D-07, tên event type (Q-X3), số hiệu DET-101, mã lỗi `R-*`/`A-*`, ADR 0004/0007, các schema/contract W06–W07 (`docs/architecture/w6/contracts/`, `docs/architecture/w7/contracts/`), bảng `static_candidates` và số hiệu `DACN-STATIC-001`.

**Kết quả test mới nhất (2026-11-28, Linux, Python 3.13, KHÔNG có `lightgbm`, sau hạng mục 7 điểm rủi ro `EXTERNAL_AV`):** `python -m pytest -q` → **615 pass, 2 skipped, 0 fail** (thêm 3 test `tests/risk/test_external_av.py`).

**Kết quả test (2026-11-28, sau hạng mục 6):** `python -m pytest -q` → 612 pass, 2 skipped, 0 fail (thêm 12 test `tests/detection/test_powershell_rules.py` và một test hồi quy lỗi `min()` khi DB chỉ có dữ liệu kênh v1.3, lỗi do hạng mục 5 gây ra và đã sửa).

**Kết quả test (2026-11-28, sau hạng mục 5):** `python -m pytest -q` → 599 pass, 2 skipped, 0 fail (thêm 16 test `tests/detection/test_defender_rules.py`; `docs/architecture/w6/contracts/rule.schema.json` xuất lại bằng `scripts/contracts/export_issue40_contracts.py`).

**Kết quả test (2026-11-28, sau hạng mục 3):** `python -m pytest -q` → 583 pass, 2 skipped, 0 fail (thêm 17 test `tests/pipeline/test_silver_windows_channels.py`).

**Kết quả test (2026-11-28, sau hạng mục 1–2):** `python -m pytest -q` → 566 pass, 2 skipped, 0 fail (533 pass, 2 skipped trước thay đổi trong cùng môi trường; thêm 33 test: `tests/agent/test_multichannel.py`, `tests/pipeline/test_bronze_v11_channels.py`, một test `/health` DEGRADED).

**Kết quả test (2026-11-26, Linux, Python 3.13, có `lightgbm`, sau khi thêm màn hình cây tiến trình):** `python -m pytest -q` → 539 pass, 1 skipped, 0 fail (thêm 26 test: `tests/alerts/test_process_view.py`, `tests/api/test_investigation_api.py`; kiểm tra Playwright mới nằm trong `tests/dashboard/test_dashboard_ui.py`).

**Kết quả test (2026-11-26, trước màn hình cây tiến trình, sau khi thêm `atomic_compare` (có `--bronze`), DET-003 v2/v3 và test cấu hình Sysmon):** `python -m pytest -q` → 513 pass, 1 skipped, 0 fail.

**Kết quả test (2026-11-25, sau khi thêm điểm rủi ro và tín hiệu ML):** `python -m pytest -q` → 489 pass, 1 skipped, 0 fail (thêm 61 test). `ruff check --select F` còn 3 lỗi có từ trước (`tests/static_analysis/test_workflow.py`, hai notebook Kaggle). `run_acceptance.py` chưa chạy lại.

**Kết quả test (2026-11-22, Linux, sau audit đợt 2 và merge #40):** `python -m pytest -q` → 428 pass, 1 skipped, 0 fail khi có `lightgbm` (395 trước khi thêm test cờ CLI của hướng dẫn và các test sửa lỗi Windows) (test skipped cần Windows thật, marker `windows`); 389 pass, 2 skipped khi không có `lightgbm` (đo trước khi thêm 15 test, chưa đo lại) (thêm test nạp mô hình EMBER2024 bị bỏ qua). Cả hai con số đều đã đo, ở hai thời điểm khác nhau. **Windows 10, Python 3.14, một VM, hai lần chạy:** lần 1 (trước khi sửa) 269 pass, 89 fail, 35 error, nguyên nhân chủ yếu thiếu `tzdata`; lần 2: 382 pass, 12 fail; **lần 3: 401 pass, 14 skipped, 0 fail** (12 phút). File mode qua `edr_ctl` chạy được và dashboard hiển thị. Agent live lần đầu FAIL (checkpoint dùng chung, `EvtSubscribe` thiếu `SignalEvent`); **sau khi sửa (2026-11-24): agent live đọc được Sysmon thật**, AT-03/04/05/34 quan sát đạt trên VM (thủ công, một lần). Script lab lỗi encoding trên PowerShell 5.1, đã sửa (BOM) nhưng **chưa chạy lại**; kịch bản lab, phát hiện trên dữ liệu thật và response chưa kiểm chứng. Chạy lại trước khi tin cậy.

### 3.2. TARGET ARCHITECTURE — kế hoạch, chưa được triển khai

Căn cứ: `docs/architecture/local-edr-reference-architecture-v2.md` (trạng thái **PROPOSAL / FOR REVIEW**, 04/11/2026) và `docs/decisions/0007_local_edr_modular_architecture.md` (trạng thái **PROPOSED / chưa phê duyệt**).

Kiến trúc mục tiêu gồm ba nhóm:
1. **Data plane:** Telemetry collection → Bronze bền vững (sealed JSONL) → validation/quarantine → Silver (DuckDB) → enrich/features → Detection → Alert/Incident → Investigation.
2. **Control plane:** rule/config có phiên bản, policy, allowlist, phê duyệt, kiểm soát truy cập, cập nhật có chữ ký (theo khả năng thực thi).
3. **Operations & trust:** health/watchdog, checkpoint/replay, audit, privacy/retention, an toàn khi response, recovery, đo hiệu năng trên VM.

Định hướng triển khai: **modular monolith** chạy trên cùng một host, giao tiếp bằng hàm hoặc file JSONL đã niêm phong, lưu trữ theo ADR 0005 (JSONL + DuckDB/Parquet). Tránh Kafka, cụm Elasticsearch, Kubernetes và dịch vụ cloud trong phạm vi đồ án. Không xây XDR tập trung (connector network/cloud/email/identity, multi-tenant SOC, SOAR).

Lộ trình (theo v2 mục 11):
- **W06** (Cyber dẫn dắt): Rule Model/Registry, Evaluation Contract, thiết kế correlation, ưu tiên DET-001/003/010.
- **W07** (Software + Data): Collector → sealed Bronze → Silver replay bền vững; thử nghiệm crash/restart, duplicate, bản ghi lỗi, log reset trên Windows VM.
- **W08** (Team): PoC rule có giới hạn và alert store; truy vấn process tree và truy vết bằng chứng.
- **W09+**: Investigation UI/CLI, response có phê duyệt của người dùng, khôi phục an toàn; tinh chỉnh rule.
- **W10–W12**: Test kịch bản benign và adversary-like an toàn; QA, profiling, tài liệu và demo.
- **Giai đoạn sau**: mô hình AI, IOC feeds, sensor bổ sung. Chỉ làm sau khi Giai đoạn 1 hoạt động.

Các ADR và tài liệu trạng thái chưa được chốt:
- ADR 0001, 0002, 0003, 0005, 0006: ghi là **Accepted**.
- ADR 0004: "Quyết định đề xuất từ Data; cần minh chứng xác nhận liên nhóm"; chưa có bằng chứng review độc lập.
- ADR 0007: **PROPOSED / chưa phê duyệt**.
- Hợp đồng Bronze chung (`docs/architecture/w5/contracts/README.md`): **chưa được phê duyệt chéo** giữa Data, Software và Cyber.
- Contract rule/`DetectionResult`/error (W06) và static/knowledge/candidate (W07) trong `docs/architecture/w6/contracts/`, `docs/architecture/w7/contracts/`: **đề xuất của Software, chờ Data/Cyber review** (hồ sơ: `docs/research/software/w7/03-issue-40-handoff-and-review.md`).

Ưu tiên P0 trước khi gọi kiến trúc là đã hiện thực (theo v2 mục 10): (i) owner sign-off Bronze 1.0, adapter và schema theo từng loại sự kiện; (ii) lineage và identity epoch; (iii) vòng đời và kiểm thử collector trên Windows; (iv) các trường của alert contract và quyền truy cập.

## 4. Lệnh thường dùng

Dependency nằm trong `requirements.txt`. `pytest.ini` và `conftest.py` ở thư mục gốc đã cấu hình đường dẫn; chạy mọi lệnh từ thư mục gốc repository.

```bash
pip install -r requirements.txt

# Toàn bộ test (Linux)
python -m pytest -q
python -m pytest -q tests/detection          # một thư mục
python -m pytest -q poc/sysmon-collector     # collector PoC

# Nghiệm thu: chạy pytest, sinh báo cáo trong docs/implementation/acceptance/
python scripts/acceptance/run_acceptance.py

# Chạy hệ thống (cần PYTHONPATH=src; ví dụ Linux, dữ liệu mẫu)
PYTHONPATH=src python -m edr_ctl --config <edr.yaml> start
PYTHONPATH=src python -m edr_ctl --config <edr.yaml> status
PYTHONPATH=src python -m edr_ctl --config <edr.yaml> stop
# Tạo token API: PYTHONPATH=src python -m api.auth --config <edr.yaml> --role analyst --actor <tên>

# Collector PoC ở file mode (mọi hệ điều hành)
python poc/sysmon-collector/sysmon_collector_poc.py --mode file \
  --input references/samples/raw/raw_process_create_event1.xml --output /tmp/out.json

# Detector độ hiếm hành vi (NHÁP, tắt mặc định; dừng core trước vì DuckDB một writer)
PYTHONPATH=src python -m detection.ml.behavior train --db <silver.duckdb> --since <ISO+TZ> --until <ISO+TZ> --out <dir> --model-version <v>
PYTHONPATH=src python -m detection.ml.behavior score --db <silver.duckdb> --model-dir <dir>
# Core với cấu hình ML khác mặc định: thêm --ml-config <tệp> cho python -m core

# Báo cáo độ phủ field
python poc/sysmon-collector/contract_check.py --samples references/samples --out coverage_report.md
```

Cấu hình mẫu: `config/edr.example.yaml`, `config/response-policy.yaml`. Hướng dẫn cài đặt Windows: `docs/implementation/EDR_INSTALL_GUIDE.md` (cú pháp `set PYTHONPATH` là của cmd; PowerShell dùng `$env:PYTHONPATH`). Live mode và `--live` cần Windows, `pywin32` và quyền Administrator; **chưa kiểm chứng trên Windows**.

Lệnh `pytest` và `run_acceptance.py` đã chạy lại ngày 2026-11-22 (nghiệm thu không đổi: 28 PASS, 1 PARTIAL, 14 NOT RUN); các lệnh còn lại ngày 2026-11-09, trên Linux. `scripts/contracts/export_issue40_contracts.py` và `scripts/poc/run_issue40_demo.py` chưa chạy lại trong phiên này.

## 5. Mô hình import (đọc trước khi thêm module)

Các file Python không phải là package. Chúng import lẫn nhau bằng tên module trần:
- `bronze_contract.py` có `import sysmon_collector_poc as poc`; `bronze_to_silver_adapter.py` import `bronze_contract` và `sysmon_collector_poc`.
- `test_canonical_bronze_contract.py` import `bronze_contract`, `bronze_to_silver_adapter` và `validator_poc` bằng tên trần.
- `tests/test_validator_poc_w5.py` và `test_canonical_bronze_contract.py` tự chèn `src/pipeline` vào `sys.path`.

Các package trong `src/` (`agent`, `pipeline`, `detection`, `alerts`, `response`, `static_analysis`, `risk`, `api`, `core`, `common`) là package thật nhưng không cài đặt. `api.auth`, `edr_ctl` và `detection.ml.static_scorer` chạy được với `PYTHONPATH=src`; `agent`, `pipeline`, `core`, `api`, `response` còn import `bronze_contract`, `validator_poc`… nên cần `PYTHONPATH` gồm `src`, `src/pipeline` và `poc/sysmon-collector` (như `EDR_INSTALL_GUIDE.md` mục 2; `edr_ctl start` tự đặt cho tiến trình con). Test đã được `pytest.ini`/`conftest.py` cấu hình sẵn.

Chạy test từ thư mục gốc repository bằng `python -m pytest` để rootdir của pytest đưa `poc/sysmon-collector` vào đường dẫn. Chạy script từ thư mục khác sẽ làm hỏng các import này.

## 6. Kiến trúc hiện tại: luồng dữ liệu

> Mục này mô tả chuỗi PoC (collector → Bronze envelope → adapter → validator). Chuỗi chạy thật nằm trong `src/`: `agent` → Bronze sealed (JSONL + manifest) → `pipeline` (Silver DuckDB) → `detection` → `alerts` → `response`/`api`/`dashboard`, do `core` và `edr_ctl` điều phối. Xem `docs/implementation/EDR_TARGET_ARCHITECTURE.md`.

Dữ liệu đi qua bốn bước. Mỗi bước giữ nguyên payload gốc của Sysmon và không tự tạo field không có trong nguồn.

1. **Collect** (`poc/sysmon-collector/sysmon_collector_poc.py`). Parse XML `<Event>` (từ export `wevtutil`/`Get-WinEvent` hoặc đọc trực tiếp bằng `win32evtlog`) và tạo bản ghi PoC đã chuẩn hóa, gồm:
   - `event_id` = UUIDv5 trên `Computer|Channel|EventRecordID`, dùng namespace cố định.
   - `event_type` lấy từ bảng ánh xạ Sysmon ID, ví dụ `1 → PROCESS_START`, `3 → NETWORK_CONNECT/ACCEPT`.
   - `data` (field đã kiểu hóa như `pid`, `image_path`, `hashes`) và `raw_data` (tên field EventData gốc).

2. **Bronze envelope** (`bronze_contract.py` + `bronze-event.schema.json`). Bọc một sự kiện thành bản ghi chuẩn `bronze-event/1.0`. Bản ghi giữ nguyên `raw_xml` và `event_data`, kèm `host_id` (UUIDv5 của hostname viết thường) và metadata `ingest`. `validate_record` kiểm tra bản ghi theo JSON Schema.

3. **Adapter** (`bronze_to_silver_adapter.py`). `to_silver_input` hoạt động theo nguyên tắc fail closed: kiểm tra envelope, tính lại định danh (`event_id`, `host_id`), đối chiếu `raw_xml` đã parse với `event_data` đã lưu. Sai lệch sẽ gây `BRONZE_IDENTITY_MISMATCH` hoặc `BRONZE_RAW_MISMATCH`. Kết quả là dict phẳng mà validator cần.

4. **Validate và route** (`src/pipeline/validator_poc.py`, `SilverValidatorEngine`). Đây là bản sao độc lập của thiết kế Data W05; không import collector. Các kiểm tra chạy theo thứ tự:
   - Khóa tự nhiên, kiểu `record_id`, Sysmon ID được hỗ trợ (`SUPPORTED_SYSMON_IDS`), khoảng thời gian hợp lệ, định dạng `process_guid`.
   - Loại trùng theo `event_id` xác định.
   - Route vào một trong bốn nhóm Silver: process `{1,5}`, file `{11,15,23,26,29}`, registry `{12,13,14}`, network `{3,22}`.
   - Bản ghi không qua kiểm tra nào vào `quarantine_dlq` với mã `ERR_*`. Không có bản ghi nào bị bỏ âm thầm hoặc được điền giá trị giả.

`contract_check.py` là báo cáo độ phủ, không phải cổng kiểm soát. Nó đối chiếu từng field EventData với bảng `EXPECTED`, ghi nhận field đã có cột Silver (`in_silver`), chưa có (`missing_in_silver`), hoặc chưa có bảng đích (`no_target`).

`src/pipeline/sql/silver_gold_schema_and_views_v1_1.sql` là DDL đã duyệt cho schema Silver/Gold; `validator_poc.py` vẫn tự tạo bảng DuckDB trong bộ nhớ và không thực thi file này. Hệ thống chạy thật (`src/pipeline/silver_store.py`, DuckDB bền vững) dùng DDL v1.2 trong `src/pipeline/sql/silver_gold_schema_and_views_v1_2_proposal.sql`, đây là **đề xuất chưa được duyệt**; không sửa v1.1.

## 7. Lưu ý kỹ thuật

- **Logic bị nhân bản.** `validator_poc.py` tự cài lại `strip_guid`, `parse_iso_utc`, phần phân tích registry và hằng số namespace `EDR_NAMESPACE`, thay vì import từ collector. Hai hằng số namespace phải giống hệt nhau. `test_01_deterministic_uuidv5_matches_w3_real_samples` trong `tests/test_validator_poc_w5.py` đối chiếu event ID của validator với mẫu W3 thật, nên sai lệch giữa hai bản sẽ lộ ra ở đó.
- **Hai bộ tên event type.** Collector phát các tên như `PROCESS_START` và `REGISTRY_SET_VALUE`. `EVENT_ID_TO_TYPE_DEFAULT` của validator dùng tên gần giống nhưng không hoàn toàn trùng, ví dụ `REGISTRY_RENAME` so với `REGISTRY_RENAME_KEY` của collector. Comment trong collector ghi đây là quyết định đang chờ Q-X3. Không giả định hai phía khớp nhau.
- **Không bịa dữ liệu (Zero Data Fabrication).** Field thiếu vẫn để thiếu; bản ghi thiếu field bắt buộc bị đưa vào quarantine thay vì được điền mặc định. Giữ nguyên hành vi này khi mở rộng code.
- **Bộ mẫu chưa khử định danh hoàn toàn.** `references/samples/` và fixture test chứa tên máy và tên người dùng trông thật (ví dụ `DESKTOP-IDEMGQU`). Theo README, cần kiểm tra trước khi chia sẻ. Không công bố, không sao chép sang tài liệu hoặc file công khai mới.
- **Tài liệu.** `docs/` viết bằng tiếng Việt, tổ chức theo tuần (`w1`–`w5`) và theo chủ đề (`architecture`, `research`, `decisions`, `scope`). Các ADR 0001–0003 quy định event ID, GUID và bảo tồn dữ liệu thô; kiểm tra chúng trước khi đổi các quy tắc này.

## 8. Quy định làm việc của AI Agent

1. Trước khi sửa code, đọc `README.md`, ADR liên quan trong `docs/decisions/`, schema và data contract, tài liệu kiến trúc, phạm vi Giai đoạn 1 và các GitHub Issues liên quan.
2. Tuân thủ các quyết định kiến trúc đã được chấp thuận (ADR trạng thái Accepted). Không coi ADR PROPOSED là quyết định đã chốt.
3. Không tự ý thay đổi data contract, event identity, UUID, cơ chế raw preservation hoặc quy tắc chuẩn hóa dữ liệu.
4. Đảm bảo tương thích giữa ba nhóm **Software**, **Data** và **Cybersecurity**. Khi thay đổi ảnh hưởng đến nhóm khác, nêu rõ trong báo cáo.
5. Không commit trực tiếp lên `main`. Không tự merge Pull Request.
6. Commit và push chỉ thực hiện khi người dùng yêu cầu rõ ràng và đã xem xét thay đổi.
7. Khi triển khai một issue: tạo branch riêng, thực hiện thay đổi trong phạm vi issue, chạy test và báo cáo kết quả.
8. Không sửa thành phần ngoài phạm vi issue nếu không thực sự cần thiết.
9. Các lỗi test đã ghi nhận trong mục 3.1 phải được chạy lại để xác minh; không mặc định vẫn còn tồn tại.
10. Không đưa secret, token, thông tin nhận dạng máy thử nghiệm, tên người dùng thật hoặc dữ liệu nội bộ vào tài liệu công khai, commit message hay PR.
11. Ưu tiên sửa các vấn đề kỹ thuật hiện có trước khi mở rộng chức năng.
12. Không thay đổi phạm vi, milestone hoặc kế hoạch 12 tuần nếu chưa được phê duyệt.
13. Khi phát hiện mâu thuẫn giữa tài liệu và code, báo cáo rõ trước khi thực hiện thay đổi ảnh hưởng đến kiến trúc.
14. Khi cần thông tin về GitHub (Issue, PR, CI), dùng công cụ GitHub của session; không giả định nội dung issue khi chưa đọc.

## 9. Quy trình triển khai issue

1. Đọc issue và tiêu chí nghiệm thu.
2. Xác định module, tài liệu và data contract liên quan.
3. Kiểm tra trạng thái code hiện tại và chạy lại test liên quan.
4. Lập kế hoạch triển khai và nêu rõ phần nào thuộc CURRENT STATE, phần nào thuộc TARGET.
5. Tạo branch theo quy ước trong mục 10.
6. Triển khai code trong phạm vi được giao.
7. Chạy unit test, integration test hoặc kiểm thử phù hợp.
8. Kiểm tra khả năng tương thích với module hiện có.
9. Cập nhật tài liệu khi cần.
10. Báo cáo: các file đã sửa, kết quả test (kèm lệnh và thời điểm), vấn đề tồn đọng, và hướng dẫn chạy trên Windows.
11. Chỉ push và tạo Pull Request khi có quyền GitHub phù hợp và người dùng yêu cầu.
12. Không tự merge Pull Request.

## 10. Quy ước Git

- **Commit message** theo Conventional Commits, scope lấy từ `docs/conventions/03-commit-convention.md`: `feat(collector): ...`, `fix(silver): ...`, `docs(architecture): ...`, `test(...)`, `chore(...)`. Mô tả ngắn ở thì hiện tại, không viết hoa chữ đầu, không có dấu chấm cuối. Dùng `Refs #n` hoặc `Closes #n` ở footer khi liên quan đến issue.
- **Tên branch** theo `<loại>/<mô-tả-ngắn>` hoặc `<loại>/<issue-id>-<mô-tả-ngắn>`, với loại `feature/`, `fix/`, `docs/`, `research/`, `refactor/`, `chore/`. Viết thường, nối bằng dấu `-`, không có khoảng trắng. Xem `docs/conventions/02-branch-convention.md`.
- Nhánh làm việc tạo từ nhánh chính (`main`, hoặc `develop` nếu dùng).

## 11. Issue đang mở (kiểm chứng ngày 2026-11-08)

- #26 `[W05][Team]` Thống nhất thiết kế Data Pipeline và nghiệm thu các hợp đồng dữ liệu
- #27 `[W05][Data]` Thiết kế Bronze/Silver/Gold, schema, chất lượng và lineage dữ liệu
- #28 `[W05][Cyber]` Xác thực dữ liệu và khả năng truy vết phục vụ Detection/Investigation
- #29 `[W05][Software]` Thiết kế giao diện Collector–Pipeline và khả năng triển khai lưu trữ cục bộ
- #38 `[W06–W07][Cyber]` Thiết kế Detection Engine, Static Analysis, Whitelist và Threat Signature
- #39 `[W06–W07][Data]` Thiết kế hợp đồng Detection/Alert và mô hình dữ liệu Static–Whitelist–Signature
- #40 `[W06–W07][Software]` Thiết kế module Detection Engine và tích hợp Static Analysis/Whitelist vào Local EDR

Danh sách này có thể đã thay đổi; kiểm tra lại trước khi dùng.

## 12. Quản lý tài liệu này

- `CLAUDE.md` là hướng dẫn cho AI Agent, không thay thế README hoặc tài liệu kiến trúc. Ưu tiên dẫn chiếu đến tài liệu gốc thay vì sao chép nội dung dài.
- Khi cấu trúc, kiến trúc, trạng thái ADR hoặc kết quả test thay đổi, cập nhật mục 3 và mục 4 của file này.
- Mọi thông tin về trạng thái test phải ghi ngày kiểm chứng; sau thời điểm đó, yêu cầu chạy lại.
- Chỉ các tài liệu hướng dẫn AI thực sự cần thiết mới được thêm vào repository.

## 13. Tài liệu gốc cần đọc

- `README.md`: mục tiêu, trạng thái, cấu trúc repository, ví dụ chạy PoC.
- `docs/scope/phase-1-scope.md`, `docs/scope/data_pipeline_phase_1_scope.md`: phạm vi Giai đoạn 1.
- `docs/decisions/`: ADR 0001–0007 và `week-1-decisions.md`.
- `docs/architecture/local-edr-reference-architecture-v2.md`: kiến trúc mục tiêu (PROPOSAL).
- `docs/architecture/w5/`: hợp đồng dữ liệu, schema reconciliation, validation và lineage.
- `docs/architecture/w6/`, `docs/architecture/w7/`: kiến trúc Detection và static/whitelist/signature (đề xuất, chờ review).
- `docs/report/`: báo cáo tiến độ theo tuần.
- `docs/conventions/`: quy ước nhánh, commit, issue và GitHub Project.
