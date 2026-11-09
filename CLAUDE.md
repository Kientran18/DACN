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

Các chức năng AI/ML (anomaly detection, risk scoring) mới chỉ có giao diện (tắt mặc định, không có mô hình); chưa có mô hình nào được triển khai.

Phạm vi Giai đoạn 1 (đồ án chuyên ngành, 12 tuần) được ghi tại `docs/scope/phase-1-scope.md` và `docs/decisions/week-1-decisions.md`. Giai đoạn 2 (luận văn) tập trung hiện thực, tích hợp và đánh giá.

## 3. Trạng thái hiện tại và kiến trúc mục tiêu

Phân biệt rõ hai nhóm thông tin. **Không mô tả thành phần thuộc TARGET như thể đã hoàn thành.**

### 3.1. CURRENT STATE — đã triển khai và có bằng chứng

Căn cứ: mã nguồn trên nhánh tích hợp `claude_implement` và kết quả test ngày **2026-11-09** (Linux, Python 3.13). Chi tiết: `docs/implementation/` (`EDR_PROGRESS.md`, `EDR_TASK_BACKLOG.md`, `handover/TEST_REPORT.md`, `handover/LIMITATIONS_AND_RISKS.md`).

| Thành phần | Vị trí | Mức độ kiểm chứng |
|---|---|---|
| Sysmon collector PoC, Bronze contract, adapter, validator W05 | `poc/sysmon-collector/`, `src/pipeline/validator_poc.py` | Có test; dữ liệu synthetic và mẫu lab. Bronze contract vẫn là **đề xuất**, chưa phê duyệt chéo |
| Agent (nguồn giả/tệp/Event Log, Bronze sealed + manifest, checkpoint, recover) | `src/agent/` | Có test trên Linux; nguồn Event Log thật **chưa chạy trên Windows** |
| Pipeline (Silver DuckDB, dedup, quarantine/DLQ, replay, ledger) | `src/pipeline/` | Có test trên Linux; dùng DDL v1.2 là **đề xuất chưa duyệt** |
| Detection Engine (DET-001/002/003/004/010/101 bật; DET-007/008 blocked; IOC, allowlist, correlation, 4 kết quả đánh giá) | `src/detection/`, `config/` | Có test với fixture; mọi rule `synthetic_only`, chưa hiệu chỉnh, không có số liệu TP/FP/FN |
| Alert/Incident, audit hash-chain, truy vết alert→Silver→Bronze→raw_xml | `src/alerts/` | Có test trên Linux |
| Response Engine (mặc định `dry_run`, hai khóa execute, duyệt, quarantine/restore) | `src/response/`, `config/response-policy.yaml` | Có test với backend giả; **chưa từng thực thi hành động thật**; có ADD/REMOVE_WHITELIST (chưa chạy thật). Auto-response và block-hash nằm ở `experimental/`, chưa nối vào hệ thống |
| API FastAPI (loopback, 4 vai trò) và Dashboard tĩnh | `src/api/`, `src/dashboard/` | Có test (kể cả Playwright) trên Linux |
| Core service và launcher | `src/core/`, `src/edr_ctl.py` | Chạy nhiều tiến trình thật trên Linux; chưa trên Windows |
| Script lab (SC01–SC07) và kiểm tra môi trường Windows | `scripts/lab/`, `scripts/windows/` | Chỉ kiểm tra tĩnh; **chưa chạy trên Windows** |
| Nghiệm thu | `tests/acceptance/at_catalog.yaml`, `scripts/acceptance/run_acceptance.py`, `docs/implementation/acceptance/` | 43 AT: 28 PASS, 1 PARTIAL, 0 FAIL, 14 NOT RUN (mức W chưa chạy) |

**Chưa được chứng minh / chưa có:**
- Mọi thứ trên Windows thật: live Event Log, `WinProcessApi`, Sysmon config, script lab, hướng dẫn cài đặt, response `execute`.
- Chất lượng phát hiện, hiệu năng (CPU/RAM/độ trễ) trên VM 2 GB.
- Retention xóa thật (mới có dry-run), Windows service, Gold/Feature, mô hình ML (chỉ có giao diện, tắt mặc định).
- Phê duyệt liên nhóm: DDL v1.2, schema `DetectionResult`, hostname D-07, tên event type (Q-X3), số hiệu DET-101, mã lỗi `R-*`/`A-*`, ADR 0004/0007.

**Kết quả test (2026-11-09, Linux):** `python -m pytest -q` → 233 pass, 0 fail. Chưa có kết quả nào trên Windows. Chạy lại trước khi tin cậy.

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

# Báo cáo độ phủ field
python poc/sysmon-collector/contract_check.py --samples references/samples --out coverage_report.md
```

Cấu hình mẫu: `config/edr.example.yaml`, `config/response-policy.yaml`. Hướng dẫn cài đặt Windows: `docs/implementation/EDR_INSTALL_GUIDE.md` (cú pháp `set PYTHONPATH` là của cmd; PowerShell dùng `$env:PYTHONPATH`). Live mode và `--live` cần Windows, `pywin32` và quyền Administrator; **chưa kiểm chứng trên Windows**.

Các lệnh test đã chạy lại ngày 2026-11-09 trên Linux.

## 5. Mô hình import (đọc trước khi thêm module)

Các file Python không phải là package. Chúng import lẫn nhau bằng tên module trần:
- `bronze_contract.py` có `import sysmon_collector_poc as poc`; `bronze_to_silver_adapter.py` import `bronze_contract` và `sysmon_collector_poc`.
- `test_canonical_bronze_contract.py` import `bronze_contract`, `bronze_to_silver_adapter` và `validator_poc` bằng tên trần.
- `tests/test_validator_poc_w5.py` và `test_canonical_bronze_contract.py` tự chèn `src/pipeline` vào `sys.path`.

Các package trong `src/` (`agent`, `pipeline`, `detection`, `alerts`, `response`, `api`, `core`, `common`) là package thật nhưng không cài đặt; chạy chúng bằng `PYTHONPATH=src` (test đã được `pytest.ini`/`conftest.py` cấu hình sẵn).

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
- `docs/report/`: báo cáo tiến độ theo tuần.
- `docs/conventions/`: quy ước nhánh, commit, issue và GitHub Project.
