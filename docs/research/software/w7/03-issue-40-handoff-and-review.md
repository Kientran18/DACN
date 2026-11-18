# Issue #40 — Hồ sơ bàn giao Software W06–W07

Ngày: **17/11/2026 (Asia/Saigon)**. Nhánh làm việc: `codex/40-static-review-completion`, từ `origin/claude_implement` commit `685b3c7fbc09ce7229546f342c48ba324debf95c`. [Yêu cầu GitHub #40](https://github.com/Kientran18/DACN/issues/40).

**Trạng thái:** hoàn thiện thiết kế và PoC Software trong workspace, có kiểm thử; **chờ Data/Cyber review**, chưa tự đóng issue, chưa commit/push/PR. Không nhận đã nghiệm thu trên Windows 10 VirtualBox/Sysmon live. Kế hoạch cũ `docs/plan/issue-40-resolution-plan.md` là bản đã có trước công việc này, không phải bằng chứng thực thi.

## 1. Danh mục bàn giao và ánh xạ checklist

| Checklist #40 | Bằng chứng | Trạng thái Software |
|---|---|---|
| W06 rà Collector/contract/adapter/validator/Silver-Gold | [baseline/gap matrix](../w6/01-baseline-and-contract-gap-matrix.md) | Designed, đã rà source |
| Module boundary và quyền/ownership | [Detection Architecture](../../../architecture/w6/detection-module-architecture-v1.md) | Designed; PoC trên nhánh nền + bổ sung |
| Read-only detector / single writer | Architecture mục2; Core/API shared connection/RLock | Implemented same-process; snapshot export Designed |
| Versioned rule/result, references, error/completeness | [W06 schemas/examples](../../../architecture/w6/contracts/README.md), error-envelope spec, EvidenceResolver | Implemented rule/result; error envelope Designed; owner review pending |
| Python structure, loader/version/config | [Rule/Config Design](../w6/02-rule-loading-and-config-design.md), `src/detection/` | Loader/schema Implemented; signed/hot YAML package update Future |
| Late events/lifetime/replay/alert dedup | host watermark, optional lateness, process_context helper, durable outbox + frozen rule metadata, tests | Implemented bounded PoC; streaming/clock sequence/quotas Future |
| Windows/resource/log/error feasibility | [Feasibility/test plan](../w6/03-feasibility-and-test-plan.md) | Designed; host fixture tests, VM chưa chạy |
| Synthetic/W03/negative test strategy | tests/detection, tests/core/test_issue40_delivery.py, tests/static_analysis | Tested fixture; không gán accuracy |
| W07 Static Extractor | [W07 Architecture](../../../architecture/w7/static-whitelist-signature-design-v1.md), `src/static_analysis/extractor.py` | Hash/size/entropy/minimal PE Implemented; digital signature UNAVAILABLE + provider Designed |
| Telemetry vs current bytes, TOCTOU/locked/deleted/denied/large | [Windows File Access/Safety](01-windows-file-access-and-safety.md) | Designed + error/identity/budget tests |
| IOC/Whitelist/Signature Store/Candidate Review | knowledge.py, review.py, service.py, API `/static/*` | Implemented bounded local PoC |
| Version/update validation/cache/expiry/rollback | KnowledgeStore + [Architecture mục5](../../../architecture/w7/static-whitelist-signature-design-v1.md) | Activate/rollback/expiry Implemented; no stale cache; signed distribution Future |
| Safe policy/protected targets/review audit/no automatic response | allowed lab root, exact-hash allowlist, role/CAS/reason/audit, no ResponseExecutor call | Implemented; tests no response |
| JSON static/verdict/hit/candidate | [W07 schemas/examples](../../../architecture/w7/contracts/README.md) | Exported/validated; Data/Cyber approval pending |
| W06 integration, W08/W09 extension | [API/flow](02-candidate-review-and-integration-api.md), Architecture sequence | Implemented static→DetectionResult/Alert; W08/W09 interface Designed |
| Benign PoC evidence/dependencies/limitations | [poc-demo.json](poc-demo.json), script `scripts/poc/run_issue40_demo.py`, tests, dependencies snapshot | Tested lab/fixture; không malware/benchmark claim |

## 2. Thay đổi chính

- Thêm `src/static_analysis/{extractor,knowledge,contracts,review,service}.py`: không execute file hoặc fetch threat feed.
- Thêm 8 endpoint static/candidate/knowledge (bao gồm candidate history) trong `src/api/app.py`; actor từ token, quyền duyệt riêng, stale revision reject.
- Thêm bảng mở rộng `static_candidates`, dùng cùng writer và audit transaction; không đổi Bronze/UUID/Silver v1.1.
- Detector có host watermark, lateness option, giữ pending anchors, cho closed partial được sửa thành MATCH nếu evidence hợp lệ đến muộn; helper lifetime không PID join.
- Durable `_detection_outbox`: result/cursor/outbox atomic; delivery mang rule metadata/version đóng băng; alert + ack atomic. Restart/crash được test; không claim exactly-once streaming.
- Xuất schemas/examples có kiểm chống drift; bổ sung component/sequence/state diagrams, review package, dependencies và hướng dẫn tái lập.
- Hai test baseline được làm portable: missing pywin32 được mô phỏng thay vì mở channel thật; time tolerance dùng timezone rõ ràng. Không sửa runtime response/collector để che lỗi.

## 3. Kiểm chứng thực tế

Môi trường: **Windows host, Python 3.12.8**, fixture/local temp files, loopback TestClient; không phải Windows 10 VirtualBox với Sysmon live. Dependencies xem [verification-dependencies.txt](verification-dependencies.txt). Socket loopback của event loop phải được môi trường thực thi cho phép; lần chạy hạn chế ban đầu bị treo tại socketpair, đã dừng và chạy lại với quyền phù hợp.

| Lệnh | Kết quả đã quan sát |
|---|---|
| `python -m pytest -q tests/static_analysis tests/detection/test_issue40_correlation.py tests/core/test_issue40_delivery.py` | 32 pass, 1 skip ở lần kiểm trước khi thêm test pattern-expiry; kết quả cuối cập nhật bên dưới |
| `python -m pytest -q --ignore=tests/dashboard --ignore=tests/e2e/test_edr_ctl_real_processes.py` | **259 passed, 6 skipped**, 1 dependency deprecation warning; 136.25s |
| `python scripts/contracts/export_issue40_contracts.py` | Export schemas/examples thành công; có test validate và chống drift |

Regression loại trừ dashboard Playwright (không cài browser tooling trong task này) và test launcher đa tiến trình tự mô tả Linux, thay SystemRoot/TEMP bằng `/tmp`. Không nhận đã chạy hai nhóm này. Các skip còn lại là điều kiện platform/dependency trong suite; symlink test mới skip khi không có quyền tạo symlink. Test Windows exclusive-lock mới dùng file vô hại và handle được đóng; không chạm tiến trình hay file hệ thống.

Lần regression trước portable test fixes: 254 pass/6 skip/2 fail; hai failure cũ là test thiếu pywin32 nhưng host đã có thư viện và oracle timezone implicit UTC trên host UTC+7. Thay đổi chỉ test isolation/timezone input, không thay behavior runtime. Live Sysmon channel không có trên host nên không thử cài hoặc cấu hình sensor.

Kết quả cuối bộ test mới, PoC và kiểm tra tài liệu được cập nhật sau khi chạy ở cuối hồ sơ. Không thay thế báo cáo acceptance PH12/43 AT lịch sử bằng số pytest mới; chưa chạy lại bộ nghiệm thu Windows live.

**Kết quả cuối đã chạy:** bộ test riêng #40 ở lệnh đầu đạt **35 passed, 1 skipped**, 1 dependency deprecation warning, 9.69s. Skip là symlink cần quyền Windows; test exclusive file lock thật trên Windows host đã PASS. PoC `run_issue40_demo.py` trả **PASS**, artifact đã redacted path/filesystem IDs. Kiểm tra 11 file Markdown W06/W07: **0 broken links**; `git diff --check` không báo lỗi. Regression 259/6 ở trên được chạy trước hai ca đường dẫn invalid cuối, hai ca đó đã chạy trong bộ #40 cuối.

## 4. Ranh giới Designed / Tested / Future

**Tested:** known hash/byte entropy, bounded file access/errors, changed-during-read, real exclusive lock trên Windows host, minimal synthetic PE, chunk-boundary patterns, package schema/version/expiry/corruption/rollback, candidate role/state/CAS/audit rollback, source-path/hash validation, static alert-only, correlation host/lateness/replay, outbox crash/restart, schema exports.

**Designed chưa có runtime đầy đủ:** optional offline signature trust provider; snapshot export nếu tách process; error-envelope publisher riêng; W08 Risk/W09 interface. Signature PoC trả UNAVAILABLE, không tự gán trusted/unsigned. Helper process_context là tham chiếu, chưa rewrite toàn bộ query/view W05 hay enrich mọi rule.

**Future/out-of-scope:** hard timeout cho syscall bị treo (hiện cooperative chunk deadline), multi-process knowledge writers, cryptographically signed feed/update distribution, full PE imports/YARA, benchmark accuracy/resource, streaming guarantee, Windows service/driver protection, GUI đầy đủ, mô hình AI, auto-response. Không cần hoàn thiện các hạng mục này để nghiệm thu phạm vi thiết kế #40.

## 5. Review cần người thật và điều kiện đóng issue

| Reviewer / nội dung | Trạng thái | Evidence |
|---|---|---|
| Data (#39): schemas W06/W07, static_candidates extension, v1.2 dependencies, clock/lineage | PENDING | Chưa có sign-off |
| Cyber (#38): proposed DACN-STATIC-001, rule conditions/thresholds, whitelist conflict, signature semantics, review policy | PENDING | Chưa có sign-off |
| Software: source/design/tests trong workspace | Có implementation và bằng chứng ở trên | Chưa commit/push/PR |
| Windows10 VirtualBox: Sysmon live, real permission/reparse/telemetry chain và profiling | NOT RUN | Không suy ra từ host fixture tests |

Các quyết định W05 (#26–#29), DDL v1.2, hostname/epoch/µs/event enum vẫn thuộc owner tương ứng; không tự phê duyệt trong #40. Proposed API/DDL/namespace đã tách version và có khả năng review. Khởi động database có detection results từ trước outbox cần replay/đánh giá migration có kiểm soát; không nhận tự backfill lịch sử đã thiếu alert.

**Chỉ đóng #40 sau:** Data/Cyber review đúng phạm vi thiết kế, giải quyết hoặc chấp nhận các điểm còn mở, có commit/PR + liên kết bằng chứng trong issue. File [draft bàn giao GitHub](04-github-handoff-draft.md) sẵn để người dùng review; chưa đăng/sửa issue hoặc gửi thông báo người khác.

## 6. Tái lập

Từ repo root, môi trường Python có `requirements.txt`:

```powershell
python scripts/contracts/export_issue40_contracts.py
python -m pytest -q tests/static_analysis tests/detection/test_issue40_correlation.py tests/core/test_issue40_delivery.py
python scripts/poc/run_issue40_demo.py --out artifacts/issue40/poc-demo.json
```

API hiện hữu thêm `/static/*`; tạo token theo docs/api, đặt file benign trong `<EDR_HOME>/lab`, analyst POST `/static/analyses`. Package do approver activate với schema/reason/expected_revision, không có tự tải feed. Demo chỉ tạo file marker trong thư mục tạm, không cài Sysmon, không execute file, không gọi response.
