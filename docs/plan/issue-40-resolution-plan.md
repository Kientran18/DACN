# Kế hoạch giải quyết issue #40 — Software W06–W07

Ngày kiểm tra: 10/11/2026 (Asia/Saigon). Người được giao: **BuiCuongTuan**.

Trạng thái: **KẾ HOẠCH ĐỀ XUẤT**, chưa phải báo cáo thiết kế hoàn thành hoặc kết quả kiểm thử. Thời lượng bên dưới là ước lượng công sức, không phải deadline đã được nhóm xác nhận.

## 1. Kết quả kiểm tra GitHub và bản mã hiện tại

| Issue đang mở được giao | Vai trò của bạn | Hướng xử lý |
| --- | --- | --- |
| [#40 — Detection Engine, Static/Whitelist W06–W07](https://github.com/Kientran18/DACN/issues/40) | Software phụ trách | Công việc chính của kế hoạch này |
| [#29 — Collector–Pipeline W05](https://github.com/Kientran18/DACN/issues/29) | Software phụ trách | Kế thừa tài liệu đã có, rà phần review/bằng chứng còn thiếu |
| [#26 — Nghiệm thu hợp đồng W05](https://github.com/Kientran18/DACN/issues/26) | Đồng phụ trách với Data/Cyber | Chốt các giao diện ảnh hưởng W06–W07; không tự nghiệm thu thay nhóm |

- Nhánh local: `docs/update-project-docs-w4-w5`, HEAD `330b7f9`; cây làm việc sạch tại lúc kiểm tra. Không có adapter/validator/schema W05 mới trong danh sách file local đã kiểm tra.
- Đã đọc trực tiếp các file mới trên GitHub `main`; tree SHA tại lúc kiểm tra: `3d68e806a96b30f9d55f35404980a5cce74b6191`. Chưa đổi nhánh hoặc đồng bộ bản mã trên máy.
- [PR #30](https://github.com/Kientran18/DACN/pull/30) và [PR #34](https://github.com/Kientran18/DACN/pull/34) đã merge. Issue #29 vẫn mở; nội dung `Closes #29` trong PR không đủ để kết luận issue đã hoàn thành.
- [Canonical contract W05](https://github.com/Kientran18/DACN/blob/main/docs/architecture/w5/contracts/README.md) vẫn ghi **COMMON CONTRACT PROPOSAL — NOT YET CROSS-TEAM APPROVED**. Bronze canonical là `bronze-event/1.0`; Silver v1.1. Việc đã merge không thay thế xác nhận của owner.
- [PR #36](https://github.com/Kientran18/DACN/pull/36) vẫn mở. Roadmap mục 11 trong [Architecture v2 trên main](https://github.com/Kientran18/DACN/blob/main/docs/architecture/local-edr-reference-architecture-v2.md) còn khác trọng tâm W07/W08 của issue #40. Kế hoạch này bám yêu cầu #40: W06 Detection, W07 Static/Whitelist, W08 AI/Risk.
- Issue #40 chưa có comment tại lúc kiểm tra. Chưa thấy thư mục bàn giao W06/W07 trong tree `main` đã đọc.

## 2. Phạm vi và cách tổ chức công việc

**Bắt buộc:** thiết kế module, JSON/schema/API nội bộ, component/sequence diagrams, rule/config lifecycle, correlation/replay/dedup, static/whitelist/candidate flow, Windows feasibility, test plan và review Data/Cyber.

**Tùy chọn sau khi thiết kế ổn định:** PoC giới hạn DET-001/003, DET-010 và hash/metadata/allowlist bằng fixture hoặc file lab vô hại. Chỉ làm phần có đủ đầu vào và thời gian; ghi rõ phần thực thi thật.

Không dùng hoàn thiện Collector/Bronze, production service, driver protection, GUI đầy đủ hay benchmark toàn hệ thống làm điều kiện đóng #40. Các thiếu sót ingestion/identity/lineage được theo dõi như phụ thuộc hoặc backlog có owner.

Tạo nhánh từ `origin/main` đã cập nhật khi bắt đầu thực hiện, đề xuất `docs/40-detection-static-module-design` theo quy ước nhánh của repo. Chia hai PR để review: W06 trước, W07 sau; cùng liên kết `Refs #40`. Chỉ đề nghị đóng issue sau khi cả hai phần và review bắt buộc đã hoàn thành.

## 3. Các quyết định cần chốt trước khi đóng băng giao diện

| Mã | Phát hiện / việc cần quyết định | Người xác nhận đề xuất | Cách tiếp tục khi còn mở |
| --- | --- | --- | --- |
| Q1 | Bronze 1.0, mapping Silver v1.1 và required fields theo Event ID | Data + Software, Cyber review | Thiết kế dựa proposal có ghi version; không đổi Bronze envelope |
| Q2 | Adapter trả `bronze_source` nhưng chưa có cột Silver bền vững tương ứng | Data; Cyber xác nhận yêu cầu evidence | Đề xuất provenance contract/sidecar; mock bằng fixture có nhãn, không nhận đã chứng minh persistence |
| Q3 | Gold DDL chưa có `rule_version`, `outcome`, `missing_fields`, `coverage_status`; bắt buộc `confidence_score`, `process_guid`, `image_path` có thể không phù hợp static result | Data + Cyber | Viết gap matrix và đề xuất migration/adapter; không gán số điểm/GUID/path giả để insert |
| Q4 | Một số enriched views nối theo GUID chưa kèm hostname/lifetime | Data + Software | Spec detector bắt buộc host + GUID + lifetime; ghi đề nghị chỉnh query và fixture cross-host |
| Q5 | UUIDv5 theo hostname/channel/record_id có rủi ro khi log reset | Data + Software | Ghi collision/epoch requirement và migration đề xuất; không âm thầm đổi ID legacy |
| Q6 | Chọn reader topology, snapshot consistency, clock và allowed lateness | Data + Software; Cyber chốt ý nghĩa rule | Dùng snapshot bất biến cho thiết kế/PoC; cấu hình ngưỡng có nhãn chưa hiệu chỉnh |
| Q7 | Whitelist precedence, IOC conflict, protected targets và quyền duyệt candidate | Cyber + Software; Data chốt schema | Lưu cả evidence và lý do suppression/conflict; mặc định alert-only |
| Q8 | Hệ điều hành, Python/dependency và quyền thực tế trên VM | Software | Ghi môi trường chưa kiểm chứng; không nhận test trên máy host là test Windows VM |

## 4. Kế hoạch W06 — Detection Module Architecture

### Bước 1 — Lập baseline và ma trận tương thích (4–5 giờ)

1. Đọc Collector W03, `bronze_contract.py`, `bronze_to_silver_adapter.py`, `src/pipeline/validator_poc.py`, Silver/Gold SQL, canonical W05 contract và Cyber required-fields/traceability.
2. Đối chiếu mỗi field DET-001/003/010 với raw XML, Bronze, adapter, Silver và Gold; đánh dấu observed/derived/missing.
3. Ghi baseline commit, version, owner, câu hỏi Q1–Q8 và tác động. Rà #29 để tái sử dụng deliverables thay vì viết lại W05.
4. Khi thực thi, chạy bộ test baseline thích hợp từ main và lưu lệnh/output; nếu thiếu dependency hoặc VM thì ghi rõ chưa chạy và nguyên nhân.

**Đầu ra:** `docs/research/software/w6/01-baseline-and-contract-gap-matrix.md`.

**Nghiệm thu:** mỗi thiếu hụt có owner đề xuất, ảnh hưởng và quyết định cần review; không coi field có ở adapter là đã persist tại Silver.

### Bước 2 — Thiết kế module và phương án đọc Silver (4–5 giờ)

Module đề xuất: `SilverReader` → `RuleRegistry/Loader` → `EventMatcher` → `Correlator` → `DetectionEvaluator` → `DetectionResultPublisher` → `AlertBuilder` interface.

- Mỗi module có input/output, lifecycle, quyền, dependency, error states và owner. Software thiết kế khả năng triển khai; Cyber sở hữu logic rule; Data sở hữu schema/storage.
- Hướng ưu tiên: modular monolith, cùng process quản lý store hoặc snapshot export bởi single writer. Nếu detector ở process riêng, chỉ đọc snapshot đã công bố; không giả định mở read-only file DuckDB đang có process khác ghi sẽ luôn hoạt động.
- Snapshot phải có snapshot ID, schema/mapping version, batch/run ID, thời điểm cắt dữ liệu, phạm vi event-time, trạng thái completeness, checksum và quy tắc publish/cleanup. Reader không được thấy snapshot dở dang.
- Đặc tả `read_batch(snapshot_ref, cursor, filters)` ở mức interface, bounded batch, retry, cursor ổn định và phản hồi snapshot unavailable/schema incompatible.
- Vẽ component diagram, sequence đọc–evaluate–publish, luồng lỗi và restart. Dùng Mermaid trong tài liệu repository.

**Đầu ra:** `docs/architecture/w6/detection-module-architecture-v1.md`.

**Nghiệm thu:** đường ghi DuckDB duy nhất được chỉ rõ; mọi đường đọc có consistency/lifecycle/error policy.

### Bước 3 — Rule/API contracts và config lifecycle (5–6 giờ)

- Rule contract: schema version, namespaced `DACN-DET-*` + legacy ID, rule version, required fields theo loại event, operators được hỗ trợ, correlation keys/window, MITRE techniques, evidence requirements, severity rationale, response policy.
- DetectionResult contract: evaluation ID, rule/version, host/subject, event window, contributing IDs/raw refs, matched/missing fields, coverage, outcome, reasons và phiên bản cấu hình/snapshot.
- Giữ bốn outcome: `MATCH`, `NO_MATCH`, `INSUFFICIENT_TELEMETRY`, `PENDING_LATE_EVENTS`. Lỗi thực thi phải có error outcome/envelope riêng, không chuyển thành `NO_MATCH`.
- Đặc tả publisher/AlertBuilder: phân biệt đánh giá với tạo cảnh báo, acknowledgment, retry, replay và failure log. Phương án state/outbox bền vững là thiết kế cần Data review.
- Viết schema và ví dụ JSON cho đủ bốn outcome, lỗi, raw thiếu/hết retention; đối chiếu Gold DDL bằng migration/gap proposal.
- Loader chỉ hỗ trợ rule khai báo; schema/version validation, operator allowlist, không `eval` tùy ý. Cấu hình mới validate toàn bộ trước activation; snapshot rule/config mỗi run, last-known-good, rollback, audit và quyền sửa.
- Cấu trúc Python là đề xuất: `src/detection/{reader,registry,matcher,correlator,evaluator,publisher}.py`, `src/detection/rules/`, `tests/detection/`; không tạo file module rỗng để nhận đã triển khai.

**Đầu ra:** `docs/architecture/w6/contracts/` (README, JSON schemas, examples) và `docs/research/software/w6/02-rule-loading-and-config-design.md`.

**Nghiệm thu:** ví dụ khớp schema; version không hỗ trợ bị từ chối rõ; có mapping từng DetectionResult field sang Gold hoặc gap được ghi nhận.

### Bước 4 — Correlation, replay và review W06 (5–6 giờ)

- Clock chính: System.TimeCreated; giữ EventData.UtcTime và ingest-time riêng. Định nghĩa watermark, allowed lateness, expiration và policy event đến sau cửa sổ đã đóng.
- Process join theo host + GUID + lifetime, thiếu ancestor phải partial. File chain theo host + normalized path + event-time; lưu actor GUID riêng từng bước, không buộc creator/executor/deleter cùng GUID.
- Đề xuất ID đánh giá/dedup key từ rule/version + host/subject + window + evidence identity; tách khóa evaluation khỏi alert grouping. Chốt re-evaluation/update policy khi late event bổ sung evidence.
- Replay cùng input/config không nhân đôi alert; crash giữa publish và checkpoint có recovery spec. Window đóng mà thiếu evidence phải chuyển sang trạng thái thiếu dữ liệu, không pending vô hạn hoặc full MATCH.
- Review với Data/Cyber: contract, missing evidence, timestamp, queries và quyền. Lưu nhận xét/điểm còn mở, không tự ghi người khác đã chấp thuận.

**Đầu ra:** `docs/research/software/w6/03-correlation-replay-and-integration-feasibility.md`, `04-test-plan-and-review-record.md`.

**Nghiệm thu:** có expected behavior cho out-of-order/late/missing/replay/cross-host và dedup; interface W06 đủ ổn định để W07 tham chiếu.

## 5. Kế hoạch W07 — Static / Signature / Whitelist

### Bước 5 — Static Extractor và Windows file access (4–5 giờ)

- Phân biệt Sysmon file event với bytes tại thời điểm phân tích; không nhận hash đọc hiện tại là hash lịch sử của event.
- Input: validated local file reference, source event refs, requested features, byte/time budget và analysis version. Mặc định chỉ đọc file lab/local được phép; không chạy file để lấy metadata.
- Output: SHA-256, size, byte entropy, optional PE metadata/signature status; từng feature có status, nguồn và thời điểm. Phân biệt entropy bytes với entropy chuỗi command line ở W05.
- Đặc tả missing/deleted/locked/access denied/too large/timeout/not PE/unsupported signature provider. Không dùng `unsigned` thay cho trạng thái chưa kiểm tra được chữ ký.
- Thiết kế TOCTOU: ưu tiên đọc qua cùng handle, lưu identity/metadata trước–sau; phát hiện thay đổi thì invalid/retry có giới hạn. Ghi giới hạn residual race, symlink/reparse point và cache invalidation.
- Đánh giá dependency hash chuẩn Python, PE parser/signature provider tùy chọn theo khả năng VM; ghi version/license/khả năng cài đặt và phần chưa thử.

**Đầu ra:** `docs/architecture/w7/static-feature-extractor-design-v1.md`, `docs/research/software/w7/01-windows-file-access-and-safety.md`.

**Nghiệm thu:** mọi feature phân biệt success/unavailable/error; có ví dụ file bị đổi/xóa và không tự thực thi file.

### Bước 6 — IOC/Whitelist/Signature và Candidate Review (5–6 giờ)

- Thiết kế `HashIOCMatcher`, `LocalWhitelistStore`, `SignaturePatternStore`, `CandidateReview` interface và owner ghi từng store.
- Bản ghi store có ID/version, nguồn, loại indicator, thời điểm tạo/cập nhật/hết hạn, reviewer/reason/audit. Cache theo file identity/hash và version của policy/store; không cache chỉ theo path.
- Đặc tả update package validation, schema compatibility, checksum/trust mechanism, atomic activation, expiry, last-known-good và rollback. Không tự tải feed.
- Lập bảng quyết định: IOC hit + allowlist hit, allowlist hết hạn, path wildcard rộng, trusted signer nhưng behavioral evidence đáng ngờ, file protected, metadata thiếu. Không xóa evidence do whitelist; lưu suppression/conflict và policy version.
- Candidate workflow đề xuất theo kế hoạch PR #36: NEW → TRIAGED → ALLOWLISTED / SUSPICIOUS / REJECTED; quy định quyền chuyển trạng thái, lý do bắt buộc và concurrency revision check. `SUSPICIOUS` không tương đương đã xác nhận malicious.
- Candidate Review API là interface nội bộ trước; mô tả request/result/errors, chưa cần dựng REST service.

**Đầu ra:** `docs/architecture/w7/static-whitelist-signature-and-review-design-v1.md`, `docs/architecture/w7/contracts/` (schemas/examples), `docs/research/software/w7/02-policy-versioning-and-review-flow.md`.

**Nghiệm thu:** có ví dụ static result, whitelist verdict, signature hit và candidate transition; Cyber review precedence, Data review schema, Software review quyền/lifecycle.

### Bước 7 — Tích hợp W06/W07 và bàn giao W08/W09 (3–4 giờ)

- Sequence: event/file reference → static request → extractor → IOC/allowlist evaluation → DetectionResult enrichment → AlertBuilder/policy → audit/candidate review.
- Kết quả static là evidence bổ sung; không tự terminate/quarantine. Whitelist không được âm thầm làm mất behavioral result.
- Đặc tả reference từ result về source events, file observation và analysis version; trạng thái partial/raw expired phải hiển thị được.
- W08 nhận contract rule/static evidence + explanation/version/completeness, không nhận điểm confidence tùy ý. W09 nhận timeline/process/file refs, candidate history và audit.

**Đầu ra:** `docs/research/software/w7/03-integration-handoff-and-review-record.md`, kèm component/sequence diagrams hoặc liên kết tới diagram W06/W07.

**Nghiệm thu:** một ví dụ xuyên suốt đủ truy vết từ Silver tới result/alert/raw; phân biệt ví dụ mô phỏng với kết quả chạy thật.

## 6. Ma trận kiểm chứng tối thiểu

Các ca dưới đây bắt buộc được đặc tả expected result; chỉ ghi PASS nếu có implementation được chạy và log tương ứng. Rule conditions phải do Cyber review trước khi dùng làm ground truth.

| Nhóm | Ca cần có | Kỳ vọng |
| --- | --- | --- |
| Rule loader | Hợp lệ; schema/version sai; rule/operator không hỗ trợ | Chấp nhận đúng version, reject lỗi có reason; config cũ vẫn dùng được |
| DET-001 | Synthetic match theo spec; PowerShell benign; thiếu command line/context | MATCH / NO_MATCH / INSUFFICIENT tương ứng |
| DET-003 | Run/RunOnce đúng spec; registry key không liên quan; thiếu Details | Không coi mọi Event13 là persistence |
| DET-010 | 11→1→26 đúng host/path/window; late 26; thiếu 26; khác host/path; actor khác nhau | Chỉ full MATCH khi đủ điều kiện; pending có hạn, partial/insufficient rõ |
| Correlation | Process kết thúc; thiếu parent; PID reuse; GUID trùng trên host khác; timestamp skew | Không join nhầm host/lifetime, không tạo ancestor giả |
| Replay | Lặp snapshot; input xáo trộn; crash sau publish trước checkpoint; version đổi | Không tạo duplicate ngoài policy; thay version/re-evaluation truy vết được |
| Evidence | Raw resolve được; raw hết hạn; lineage thiếu; identity collision sau log reset | Completeness/gap hiển thị, không ghi bằng chứng giả |
| Static | File lab hash biết trước, entropy case biết trước, non-PE, signature unavailable | Giá trị/feature status khớp oracle, không suy luận malware từ entropy |
| File access | Deleted/locked/denied/large/changed-during-read/reparse path | Lỗi có cấu trúc, bounded retry, không tự chạy file |
| Policy/review | IOC+allowlist conflict; expiry; rollback; reviewer thiếu quyền; revision cũ | Quyết định và audit đúng policy đã review |
| VM/store | Writer đang hoạt động; snapshot publish dở; reader restart | Không đọc partial snapshot; không mở thêm writer DuckDB |
| Safety | Chỉ có static hit; target protected | Alert/review only, không có hành động phá hủy tự động |

## 7. Lịch thực hiện và PoC tùy chọn

Tổng thiết kế ước lượng **30–37 giờ**, chia khoảng **8 phiên, mỗi phiên 4–5 giờ**; thời gian chờ reviewer/dependency không tính trong ước lượng. W06 là phiên 1–4; W07 là phiên 5–7; phiên 8 hoàn thiện review và bàn giao. Đây là phân bổ công sức đề xuất, không tự gắn ngày bắt đầu/kết thúc của tuần học.

1. Baseline/gap matrix, chuẩn bị câu hỏi Data/Cyber.
2. Module boundary, SilverReader/snapshot và diagrams.
3. JSON/schema examples, rule loader/config lifecycle.
4. Correlation/replay/dedup, test plan và PR W06.
5. Static Extractor, file access và feature-error contracts.
6. IOC/whitelist/signature stores, candidate lifecycle và schemas.
7. Tích hợp W06→W07→W08/W09, diagrams và test matrix.
8. Sửa theo review, kiểm tra links/schema/examples, bảng DoD và PR W07.

**PoC tùy chọn: thêm 6–10 giờ**, ưu tiên sau khi hai phần thiết kế đủ review: (1) loader + DET-001/003 bằng fixtures; (2) SHA-256/size/entropy và allowlist trên file vô hại; (3) DET-010 nếu correlation/evidence contract đã chốt. Có thể bỏ toàn bộ PoC mà vẫn hoàn thành phần thiết kế theo issue, nhưng phải ghi rõ Tested/Future và được reviewer nghiệm thu đúng phạm vi.

Nếu Q1–Q7 chưa chốt: tiếp tục module diagrams, draft contracts và negative test specifications; ghi assumption/dependency thay vì xem là approved. Không cần chờ production ingestion để viết thiết kế, nhưng chưa thể nhận nghiệm thu integration thực tế.

## 8. Điều kiện đóng issue và bằng chứng bàn giao

- [ ] W06 đủ module input/output, errors, quyền, ownership, diagrams và rule/config lifecycle.
- [ ] Có phương án single-writer/read-only snapshot; lifecycle/consistency/recovery được mô tả.
- [ ] W06 có detection/alert mapping, correlation/lateness/replay/dedup và evidence completeness.
- [ ] W07 đủ extractor, IOC/hash, whitelist/signature, candidate review, policy/expiry/rollback và Windows safety.
- [ ] Có schemas/examples hoặc gap/migration proposals có Data/Cyber review; không dùng default giả để lấp required fields.
- [ ] Có test matrix positive/negative/missing/error; nếu chạy PoC thì đính kèm lệnh, version, input/hash, expected/observed, output và giới hạn.
- [ ] Mỗi deliverable ghi Designed / Tested / Future; không coi code đọc được là test đã PASS hoặc spec là runtime.
- [ ] Data và Cyber xác nhận review qua PR/comment có link; tồn đọng có owner và ảnh hưởng nghiệm thu rõ.
- [ ] PR/commit và danh sách file được liên kết trong #40 khi thực hiện bước bàn giao; chỉ đóng khi DoD đạt.
- [ ] #29/#26 được cập nhật theo bằng chứng/review riêng, không tự đóng theo #40.

Trong lần lập kế hoạch này chỉ kiểm tra read-only GitHub/mã nguồn và tạo tài liệu kế hoạch; **chưa chạy tests, chưa sửa runtime, chưa đăng comment hay thay đổi trạng thái issue/PR**.

## 9. Nguồn đã đối chiếu

- [Issue #40 — yêu cầu và DoD chính](https://github.com/Kientran18/DACN/issues/40).
- [Issue #26](https://github.com/Kientran18/DACN/issues/26), [#29](https://github.com/Kientran18/DACN/issues/29), [PR #30](https://github.com/Kientran18/DACN/pull/30), [PR #34](https://github.com/Kientran18/DACN/pull/34).
- [PR #36 — kế hoạch W06–W12 còn chờ merge](https://github.com/Kientran18/DACN/pull/36); đã đọc bản plan ở head commit `f4734d98485b7d8d05a396f24b1ed709d4c394dc`.
- [Architecture v2](https://github.com/Kientran18/DACN/blob/main/docs/architecture/local-edr-reference-architecture-v2.md).
- [Canonical Bronze contract](https://github.com/Kientran18/DACN/blob/main/docs/architecture/w5/contracts/README.md).
- [Adapter](https://github.com/Kientran18/DACN/blob/main/poc/sysmon-collector/bronze_to_silver_adapter.py), [validator](https://github.com/Kientran18/DACN/blob/main/src/pipeline/validator_poc.py), [Silver/Gold SQL](https://github.com/Kientran18/DACN/blob/main/src/pipeline/sql/silver_gold_schema_and_views_v1_1.sql).
- [Cyber required fields và correlation requirements](https://github.com/Kientran18/DACN/blob/main/docs/research/cyber/w5/01-detection-required-fields-and-mitre-to-data.md).
