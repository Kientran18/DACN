# EDR — Task Backlog (nguồn sự thật cho Claude Code)

> **Trạng thái tài liệu:** PROPOSAL, chờ người dùng phê duyệt (2026-11-08). Chưa task nào được bắt đầu.
> Phối hợp với: [EDR_MASTER_PLAN.md](EDR_MASTER_PLAN.md) (phase, critical path), [EDR_TARGET_ARCHITECTURE.md](EDR_TARGET_ARCHITECTURE.md) (kiến trúc, đường dẫn file), [EDR_PROGRESS.md](EDR_PROGRESS.md) (tiến độ), [EDR_ACCEPTANCE_MATRIX.md](EDR_ACCEPTANCE_MATRIX.md).

## Cách đọc

- **Trạng thái:** `TODO` · `IN_PROGRESS` · `BLOCKED` · `REVIEW` · `DONE`. Chỉ đổi sang `DONE` khi có bằng chứng ghi trong `EDR_PROGRESS.md`.
- **Ưu tiên:** `P0` MVP bắt buộc · `P1` quan trọng · `P2` nâng cao.
- **Effort tương đối:** `S` ≈ nửa ngày · `M` ≈ 1–2 ngày · `L` ≈ 3–5 ngày · `XL` > 1 tuần. Đây là ước lượng thô để so sánh, chưa được kiểm chứng; ưu tiên phụ thuộc kỹ thuật hơn mốc thời gian.
- **Owner:** `SW` Software · `DA` Data · `CY` Cybersecurity (vai trò chủ trì theo `docs/research/*`; chéo nhóm cần review của hai nhóm còn lại).
- **Môi trường:** `C` Claude làm được hoàn toàn trên môi trường cloud/Linux (kèm fake nguồn Windows) · `W` cần Windows 10 VM thật, **người dùng chạy** và gửi kết quả · `U` cần người dùng quyết định/thao tác.
- **Quy ước chung cho mọi task:** (1) đọc `CLAUDE.md`, đọc ADR/contract liên quan; (2) viết test trước (`test-driven-development`); (3) không đổi data contract, UUIDv5, schema Bronze, raw preservation khi chưa có phê duyệt; (4) chạy `python -m pytest -q poc/sysmon-collector` và `python -m pytest -q tests/` (cộng test mới) và ghi kết quả; (5) dùng `verification-before-completion` trước khi báo xong; (6) không commit/push/PR/merge khi chưa được yêu cầu.
- Task liên kết GitHub Issue ghi ở cột *Issue*. Task chưa có issue được đề xuất ở mục "Thứ tự Issues" trong `EDR_MASTER_PLAN.md`; không tạo issue khi chưa được phép.

---

## PH1 — Stabilization & Technical Debt

### PH1-T01 · Ghi baseline kiểm thử `[P0 · S · SW · C · DONE]`
- **Mô tả:** chạy lại toàn bộ test, ghi kết quả (lệnh, thời điểm, pass/fail) làm baseline. **Input:** repo hiện tại. **Output:** mục "Baseline" trong `EDR_PROGRESS.md`. **Phụ thuộc:** không. **Issue:** —.
- **Bước:** chạy hai lệnh pytest; ghi 2 lỗi đã biết; kiểm tra `git status`. **Skill:** `verification-before-completion`.
- **DoD:** baseline có ngày giờ và kết quả khớp đầu ra thực tế.

### PH1-T02 · Sửa mã lỗi `C-002` ở đường parse `[P0 · S · SW · C · REVIEW]`
- **Mô tả:** `_parse_event_element` báo `Event XML is missing EventID or TimeCreated` không kèm mã; test `test_collector_errors_use_reason_codes` kỳ vọng `C-002` (bảng mã lỗi trong `docs/research/software/w5/01-collector-to-bronze-interface-contract-v1.md`). **Files:** `poc/sysmon-collector/sysmon_collector_poc.py`, `poc/sysmon-collector/test_bronze_contract.py`. **Phụ thuộc:** PH1-T01.
- **Bước:** `systematic-debugging` xác nhận nguyên nhân; chạy test fail; sửa thông báo thành tiền tố `C-002` (không đổi logic); kiểm tra các nơi khác bắt thông điệp cũ (Grep).
- **Test:** `python -m pytest -q poc/sysmon-collector/test_bronze_contract.py::test_collector_errors_use_reason_codes` rồi toàn bộ suite.
- **DoD:** test pass, không test khác hồi quy. Chỉ đổi chuỗi thông báo lỗi; không đổi schema/contract.

### PH1-T03 · Điều tra và sửa `test_06` (entropy) `[P0 · S · DA · C · TODO]`
- **Mô tả:** test kỳ vọng entropy > 5.0, giá trị thực 4.7322. **Files:** `tests/test_validator_poc_w5.py`, `src/pipeline/validator_poc.py` (hàm `calculate_shannon_entropy`). **Phụ thuộc:** PH1-T01.
- **Bước:** xác định nguyên nhân gốc (công thức sai hay kỳ vọng test không khả thi cho chuỗi ngắn); tính tay entropy; chọn sửa fixture hoặc ngưỡng; ghi lý do. **Cần Data review.**
- **DoD:** test phản ánh hành vi đúng của entropy, có giải thích; không giảm ngưỡng chỉ để pass mà không có lập luận.

### PH1-T04 · Quyết định chuẩn hóa hostname giữa Bronze và Silver `[P0 · M · DA/SW · U · TODO]`
- **Mô tả:** Silver ghi `hostname.upper()` nhưng `event_id` tính trên hostname gốc → tính lại từ cột Silver cho UUID khác (đã tái hiện). **Output:** đề xuất ADR (không tự chốt) với 2–3 phương án (giữ nguyên hoa/thường; thêm cột `hostname_norm`; chuẩn hóa ngay từ Bronze). **Files:** `docs/decisions/` (đề xuất), `src/pipeline/validator_poc.py`. **Phụ thuộc:** PH1-T01.
- **DoD:** quyết định có phê duyệt Data + Software; test hồi quy tái dựng `event_id` từ cột Silver.

### PH1-T05 · Quyết định độ chính xác `timestamp` ở Silver `[P1 · S · DA · U · TODO]`
- **Mô tả:** Silver cắt 100 ns xuống µs. **Output:** quyết định (giữ chuỗi gốc `time_created` thêm một cột / chấp nhận cắt). **DoD:** ghi quyết định; nếu thêm cột thì đi qua DDL v1.2 (PH6-T01).

### PH1-T06 · Xử lý Event 4/16 (Sysmon state/config) `[P1 · M · DA · C · TODO]`
- **Mô tả:** hiện vào DLQ với `ERR_UNSUPPORTED_EVENT_ID`, gây nhiễu chỉ số quarantine. **Output:** quyết định + cài đặt: nhánh "collector health events" riêng hoặc đếm/bỏ qua có ghi nhận. **Files:** `src/pipeline/validator_poc.py`, test mới. **Phụ thuộc:** PH1-T01; hợp đồng event-specific nullability (W5-CY-03).
- **DoD:** Event 4/16 không còn làm tăng quarantine ratio; không gán `process_guid` giả.

### PH1-T07 · Bổ sung fixture Event 14, 15 (synthetic có nhãn) `[P1 · M · SW · C · TODO]`
- **Mô tả:** chưa có mẫu cho 14/15 nên chưa có bằng chứng validator. **Files:** `poc/sysmon-collector/configs/synthetic_events.xml` hoặc fixture mới trong `tests/fixtures/`, test mới. **DoD:** test chạy qua adapter+validator, ghi rõ synthetic; không bịa field ngoài tài liệu Sysmon.

### PH1-T08 · Quyết định cách chia sẻ code giữa `poc/` và `src/` `[P0 · M · SW · U · TODO]`
- **Mô tả:** các file Python import bằng tên module trần (`CLAUDE.md` mục 5). Phương án (a) shim đường dẫn + `conftest.py`/`pytest.ini` với `pythonpath`; (b) di chuyển thành package (phá liên kết tài liệu tới `poc/sysmon-collector/bronze-event.schema.json`). **Output:** ADR đề xuất + cài đặt phương án đã duyệt (khuyến nghị (a) cho MVP). **Files:** `conftest.py` (mới, gốc repo) hoặc `pytest.ini`. **DoD:** `python -m pytest` chạy từ gốc, import module mới `src/<module>/` được; không đổi vị trí schema.

### PH1-T09 · Module cấu hình và logging dùng chung `[P0 · M · SW · C · TODO]`
- **Mô tả:** chưa có logging/config trong code hiện tại. **Output:** `src/common/config.py` (tải `edr.yaml`/biến môi trường `EDR_HOME`, giá trị mặc định, kiểm tra hợp lệ), `src/common/log.py` (JSONL: `ts, level, component, run_id, event, reason_code`). **Phụ thuộc:** PH1-T08; quyết định D-05 (YAML). **Test:** `tests/common/`. **DoD:** đường dẫn dữ liệu cấu hình được; thiếu/không hợp lệ báo lỗi rõ; log không chứa command line thô.

### PH1-T10 · Thống nhất tên event type collector ↔ validator (Q-X3) `[P1 · M · DA/CY/SW · U · TODO]`
- **Mô tả:** `REGISTRY_RENAME_KEY`/`FILE_STREAM_CREATE`/`NETWORK_ACCEPT` (collector) khác `REGISTRY_RENAME`/`FILE_STREAM_HASH` (validator). **Output:** bảng ánh xạ thống nhất được ba nhóm duyệt; test đối chiếu hai bảng. **DoD:** một nguồn sự thật; detection dùng đúng tên.

### PH1-T11 · Hạ tầng test: marker và cấu hình `[P0 · S · SW · C · TODO]`
- **Mô tả:** thêm marker `windows` (bỏ qua trên Linux), `integration`; script chạy toàn bộ suite một lệnh. **Files:** `pytest.ini`/`conftest.py`. **Phụ thuộc:** PH1-T08. **DoD:** `python -m pytest -q` chạy toàn bộ trên Linux, test `windows` được skip kèm lý do.

### PH1-T12 · Tạo fixture đã khử định danh `[P1 · M · CY/SW · C · TODO]`
- **Mô tả:** mẫu `references/samples/` chưa khử định danh (`sanitized:false`). **Output:** bộ fixture đã thay tên máy/người dùng/SID bằng giá trị giả nhất quán (giữ nguyên cấu trúc, `ProcessGuid` liên kết, mối quan hệ cha-con) dùng cho test công khai và demo; script khử định danh có kiểm tra không còn chuỗi định danh gốc. Không ghi đè mẫu gốc. **DoD:** test dùng fixture mới cho kết quả tương đương; báo cáo không in giá trị gốc.

---

## PH2 — Windows Endpoint Agent

### PH2-T01 · Giao diện `EventSource` và nguồn giả `[P0 · S · SW · C · TODO]`
- **Mô tả:** Protocol `EventSource` (`iter_events(from_bookmark)` → XML + bookmark); `FileEventSource` (XML export) và `FakeEventSource` (kịch bản có điều khiển, gồm lỗi và dừng giữa chừng). **Files:** `src/agent/sources/base.py`, `file_source.py`, `fake_source.py`; test `tests/agent/`. **Phụ thuộc:** PH1-T08/T11. **DoD:** agent sau này chạy hoàn toàn trên Linux với nguồn giả.

### PH2-T02 · Bronze segment writer `[P0 · L · SW · C · TODO]`
- **Mô tả:** ghi `.jsonl.part` (UTF-8, LF, một sự kiện một dòng), `flush`+`fsync`, xoay theo ngưỡng (số bản ghi/kích thước/thời gian cấu hình), seal bằng `os.replace` sang `.jsonl` + `.manifest.json` (`sha256`, `record_count`, `first/last record_id`, `schema_version`, `collector_version`). Dùng `bronze_contract.build_bronze_record` nguyên bản. **Files:** `src/agent/bronze_writer.py`; test. **Tham chiếu:** `docs/research/software/w5/01`, `04`; kiến trúc v2 mục 5.2. **Phụ thuộc:** PH2-T01.
- **Test:** seal tạo manifest đúng hash; sửa 1 byte → verify phát hiện; không đọc `.part`; tên file hợp lệ trên Windows (đường dẫn ngắn). **DoD:** schema `bronze-event/1.0` không đổi; bản ghi giữ nguyên `raw_xml`/`event_data`.

### PH2-T03 · Checkpoint/bookmark store `[P0 · M · SW · C · TODO]`
- **Mô tả:** lưu bookmark sau khi segment/lô đã bền (thứ tự: ghi → fsync → mới cập nhật bookmark → `os.replace` có retry-backoff cho `PermissionError`). **Files:** `src/agent/checkpoint.py`. **Test:** chết giữa các bước (fake) → đọc lại không mất, có thể trùng. **DoD:** theo giao thức at-least-once của tài liệu W5-04.

### PH2-T04 · Phục hồi khi khởi động `[P0 · M · SW · C · TODO]`
- **Mô tả:** quét `.part` mồ côi, cắt dòng dở, seal hoặc quarantine; bookmark hỏng → bắt đầu từ bản ghi cũ nhất kèm sự kiện `COLLECTOR_INTERNAL` ghi khoảng hở. **Test:** bảng ma trận lỗi mục 3 của W5-04 (các dòng chạy được trên Linux). **DoD:** không mất bản ghi âm thầm; mỗi trường hợp có mã lý do.

### PH2-T05 · Spike: xác minh API `pywin32` trên VM `[P0 · S · SW · W · IN_PROGRESS]`
- **Mô tả:** kiểm tra thực tế `EvtSubscribe`, `EvtCreateBookmark`, `EvtUpdateBookmark`, `EvtRender`, hành vi `ERROR_EVT_QUERY_RESULT_STALE`. **Output:** ghi chú kết quả (phiên bản Windows/Python/pywin32, đầu ra thật). Người dùng chạy script kiểm tra do Claude viết (`scripts/windows/verify_windows_env.py`, test `tests/test_verify_windows_env.py`; không đổi cấu hình, không in nội dung sự kiện). Script đã viết và test trên Linux; **chờ người dùng chạy trên VM**. **Rủi ro:** tên hàm khác dự kiến. **DoD:** danh sách hàm xác nhận/không xác nhận.

### PH2-T06 · Nguồn Windows Event Log `[P0 · L · SW · C+W · TODO]`
- **Mô tả:** `EventLogSource` dùng `pywin32` (`EvtSubscribe` có bookmark hoặc `EvtNext` kéo theo lô, theo kết quả PH2-T05); phát XML thô. Lỗi quyền → `C-006`. Mọi gọi `win32evtlog` nằm sau lớp mỏng để test bằng đối tượng giả. **Files:** `src/agent/sources/eventlog.py`. **Phụ thuộc:** PH2-T01, PH2-T05. **Test:** Linux: lớp giả; Windows: PH2-T09. **DoD:** import không lỗi trên Linux; hành vi Windows ghi `UNKNOWN` tới khi PH2-T09 có bằng chứng.

### PH2-T07 · Vòng chạy agent, tín hiệu dừng, health `[P0 · M · SW · C · TODO]`
- **Mô tả:** `AgentRunner`: đọc lô → ghi Bronze → bookmark; backpressure (hàng đợi giới hạn); xử lý Ctrl+C/`stop` file; ghi `health.json` (heartbeat, `last_event_at`, `last_seal_at`, `queue_depth`, số lỗi theo mã). **Files:** `src/agent/runner.py`, `health.py`, `__main__.py`. **Test:** nguồn giả chạy 10.000 sự kiện, dừng giữa chừng, khởi động lại → không mất. **DoD:** CLI `python -m agent run --config edr.yaml`.

### PH2-T08 · Sysmon config cho các kịch bản MVP `[P0 · S · CY · U · TODO]`
- **Mô tả:** đối chiếu `poc/sysmon-collector/configs/sysmon-config.xml` với telemetry cần cho SC-01..SC-04 (Event 1, 3, 5, 11, 12/13, 22, 23/26, 29; hash SHA256/IMPHASH). Đề xuất thay đổi qua PR vào cấu hình trong repository (không sửa trực tiếp trên máy). **Người dùng** áp dụng trên VM. **DoD:** bảng "kịch bản → Event ID cần có → đã bật?".

### PH2-T09 · Kiểm chứng agent trên Windows VM `[P0 · L · SW · W · TODO]`
- **Mô tả:** người dùng chạy: cài Sysmon (config của repo), chạy agent live, tạo hoạt động vô hại (`run-poc-activities.ps1` sau khi đọc), so sánh Bronze với `wevtutil` export; kill agent giữa chừng và khởi động lại; kiểm tra quyền (có/không Administrator). **Skill:** `dacn-windows-integration-test`. **Output:** báo cáo có lệnh, phiên bản, đầu ra thật. **DoD:** mỗi ca PASS/FAIL/NOT RUN với bằng chứng; live mode chỉ được nâng lên `VERIFIED` ở đây.

### PH2-T10 · Hướng dẫn cài đặt và chạy Agent `[P0 · M · SW · C · TODO]`
- **Mô tả:** `docs/implementation/` hoặc `docs/guides/` (vị trí do người dùng chọn): tiền điều kiện, các bước, cách dừng/gỡ, quyền. **DoD:** người dùng làm theo được trên VM sạch (xác nhận ở PH2-T09).

### PH2-T11 · Dịch vụ Windows (tùy chọn) `[P2 · L · SW · W · TODO]`
- **Mô tả:** chỉ sau khi runner ổn định; quyết định giữa Task Scheduler / NSSM-like / `pywin32` service. Không tự cài; chỉ viết hướng dẫn. **DoD:** có quyết định ADR đề xuất và hướng dẫn gỡ.

---

## PH3 — Data Pipeline & Storage

### PH3-T01 · Segment reader có xác minh `[P0 · M · DA · C · TODO]`
- **Mô tả:** đọc segment đã seal, kiểm `sha256` và `record_count` theo manifest; sai lệch → quarantine segment (mã V-007), các segment khác tiếp tục. **Files:** `src/pipeline/segment_reader.py`. **Phụ thuộc:** PH2-T02. **DoD:** chỉ đọc segment sealed; test hỏng 1 byte.

### PH3-T02 · Silver store bền vững `[P0 · L · DA · C · TODO]`
- **Mô tả:** DuckDB file (`silver/endpoint_silver.duckdb`), áp DDL `silver_gold_schema_and_views_v1_1.sql` (đã xác minh chạy được), một writer; `INSERT ... ON CONFLICT DO NOTHING` theo `event_id`; bảng ledger `_ingest_ledger` (segment, trạng thái, số bản ghi, hash, `run_id`). Cột hàng Silver do validator sinh khớp DDL (đã xác minh trên mẫu). **Files:** `src/pipeline/silver_store.py`. **Phụ thuộc:** PH1-T04 (hostname), PH3-T01. **Test:** nạp hai lần → không trùng; chết giữa transaction → hoàn tác. **DoD:** replay idempotent có test.

### PH3-T03 · Persist Quarantine/DLQ `[P0 · M · DA · C · TODO]`
- **Mô tả:** ghi DLQ vào bảng `silver_quarantine_dlq` và `quarantine/*.jsonl` (giữ nguyên payload); mã lỗi và retry policy theo `validation_quality_lineage_and_governance_v1.md` mục 3.2. **Phụ thuộc:** PH3-T02. **DoD:** không bản ghi nào bị bỏ âm thầm; tổng đọc = valid + dedup + quarantine.

### PH3-T04 · Cột lineage về Bronze `[P0 · M · DA/SW · U · TODO]`
- **Mô tả:** thêm `bronze_segment_id`, `bronze_line_no`, `bronze_content_hash`, `mapper_version` vào Silver (đề xuất DDL v1.2, **cần phê duyệt**). Cho phép alert → Silver → Bronze → raw XML. **Phụ thuộc:** PH6-T01 (chung DDL v1.2). **DoD:** resolver trả được `raw_xml` từ một `event_id`.

### PH3-T05 · Lệnh replay/rebuild Silver từ Bronze `[P0 · M · DA · C · TODO]`
- **Mô tả:** `python -m pipeline replay --from-bronze` dựng lại Silver vào file mới (không sửa Bronze). **DoD:** kết quả replay trùng Silver gốc (so `event_id` và số hàng).

### PH3-T06 · Lớp truy vấn `[P0 · L · DA · C · TODO]`
- **Mô tả:** hàm truy vấn tham số hóa (không ghép chuỗi SQL): sự kiện theo thời gian/host/`process_guid`/hash/đường dẫn, cây tiến trình (`v_process_tree_lineage`), cửa sổ tương quan, phân trang. **Files:** `src/pipeline/query.py`. **Phụ thuộc:** PH3-T02. **DoD:** detection và API dùng chung; không JOIN theo PID (ADR 0002).

### PH3-T07 · Ingest worker `[P0 · M · DA/SW · C · TODO]`
- **Mô tả:** theo dõi thư mục Bronze, nạp segment mới theo thứ tự, ghi metrics (`segments_ingested`, `records_*`, `duplicates_ignored`, `lag_seconds`) vào `metrics.jsonl`, kích hoạt bước phát hiện sau mỗi batch. **Phụ thuộc:** PH3-T01..T03. **DoD:** chạy liên tục với agent giả; dừng sạch.

### PH3-T08 · Chỉ số chất lượng dữ liệu `[P1 · M · DA · C · TODO]`
- **Mô tả:** phát 6 chỉ số (completeness, validity, uniqueness, consistency, timeliness, quarantine ratio) từ dữ liệu thật của lần chạy; không đặt SLO "đạt" khi chưa đo (`dacn-data-pipeline-storage/references/data-quality-metrics.md`). **DoD:** bảng chỉ số kèm lệnh và dữ liệu nguồn.

### PH3-T09 · Retention (dry-run) `[P2 · M · DA · C · TODO]`
- **Mô tả:** chính sách theo tầng, `RAW_EXPIRED`, evidence hold; chạy dry-run, không xóa. **DoD:** báo cáo những gì sẽ bị dọn; ngưỡng do người dùng quyết định.

---

## PH4 — Detection Engine

### PH4-T01 · Schema rule và Rule Registry `[P0 · M · CY · C · TODO]`
- **Mô tả:** JSON Schema cho rule YAML (`rule_id` dạng `DACN-DET-xxx`, `legacy_id`, `rule_version`, `event_types`, `required_fields`, `conditions`, `correlation_keys`, `time_window`, `severity`, `mitre_technique_ids`, `status`, `response_policy: alert_only` mặc định); loader kiểm hợp lệ + version, từ chối rule sai. **Files:** `src/detection/schema.py`, `loader.py`, `rules/`. **Tham chiếu:** kiến trúc v2 mục 6.2; `docs/research/cyber/w5/01`. **Phụ thuộc:** PH1-T09; quyết định D-05 (YAML). **DoD:** rule hợp lệ nạp được, rule sai báo lỗi rõ.

### PH4-T02 · Hợp đồng `DetectionResult` `[P0 · S · CY/DA · U · TODO]`
- **Mô tả:** dataclass và JSON Schema: `outcome` ∈ {MATCH, NO_MATCH, INSUFFICIENT_TELEMETRY, PENDING_LATE_EVENTS}, `matched_fields`, `missing_fields`, `coverage_status`, `contributing_event_ids[]`, tham chiếu raw, `severity` + lý do. **Cần** Cyber + Data duyệt (liên quan #38, #39). **DoD:** schema được duyệt; ví dụ JSON dương/âm/thiếu dữ liệu.

### PH4-T03 · Bộ đánh giá (engine) `[P0 · L · CY/SW · C · TODO]`
- **Mô tả:** chạy rule trên Silver qua lớp truy vấn; đơn sự kiện (điều kiện trên cột Silver/`raw_data`), thiếu `required_fields` → `INSUFFICIENT_TELEMETRY`; thứ tự xử lý theo `record_id`/`timestamp`; watermark cho sự kiện muộn. **Files:** `src/detection/engine.py`, `evaluator.py`. **Phụ thuộc:** PH3-T06, PH4-T01, PH4-T02. **DoD:** replay không sinh kết quả trùng.

### PH4-T04 · Rule `DACN-DET-001` PowerShell đáng ngờ `[P0 · M · CY · C · TODO]`
- **Mô tả:** Event 1, `Image` PowerShell + `CommandLine` có dấu hiệu (ví dụ `-enc`/`-EncodedCommand`, `-ExecutionPolicy Bypass`, `DownloadString`); loại trừ ngữ cảnh lành tính nêu rõ (ví dụ parent tin cậy). Thiếu `CommandLine` → `INSUFFICIENT_TELEMETRY`. **Test:** dương (chuỗi mô phỏng vô hại), lành tính, thiếu dữ liệu; **mỗi rule ghi** mục đích, telemetry cần, điều kiện, false positive có thể, kỳ vọng. **MITRE:** chỉ gán T1059.001 khi có căn cứ (`dacn-detection-rules-mitre`). **DoD:** 3 nhóm fixture pass; nêu rõ chưa đo FP thật.

### PH4-T05 · Rule `DACN-DET-003` Registry Run/RunOnce `[P0 · M · CY · C · TODO]`
- **Mô tả:** Event 13 trên `...\CurrentVersion\Run(Once)`, chuẩn hóa HKU/HKCU (SID); phân biệt khóa khác. Chưa có mẫu Run thật trong `references/samples/` → cần fixture synthetic có nhãn và xác minh trên VM (PH5). **DoD:** test dương/âm/thiếu; ghi "chưa xác minh trên endpoint thật" cho tới PH5-T04.

### PH4-T06 · Rule tương quan `DACN-DET-010` drop→execute→delete `[P0 · L · CY/DA · C · TODO]`
- **Mô tả:** Event 11 (tạo file) → Event 1 (chạy `Image` đúng đường dẫn) → Event 26/23 (xóa) theo `(hostname, normalized_path)` trong cửa sổ cấu hình (`TBD` cho tới khi có dữ liệu có nhãn). Thiếu Event 26 → `PENDING_LATE_EVENTS`/partial, không `MATCH` đầy đủ. **Files:** `src/detection/correlator.py`. **Phụ thuộc:** PH4-T03. **DoD:** fixture đủ chuỗi / thiếu bước / trễ; chuẩn hóa đường dẫn (hoa/thường, `\Device\...`) có test.

### PH4-T07 · IOC/hash matcher và allowlist `[P0 · M · CY · C · TODO]`
- **Mô tả:** kho IOC (tệp có phiên bản, nguồn, hết hạn) và allowlist cục bộ; so khớp `Hashes` SHA-256 của Event 1/29; không tự tải feed. Allowlist ưu tiên rõ ràng, không wildcard rộng. **Files:** `src/detection/ioc.py`, `ioc/` (dữ liệu IOC của đội). **Phụ thuộc:** PH4-T03. **DoD:** khớp hash tệp thử nghiệm do đội tạo; hash hợp lệ trong allowlist không bị gắn cờ; hash không đủ chứng minh độc hại (ghi trong lý do).

### PH4-T08 · Khử trùng kết quả và replay-safe `[P0 · M · CY/DA · C · TODO]`
- **Mô tả:** khóa `rule_id + rule_version + subject + window`; chạy lại không tạo kết quả trùng; thay đổi `rule_version` tạo bản đánh giá mới có ghi nhận. **DoD:** test chạy 2 lần cho cùng kết quả.

### PH4-T09 · Harness kiểm thử rule `[P0 · M · CY · C · TODO]`
- **Mô tả:** chạy thư mục fixture có nhãn `expected_outcome` cho mọi rule; báo cáo ma trận expected↔observed. **Files:** `tests/detection/`. **Skill:** `dacn-detection-validation`. **DoD:** một lệnh chạy toàn bộ rule test.

### PH4-T10 · Giao diện ML detector `[P1 · M · DA · C · TODO]`
- **Mô tả:** `MLDetector` Protocol (`score(features) -> AnomalyResult`), `NullDetector` mặc định, hợp đồng `AnomalyResult` + `feature_schema_version`; engine gọi detector tùy chọn qua cấu hình, kết quả chỉ làm tăng rủi ro và **không kích hoạt response**. **Files:** `src/detection/ml/interface.py`. **DoD:** tắt ML = hành vi không đổi; test với detector giả.

### PH4-T11 · Rule bổ sung `[P1 · L · CY · C · TODO]`
- **Mô tả:** chọn theo telemetry thật: DET-002 (cmd/ancestry), DET-004 (schtasks candidate), DET-005/006 (chuỗi tải/mạng). Mỗi rule theo mẫu ở PH4-T04. Rule bị chặn do thiếu telemetry (DET-007, DET-008) ghi `blocked`. **DoD:** không thêm rule không có fixture.

---

## PH5 — Kiểm chứng phát hiện bằng kịch bản mô phỏng an toàn

> Mọi kịch bản chỉ chạy trên Windows 10 VM lab có snapshot sạch, do **người dùng** thực hiện. Chi tiết: [EDR_DEMO_PLAN.md](EDR_DEMO_PLAN.md).

### PH5-T01 · Danh mục kịch bản và kỳ vọng `[P0 · M · CY · C · TODO]`
- **Mô tả:** SC-01..SC-07 (PowerShell mã hóa vô hại, Run key vô hại, drop-execute-delete, hash IOC của tệp thử nghiệm, EICAR tùy chọn, kiểm soát lành tính, trường hợp thiếu telemetry), mỗi kịch bản có tiền điều kiện, telemetry kỳ vọng, `expected DetectionResult`, cleanup. **DoD:** người dùng duyệt từng kịch bản.

### PH5-T02 · Script mô phỏng an toàn `[P0 · L · CY/SW · C · TODO]`
- **Mô tả:** PowerShell có marker `DACN_LAB_<runid>`, chỉ ghi trong `%TEMP%\dacn_lab\` và `HKCU` khóa test, có tham số `-WhatIf`, cleanup đầy đủ, không tải mạng, không tắt công cụ bảo mật. **Vị trí:** thư mục người dùng chọn (đề xuất `scripts/lab/`). **Claude không chạy.** **DoD:** người dùng đọc, đồng ý, chạy `-WhatIf` trước.

### PH5-T03 · Bộ dữ liệu có nhãn và bộ so sánh `[P0 · M · CY/DA · C · TODO]`
- **Mô tả:** công cụ đối chiếu `run_id` marker → sự kiện thu được → `DetectionResult` thực tế vs kỳ vọng; xuất bảng PASS/FAIL. **Files:** `tests/e2e/compare_expected.py`. **DoD:** chạy được trên fixture lưu sẵn (Linux) và trên dữ liệu VM.

### PH5-T04 · Chạy kịch bản trên VM và ghi nhận `[P0 · L · CY · W · TODO]`
- **Mô tả:** người dùng chạy SC-01..SC-04, SC-06, SC-07 (SC-05 tùy chọn), lưu Bronze/Silver/kết quả; ghi rõ ai phát hiện (EDR / Windows Defender / không ai). **Phụ thuộc:** PH2-T09, PH4-T04..T07, PH5-T02. **DoD:** bảng observed-vs-expected có bằng chứng; phần chưa chạy là `NOT RUN`.

### PH5-T05 · Báo cáo phát hiện trên tập test `[P0 · M · CY · C · TODO]`
- **Mô tả:** tỷ lệ TP/FP/FN **chỉ trên tập kịch bản đã chạy**, nêu cỡ mẫu và giới hạn; không suy rộng. **DoD:** mọi số có nguồn chạy.

---

## PH6 — Alert & Incident Management

### PH6-T01 · Đề xuất DDL v1.2 (detection/alert/incident/audit/response) `[P0 · M · DA · U · TODO]`
- **Mô tả:** đối chiếu `gold_security_alerts` với hợp đồng: `process_guid NOT NULL` (không cho health alert/khóa registry không gắn process), `mitre_technique_id` đơn trị, thiếu `rule_version`/`coverage_status`/`missing_fields`/trạng thái; thêm `detection_results`, `alert_events`, `incidents`, `incident_notes`, `response_actions`, `audit_log`, cột lineage (PH3-T04). **Output:** `src/pipeline/sql/silver_gold_schema_and_views_v1_2_proposal.sql` + ghi chú migration. **Cần Data + Cyber + Software duyệt.** **DoD:** DDL chạy được trên DuckDB trong test; không sửa file v1.1.

### PH6-T02 · Bộ dựng alert `[P0 · M · CY · C · TODO]`
- **Mô tả:** `DetectionResult(MATCH)` → alert (severity + lý do, MITRE nếu có căn cứ, `contributing_event_ids`, tham chiếu Bronze). `INSUFFICIENT_TELEMETRY` tạo mục "coverage gap", không phải alert đe dọa. **Files:** `src/alerts/builder.py`. **Phụ thuộc:** PH4-T02, PH6-T01.

### PH6-T03 · Alert store, dedup, máy trạng thái `[P0 · L · CY/DA · C · TODO]`
- **Mô tả:** lưu alert; dedup `rule_id + host + subject + cửa sổ` có `suppression_reason`; trạng thái `NEW → TRIAGED → INVESTIGATING → (FALSE_POSITIVE|CONFIRMED|CLOSED)` với người/thời điểm/ghi chú; chuyển trạng thái sai bị từ chối. **Files:** `src/alerts/store.py`. **DoD:** replay không tạo alert trùng; test máy trạng thái.

### PH6-T04 · Evidence resolver (alert → raw) `[P0 · L · DA/CY · C · TODO]`
- **Mô tả:** từ `alert_id` ra danh sách sự kiện Silver, segment Bronze, dòng và `raw_xml` (đọc có xác minh hash); nếu Bronze hết hạn → `RAW_EXPIRED/PARTIAL`. **Files:** `src/alerts/evidence.py`. **Phụ thuộc:** PH3-T04. **DoD:** test TRC-01 hai chiều.

### PH6-T05 · Timeline và process tree `[P0 · M · CY · C · TODO]`
- **Mô tả:** timeline theo `System.TimeCreated`/`record_id` kèm skew; cây tiến trình theo `process_guid` (ghi `PARTIAL_ANCESTRY`). **Files:** `src/alerts/timeline.py`. **DoD:** kết quả khớp mẫu W03.

### PH6-T06 · Ghi chú incident và audit trail `[P1 · M · CY · C · TODO]`
- **Mô tả:** ghi chú, gán alert vào incident, audit append-only (actor, hành động, lý do). **DoD:** audit không sửa/xóa được qua API.

---

## PH7 — Response Engine (kiểm soát)

### PH7-T01 · Response policy và danh sách bảo vệ `[P0 · M · CY · C · TODO]`
- **Mô tả:** policy (`response-policy.yaml`): hành động cho phép, `mode: dry_run` mặc định, allowlist **bảo vệ** (tiến trình hệ thống, `explorer.exe`, `lsass.exe`, `csrss.exe`, thư mục `%SystemRoot%`, chính tiến trình EDR…), chỉ cho phép mục tiêu mang marker lab hoặc nằm trong thư mục lab được chỉ định. **Files:** `src/response/policy.py`, `config/response-policy.yaml`. **DoD:** mục tiêu thuộc danh sách bảo vệ luôn bị từ chối (test).

### PH7-T02 · Mô hình hành động và hàng đợi `[P0 · M · CY/SW · C · TODO]`
- **Mô tả:** `ResponseAction` (type, target identity, alert_id, requested_by, approval, mode), trạng thái `REQUESTED → APPROVED/REJECTED → EXECUTING → DONE/FAILED`. **Files:** `src/response/actions.py`. **Phụ thuộc:** PH6-T01.

### PH7-T03 · Executor lõi với backend dry-run và giả `[P0 · L · SW · C · TODO]`
- **Mô tả:** `Executor` gọi backend theo `mode`; `DryRunBackend` (ghi dự kiến, không đổi hệ thống), `FakeOSBackend` (mô phỏng tiến trình/tệp trong thư mục tạm test). Kiểm tra: policy, xác thực người duyệt, xác minh lại danh tính mục tiêu ngay trước khi thực thi (chống TOCTOU/tái sử dụng PID). **Files:** `src/response/executor.py`, `backends/`. **DoD:** thiếu approval, mục tiêu bảo vệ, PID tái sử dụng đều bị từ chối trong test.

### PH7-T04 · Backend Windows: kết thúc tiến trình thử nghiệm `[P0 · L · SW · C+W · TODO]`
- **Mô tả:** xác minh `(pid, creation time, image path, marker lab)` trước khi `TerminateProcess`; chỉ tiến trình do kịch bản mô phỏng tạo. Mã viết/kiểm thử logic trên Linux bằng lớp giả; thực thi thật chỉ khi người dùng bật `mode: execute` trên VM. **DoD:** mặc định dry-run; log chứng minh hành động.

### PH7-T05 · Backend: cách ly tệp thử nghiệm `[P0 · L · SW · C+W · TODO]`
- **Mô tả:** di chuyển tệp vào `quarantine\` (đổi tên, ghi SHA-256, đường dẫn gốc, ACL mô tả) và có `restore`; không xóa vĩnh viễn; chỉ trong thư mục lab. **DoD:** restore khớp hash; không thao tác ngoài thư mục lab.

### PH7-T06 · Audit hành động `[P0 · M · SW/CY · C · TODO]`
- **Mô tả:** ghi trước/sau mỗi hành động (actor, lý do, mục tiêu, kết quả, con trỏ rollback) vào `audit_log`; dùng chung PH6-T06. **DoD:** mỗi hành động thật có bản ghi đối chiếu được với log hệ điều hành do người dùng quan sát.

### PH7-T07 · Tiến trình `responder` `[P0 · M · SW · C · TODO]`
- **Mô tả:** tiến trình riêng (quyền tối thiểu), lấy hành động `APPROVED` từ API cục bộ bằng token, thực thi qua `Executor`, gửi kết quả. **Files:** `src/response/responder.py`. **Phụ thuộc:** PH8-T06. **DoD:** core không giữ quyền response.

### PH7-T08 · Auto-response có cổng (mặc định tắt) `[P1 · M · CY · C · TODO]`
- **Mô tả:** chỉ cho rule + mục tiêu được người dùng cho phép rõ ràng trong policy, chỉ khi `mode: execute` và bằng chứng đầy đủ (`coverage_status` đủ). **DoD:** cấu hình mặc định không tự thực thi; test.

### PH7-T09 · Block hash ở mức ứng dụng `[P1 · M · CY/DA · C · TODO]`
- **Mô tả:** thêm hash vào danh sách IOC cục bộ có nguồn "analyst-block"; không tuyên bố chặn thực thi ở mức hệ điều hành. **DoD:** hash được gắn cờ ở lần phát hiện sau; tài liệu nêu rõ là detection chứ không phải prevention.

### PH7-T10 · Kiểm chứng response trên VM `[P0 · L · CY · W · TODO]`
- **Mô tả:** người dùng bật `execute` chỉ cho tiến trình/tệp thử nghiệm của kịch bản; ghi kết quả, log, restore. Ghi rõ phân biệt detection / prevention / response sau phát hiện. **DoD:** bằng chứng cho mỗi hành động; allowlist bảo vệ được thử âm tính (yêu cầu dừng tiến trình hệ thống bị từ chối).

---

## PH8 — Backend API

### PH8-T01 · Khung ứng dụng API `[P0 · M · SW · C · TODO]`
- **Mô tả:** FastAPI + uvicorn (quyết định D-04), bind `127.0.0.1`, token Bearer cấu hình, logging, xử lý lỗi thống nhất (mã ổn định, không lộ stack/đường dẫn). **Files:** `src/api/app.py`, `auth.py`. **Phụ thuộc:** D-04, PH1-T09.

### PH8-T02 · `/health`, `/endpoint` `[P0 · S · SW · C · TODO]`
- **Mô tả:** trạng thái agent (heartbeat), pipeline (lag, DLQ), engine, phiên bản rule; thông tin endpoint đơn (hostname hiển thị theo quyết định PH1-T04).

### PH8-T03 · `/events` truy vấn `[P0 · M · SW/DA · C · TODO]`
- **Mô tả:** lọc thời gian/event type/`process_guid`/hash/path, phân trang có giới hạn, sắp xếp; tham số hóa. **Phụ thuộc:** PH3-T06.

### PH8-T04 · `/detections`, `/alerts` `[P0 · M · SW/CY · C · TODO]`
- **Mô tả:** danh sách/chi tiết, đổi trạng thái (kiểm tra máy trạng thái), ghi chú. **Phụ thuộc:** PH6-T03.

### PH8-T05 · `/alerts/{id}/evidence` `[P0 · M · SW/CY · C · TODO]`
- **Mô tả:** trả sự kiện nguồn, timeline, cây tiến trình; `raw_xml` chỉ cho vai trò được phép và có audit. **Phụ thuộc:** PH6-T04/T05.

### PH8-T06 · `/response/actions` `[P0 · M · SW/CY · C · TODO]`
- **Mô tả:** tạo yêu cầu, duyệt/từ chối (vai trò approver), xem kết quả; responder dùng cùng API. **Phụ thuộc:** PH7-T02.

### PH8-T07 · `/rules` (đọc, bật/tắt tối thiểu) `[P1 · M · CY/SW · C · TODO]`
- **Mô tả:** liệt kê rule + phiên bản + trạng thái; thay đổi rule trong production không nằm trong MVP (rule đổi qua tệp + kiểm tra). 

### PH8-T08 · Kiểm thử API `[P0 · M · SW · C · TODO]`
- **Mô tả:** test xác thực, phân quyền, validate input (quá lớn/sai kiểu), lỗi, phân trang; dùng DuckDB fixture. **Files:** `tests/api/`. **DoD:** mọi endpoint có test dương và âm.

### PH8-T09 · Xuất đặc tả OpenAPI `[P1 · S · SW · C · TODO]`
- **Mô tả:** sinh `openapi.json` và tài liệu endpoint.

---

## PH9 — EDR Dashboard

### PH9-T01 · Khung giao diện tĩnh `[P0 · M · SW · C · TODO]`
- **Mô tả:** HTML/JS thuần phục vụ bởi API (không Node, không CDN, chạy offline); client API, token, trạng thái loading/rỗng/lỗi, múi giờ UTC rõ ràng. **Files:** `src/dashboard/static/`. **Phụ thuộc:** PH8-T01.

### PH9-T02 · Overview `[P0 · M · SW · C · TODO]`
- **Mô tả:** health (agent/pipeline/engine), số alert theo mức, khoảng trống telemetry, alert mới nhất. Dữ liệu từ API; không số cứng.

### PH9-T03 · Telemetry/Event Explorer `[P0 · M · SW · C · TODO]`
- **Mô tả:** bảng, lọc, tìm, phân trang, xem chi tiết (`raw_data`).

### PH9-T04 · Detections và Alerts/Incidents `[P0 · M · SW/CY · C · TODO]`
- **Mô tả:** danh sách + chi tiết, đổi trạng thái, ghi chú; hiển thị `outcome`, `missing_fields`.

### PH9-T05 · Investigation `[P0 · L · SW/CY · C · TODO]`
- **Mô tả:** timeline, cây tiến trình, bằng chứng nguồn, tách nhãn *Quan sát / Suy luận / Thiếu dữ liệu*; mở raw XML có kiểm soát. **Phụ thuộc:** PH8-T05.

### PH9-T06 · Response Actions `[P0 · M · SW/CY · C · TODO]`
- **Mô tả:** yêu cầu, duyệt/từ chối, xem kết quả và audit; hiển thị chế độ (`dry_run`/`execute`) nổi bật; xác nhận hiển thị mục tiêu đầy đủ.

### PH9-T07 · Rules/Settings (đọc) `[P1 · M · CY/SW · C · TODO]`
- **Mô tả:** rule, phiên bản, trạng thái; cấu hình đang áp dụng (ẩn bí mật).

### PH9-T08 · Kiểm thử giao diện `[P1 · M · SW · C · TODO]`
- **Mô tả:** Playwright (có sẵn trong môi trường) chạy với API dùng DuckDB fixture; kiểm tra các trạng thái, nhãn "DỮ LIỆU MẪU" khi dùng fixture. **Files:** `tests/dashboard/`. **Lưu ý:** không gọi đây là tích hợp thật.

---

## PH10 — Tích hợp end-to-end

### PH10-T01 · Launcher `edr_ctl` `[P0 · M · SW · C · TODO]`
- **Mô tả:** `python -m edr_ctl start|stop|status|logs` khởi động/dừng agent, core (ingest+detect+API), responder; PID file, dừng sạch, trạng thái rõ. Không cài service. **Files:** `src/edr_ctl.py`. **DoD:** start/stop lặp lại không để tiến trình mồ côi (test với tiến trình giả).

### PH10-T02 · Tệp cấu hình mẫu `[P0 · S · SW · C · TODO]`
- **Mô tả:** `config/edr.example.yaml` (đường dẫn, cổng, token, ngưỡng segment, policy). Không chứa bí mật thật.

### PH10-T03 · Test tích hợp trên Linux bằng nguồn giả `[P0 · L · SW/DA/CY · C · TODO]`
- **Mô tả:** `FakeEventSource` (kịch bản đầy đủ) → agent → Bronze → core → Silver → rule → alert → API → evidence; kiểm tra tại từng giao diện. **Files:** `tests/e2e/test_pipeline_fake_source.py`. **Skill:** `dacn-end-to-end-acceptance`. **Lưu ý khi báo cáo:** đây là tích hợp với nguồn giả, **không** thay cho kiểm chứng Windows.

### PH10-T04 · Chạy tích hợp trên Windows VM `[P0 · L · SW · W · TODO]`
- **Mô tả:** người dùng chạy `edr_ctl start`, kịch bản SC-01, kiểm tra Dashboard; ghi kết quả. **Phụ thuộc:** PH2-T09, PH10-T01, PH9.

### PH10-T05 · Diễn tập lỗi `[P1 · L · SW/DA · W · TODO]`
- **Mô tả:** kill agent/core giữa chừng, đầy đĩa giả lập nhỏ, segment hỏng, restart; kỳ vọng vs quan sát (OPS-01).

### PH10-T06 · Hướng dẫn cài đặt toàn hệ thống `[P0 · M · SW · C · TODO]`
- **Mô tả:** từ VM sạch tới hệ thống chạy; liệt kê dependency chính xác với phiên bản; cách gỡ. **DoD:** người dùng làm theo được (xác nhận ở PH10-T04).

---

## PH11 — Nghiệm thu và Demo

### PH11-T01 · Bộ test nghiệm thu `[P0 · M · SW/CY/DA · C · TODO]`
- **Mô tả:** mỗi test: Preconditions, Steps, Expected, Actual, PASS/FAIL/NOT RUN, Evidence, Known limitations — điền vào `EDR_ACCEPTANCE_MATRIX.md`.

### PH11-T02 · Chạy nghiệm thu trên VM `[P0 · XL · SW/CY/DA · W · TODO]`
- **Mô tả:** người dùng chạy theo bộ test; Claude phân tích kết quả và ghi bằng chứng.

### PH11-T03 · Diễn tập demo `[P0 · M · CY · W · TODO]`
- **Mô tả:** chạy kịch bản demo hai lần liên tiếp từ snapshot sạch; có phương án dự phòng dùng dữ liệu lưu sẵn (ghi rõ là dữ liệu lưu sẵn).

### PH11-T04 · Gói bằng chứng nghiệm thu `[P0 · M · SW · C · TODO]`
- **Mô tả:** tổng hợp lệnh, phiên bản, đầu ra, ảnh chụp (đã che định danh), liên kết commit/PR.

---

## PH12 — Hoàn thiện và Bàn giao

### PH12-T01 · Tài liệu kiến trúc cuối `[P0 · M · SW · C · TODO]` — cập nhật `EDR_TARGET_ARCHITECTURE.md` theo thực tế (Implemented/Tested/Designed/Future).
### PH12-T02 · User guide và hướng dẫn triển khai `[P0 · M · SW · C · TODO]` — dựa trên PH2-T10 và PH10-T06.
### PH12-T03 · Báo cáo kiểm thử `[P0 · M · SW/CY/DA · C · TODO]` — từ PH11.
### PH12-T04 · Tổng hợp hạn chế và rủi ro `[P0 · S · CY · C · TODO]`.
### PH12-T05 · Nội dung báo cáo/bảo vệ đồ án `[P1 · M · Cả nhóm · C · TODO]` — dùng `dacn-documentation-handover`.
### PH12-T06 · Cập nhật `CLAUDE.md` mục 3, 4 theo trạng thái thực `[P1 · S · SW · U · TODO]` — chỉ khi người dùng cho phép.

---

## Nhánh ML/AI (song song, không nằm trên critical path)

### ML-T01 · Đặc tả đặc trưng (feature contract) `[P1 · M · DA · C · TODO]` — dựa trên `gold_process_features`; mỗi đặc trưng có nguồn, đơn vị, nullable, `source_event_ids`. Output: `docs/implementation/AI_TRAINING_GUIDE.md` mục đặc trưng + `src/detection/ml/features.py`.
### ML-T02 · Trích xuất đặc trưng từ Silver `[P1 · L · DA · C · TODO]` — cửa sổ thời gian, không rò rỉ nhãn; test trên fixture.
### ML-T03 · Nạp mô hình và suy luận `[P1 · M · DA · C · TODO]` — `ModelLoader` kiểm `feature_schema_version`, phiên bản, hash artifact; từ chối model sai schema.
### ML-T04 · Mã huấn luyện và đánh giá (khung) `[P2 · L · DA · C · TODO]` — preprocessing, chia train/val/test theo host/run/thời gian, metrics precision/recall/F1/FPR; **chưa chạy huấn luyện**.
### ML-T05 · Huấn luyện bởi người dùng `[P2 · XL · DA · U · TODO]` — theo `AI_TRAINING_GUIDE.md`; người dùng cung cấp artifact + báo cáo metrics.
### ML-T06 · Tích hợp mô hình đã huấn luyện `[P2 · M · DA · C · BLOCKED]` — chờ ML-T05; chỉ tích hợp khi người dùng yêu cầu.
### ML-T07 · Thử suy luận trên VM `[P2 · M · DA · W · BLOCKED]` — chờ ML-T06.
