# EDR — Báo cáo nghiệm thu (sinh tự động)

> Sinh bởi `scripts/acceptance/run_acceptance.py`; **không chỉnh tay**. Trạng thái suy ra từ kết quả pytest.
> Mức bằng chứng `L` = Linux + dữ liệu synthetic/giả lập, **không thay cho kiểm chứng trên Windows VM**.

## Môi trường chạy

- Thời điểm (UTC): 2026-11-28T14:17:20Z · thời lượng: 85.8 s
- Commit: `0bc2a3b` (cây làm việc có thay đổi chưa commit)
- Python 3.13.18 · Linux 6.18.44-fc-v880
- Thư viện: pytest 9.1.1, duckdb 2.0.1, fastapi 0.165.0, uvicorn 0.54.0, httpx 0.29.0, pydantic 2.13.5, PyYAML 6.0.3, jsonschema 4.26.0
- Mức bằng chứng: L (Linux, dữ liệu synthetic/giả lập); W (Windows) chưa chạy

## Tổng hợp

| Trạng thái | Số AT |
|---|---|
| PASS | 28 |
| PARTIAL | 6 |
| FAIL | 0 |
| NOT RUN | 18 |

PARTIAL = test đạt nhưng catalog ghi rõ phần Expected chưa được phủ tự động.

## Chi tiết

### AT-01 · R-01 · mức L · **PASS**

- **Mục tiêu:** Nguồn giả -> segment sealed, manifest đúng hash
- **Preconditions:** Thư mục home tạm; FakeSource phát N sự kiện XML synthetic
- **Steps:** 1. Chạy AgentRunner với FakeSource; 2. Đọc manifest của segment đã niêm phong; 3. Tính lại sha256
- **Expected:** Segment .jsonl + .manifest.json, sha256 khớp, raw_xml được giữ nguyên
- **Actual:** 3 test pytest đạt, 0 lỗi
- **Evidence (pytest node):**
  - `tests/agent/test_bronze_writer.py::test_seal_writes_manifest_with_correct_hash` → passed
  - `tests/agent/test_bronze_writer.py::test_raw_xml_preserved` → passed
  - `tests/agent/test_runner.py::test_full_run_writes_all_and_health` → passed
- **Known limitations:** Không chứng minh đọc Event Log thật

### AT-02 · R-01 · mức L · **PASS**

- **Mục tiêu:** Dừng/chết giữa chừng -> khởi động lại không mất bản ghi (có thể trùng)
- **Preconditions:** FakeSource có thể dừng/lỗi giữa chừng
- **Steps:** 1. Chạy agent, dừng giữa chừng; 2. Khởi động lại; 3. Đếm bản ghi trong Bronze
- **Expected:** Không mất bản ghi; trùng lặp được chấp nhận (at-least-once)
- **Actual:** 3 test pytest đạt, 0 lỗi
- **Evidence (pytest node):**
  - `tests/agent/test_runner.py::test_stop_midway_then_restart_loses_nothing` → passed
  - `tests/agent/test_runner.py::test_crash_after_write_before_checkpoint_may_duplicate_not_lose` → passed
  - `tests/agent/test_bronze_writer.py::test_recover_truncates_partial_line_and_seals` → passed
- **Known limitations:** Giả lập; chưa thử kill tiến trình trên Windows (AT-05)

### AT-03 · R-01 · mức W · **NOT RUN**

- **Mục tiêu:** Agent live nhận sự kiện mới và khớp wevtutil export
- **Preconditions:** Windows 10 VM, Sysmon chạy, quyền đọc channel Sysmon/Operational
- **Steps:** 1. $env:PYTHONPATH=...; python -m agent run --config C:\dacn_edr\edr.yaml --live --follow (hoặc python -m edr_ctl start --config C:\dacn_edr\edr.yaml --live); 2. Sinh sự kiện (mở notepad); 3. wevtutil qe Microsoft-Windows-Sysmon/Operational /c:5 /rd:true /f:xml > sysmon_export.xml; so EventRecordID và nội dung với raw_xml trong C:\dacn_edr\bronze\*.jsonl
- **Expected:** raw_xml trong Bronze trùng EventRecordID/nội dung với wevtutil
- **Actual:** Cần Windows 10 VM thật; Claude không chạy được.
- **Known limitations:** Một VM, một phiên bản Sysmon

### AT-04 · R-01 · mức W · **NOT RUN**

- **Mục tiêu:** Không có quyền đọc channel -> lỗi C-006 rõ ràng
- **Preconditions:** Windows, chạy agent bằng tài khoản không có quyền
- **Steps:** 1. Chạy python -m agent run --config C:\dacn_edr\edr.yaml --live bằng user thường; 2. Xem C:\dacn_edr\bronze\errors\collector_errors.jsonl (kiểm bằng dir nếu khác) và C:\dacn_edr\agent\health.json (kỳ vọng trạng thái error); agent thoát mã 1 khi không dùng --follow
- **Expected:** Mã lỗi C-006, agent không crash âm thầm
- **Actual:** Cần Windows 10 VM thật; Claude không chạy được.
- **Known limitations:** Phần logic ánh xạ lỗi đã có test Linux (test_access_denied_maps_to_c006) nhưng đó không phải bằng chứng trên Windows

### AT-05 · R-01 · mức W · **NOT RUN**

- **Mục tiêu:** Kill agent giữa chừng trên Windows -> phục hồi
- **Preconditions:** Windows VM, agent live đang chạy
- **Steps:** 1. taskkill /F /T /PID <pid của tiến trình agent> (lấy PID từ edr_ctl status; dùng /T vì python.exe trong venv Windows có thể là launcher sinh tiến trình con; xác nhận bằng tasklist rằng không còn python.exe của agent); 2. Khởi động lại; 3. Kiểm tra recover và không mất sự kiện
- **Expected:** recover_dir niêm phong .part, checkpoint tiếp tục
- **Actual:** Cần Windows 10 VM thật; Claude không chạy được.

### AT-06 · R-02 · mức L · **PASS**

- **Mục tiêu:** Segment hỏng 1 byte -> quarantine segment, segment khác vẫn nạp
- **Preconditions:** 2 segment hợp lệ, sửa 1 byte của một segment
- **Steps:** 1. ingest_dir; 2. Kiểm tra quarantine và Silver
- **Expected:** Segment hỏng bị quarantine; segment còn lại vào Silver
- **Actual:** 3 test pytest đạt, 0 lỗi
- **Evidence (pytest node):**
  - `tests/pipeline/test_silver_store.py::test_tampered_segment_is_quarantined_not_ingested` → passed
  - `tests/pipeline/test_silver_store.py::test_reader_rejects_tampered_segment` → passed
  - `tests/e2e/test_pipeline_fake_source.py::test_corrupt_segment_quarantined_others_still_processed` → passed

### AT-07 · R-02 · mức L · **PASS**

- **Mục tiêu:** Nạp hai lần -> không trùng; tổng đọc = valid + dedup + DLQ
- **Preconditions:** Segment synthetic
- **Steps:** 1. ingest 2 lần; 2. Đối chiếu số đếm
- **Expected:** Silver không trùng event_id; sổ cái cộng khớp
- **Actual:** 3 test pytest đạt, 0 lỗi
- **Evidence (pytest node):**
  - `tests/pipeline/test_silver_store.py::test_ingest_and_total_accounting` → passed
  - `tests/pipeline/test_silver_store.py::test_replay_is_idempotent` → passed
  - `tests/pipeline/test_silver_store.py::test_same_events_in_new_segment_are_deduped` → passed

### AT-08 · R-02 · mức L · **PASS**

- **Mục tiêu:** Replay từ Bronze dựng lại Silver trùng bản gốc
- **Preconditions:** Bronze đã nạp vào Silver
- **Steps:** 1. python -m pipeline --from-bronze D --to NEW.duckdb; 2. So sánh tập event_id
- **Expected:** Cùng tập event_id; từ chối ghi đè đích đã tồn tại
- **Actual:** 3 test pytest đạt, 0 lỗi
- **Evidence (pytest node):**
  - `tests/pipeline/test_query_replay.py::test_replay_rebuilds_same_event_ids` → passed
  - `tests/pipeline/test_query_replay.py::test_replay_refuses_existing_target` → passed
  - `tests/e2e/test_pipeline_fake_source.py::test_replay_from_bronze_reproduces_alerts` → passed

### AT-09 · R-02 · mức L · **PASS**

- **Mục tiêu:** Bản ghi thiếu field bắt buộc -> DLQ ERR_*, không điền mặc định
- **Preconditions:** Bản ghi Bronze thiếu field
- **Steps:** 1. ingest; 2. Kiểm tra DLQ
- **Expected:** Vào quarantine_dlq kèm payload, không có bản ghi Silver giả
- **Actual:** 2 test pytest đạt, 0 lỗi
- **Evidence (pytest node):**
  - `tests/pipeline/test_silver_store.py::test_bad_bronze_record_goes_to_dlq_with_payload` → passed
  - `tests/test_validator_poc_w5.py::TestDataPipelineW05::test_05_negative_samples_routed_to_quarantine_dlq` → passed

### AT-10 · R-02 · mức L · **PASS**

- **Mục tiêu:** Alert/Silver -> Bronze -> raw_xml truy vết được
- **Preconditions:** Alert từ synthetic
- **Steps:** 1. Gọi evidence resolver; 2. So raw_xml với nguồn
- **Expected:** Trạng thái FULL, raw_xml bằng XML nguồn, hash được xác minh; PARTIAL/RAW_EXPIRED khi thiếu
- **Actual:** 3 test pytest đạt, 0 lỗi
- **Evidence (pytest node):**
  - `tests/alerts/test_alerts.py::test_evidence_resolves_to_raw_xml_both_ways` → passed
  - `tests/alerts/test_alerts.py::test_evidence_partial_when_bronze_missing_or_tampered` → passed
  - `tests/e2e/test_pipeline_fake_source.py::test_full_chain_each_interface` → passed

### AT-11 · R-03 · mức L · **PASS**

- **Mục tiêu:** DET-001 dương/lành tính/thiếu dữ liệu đúng kỳ vọng
- **Preconditions:** Fixture detection (synthetic)
- **Steps:** 1. Chạy harness nhãn
- **Expected:** Expected == observed cho từng fixture DET-001
- **Actual:** 2 test pytest đạt, 0 lỗi
- **Evidence (pytest node):**
  - `tests/detection/test_rules_harness.py::test_label_matrix_all_expected_equal_observed` → passed
  - `tests/detection/test_rules_harness.py::test_missing_required_field_is_insufficient_not_benign` → passed
- **Known limitations:** Fixture, chưa phải telemetry live. Test ma trận nhãn chạy chung mọi rule, không tách riêng từng rule

### AT-12 · R-03 · mức L · **PASS**

- **Mục tiêu:** DET-003 như trên
- **Preconditions:** Fixture detection (synthetic)
- **Steps:** 1. Chạy harness nhãn
- **Expected:** Expected == observed cho fixture DET-003
- **Actual:** 1 test pytest đạt, 0 lỗi
- **Evidence (pytest node):**
  - `tests/detection/test_rules_harness.py::test_label_matrix_all_expected_equal_observed` → passed
- **Known limitations:** Không có mẫu Run key thật trước PH5; test ma trận nhãn chạy chung mọi rule

### AT-13 · R-03 · mức L · **PASS**

- **Mục tiêu:** DET-010 chuỗi đủ -> MATCH; thiếu Event 26 -> PENDING_LATE_EVENTS
- **Preconditions:** Fixture chuỗi 11->1->26
- **Steps:** 1. Chạy harness; 2. Thêm Event 26 đến muộn
- **Expected:** MATCH khi đủ; PENDING_LATE_EVENTS khi thiếu; nâng lên MATCH khi 26 đến
- **Actual:** 2 test pytest đạt, 0 lỗi
- **Evidence (pytest node):**
  - `tests/detection/test_rules_harness.py::test_label_matrix_all_expected_equal_observed` → passed
  - `tests/detection/test_rules_harness.py::test_pending_upgrades_to_match_when_delete_arrives` → passed
- **Known limitations:** Cửa sổ 300 s là TBD_UNCALIBRATED

### AT-14 · R-03 · mức L · **PASS**

- **Mục tiêu:** IOC khớp hash tệp thử nghiệm; allowlist không bị gắn cờ
- **Preconditions:** Kho IOC synthetic
- **Steps:** 1. Đánh giá sự kiện có hash IOC; 2. Đánh giá hash trong allowlist
- **Expected:** IOC -> MATCH kèm lý do nói rõ hash không chứng minh độc hại; allowlist thắng IOC; IOC hết hạn bị bỏ qua
- **Actual:** 3 test pytest đạt, 0 lỗi
- **Evidence (pytest node):**
  - `tests/detection/test_rules_harness.py::test_ioc_match_and_reason_states_hash_is_not_proof` → passed
  - `tests/detection/test_rules_harness.py::test_allowlist_wins_over_ioc` → passed
  - `tests/detection/test_rules_harness.py::test_expired_ioc_ignored` → passed
- **Known limitations:** Hash không chứng minh độc hại

### AT-15 · R-03 · mức L · **PASS**

- **Mục tiêu:** Replay không sinh DetectionResult trùng
- **Preconditions:** Silver đã phát hiện một lần
- **Steps:** 1. Chạy detection lại; 2. Đếm DetectionResult
- **Expected:** Không trùng; đổi rule_version thì tạo đánh giá mới
- **Actual:** 3 test pytest đạt, 0 lỗi
- **Evidence (pytest node):**
  - `tests/detection/test_rules_harness.py::test_rule_version_bump_creates_new_evaluation` → passed
  - `tests/alerts/test_alerts.py::test_rebuild_is_idempotent` → passed
  - `tests/e2e/test_pipeline_fake_source.py::test_interrupted_agent_then_restart_gives_same_alerts_as_uninterrupted` → passed

### AT-16 · R-03 · mức W · **NOT RUN**

- **Mục tiêu:** SC-01..SC-04 phát hiện trên VM, ghi nguồn phát hiện (EDR/Defender)
- **Preconditions:** VM lab, Sysmon, script lab đã được người dùng đọc
- **Steps:** 1. Chạy scripts\lab\dacn_lab_scenarios.ps1 -WhatIf rồi chạy thật (mặc định SC01,SC02,SC03,SC06,SC07; SC04 chạy riêng bằng -Scenario SC04); 2. python tests/e2e/compare_expected.py --manifest $env:TEMP\dacn_lab\lab_run_<runid>.json --silver <bản sao của C:\dacn_edr\silver\endpoint_silver.duckdb> --bronze C:\dacn_edr\bronze --ioc $env:TEMP\dacn_lab\ioc_candidate_<runid>.yaml --out report.md
- **Expected:** Báo cáo so khớp scenarios.yaml
- **Actual:** Cần Windows 10 VM thật; Claude không chạy được.
- **Known limitations:** Chỉ trên tập kịch bản đã chạy

### AT-17 · R-04 · mức L · **PASS**

- **Mục tiêu:** MATCH -> alert đủ trường, severity có lý do
- **Preconditions:** DetectionResult MATCH synthetic
- **Steps:** 1. Dựng alert; 2. Kiểm tra trường
- **Expected:** Alert có rule_version, MITRE (nếu có căn cứ), severity và lý do
- **Actual:** 1 test pytest đạt, 0 lỗi
- **Evidence (pytest node):**
  - `tests/alerts/test_alerts.py::test_match_becomes_alert_with_rule_version_and_mitre` → passed
- **Known limitations:** Severity là heuristic chưa hiệu chỉnh

### AT-18 · R-04 · mức L · **PASS**

- **Mục tiêu:** Máy trạng thái alert chặn chuyển sai
- **Preconditions:** Alert NEW
- **Steps:** 1. Thử chuyển trạng thái hợp lệ và không hợp lệ
- **Expected:** Chuyển sai bị từ chối; lịch sử và audit hash-chain ghi đủ
- **Actual:** 3 test pytest đạt, 0 lỗi
- **Evidence (pytest node):**
  - `tests/alerts/test_alerts.py::test_state_machine_and_history` → passed
  - `tests/alerts/test_alerts.py::test_audit_chain_detects_tampering` → passed
  - `tests/api/test_api.py::test_alert_transition_flow_and_invalid` → passed
- **Known limitations:** Audit chain phát hiện nhưng không ngăn sửa đổi

### AT-19 · R-04 · mức L · **PASS**

- **Mục tiêu:** Dedup alert; INSUFFICIENT_TELEMETRY thành coverage gap, không phải alert đe dọa
- **Preconditions:** Nhiều MATCH cùng nhóm; một INSUFFICIENT
- **Steps:** 1. Dựng alert; 2. Liệt kê alerts và coverage-gaps
- **Expected:** Nhóm trùng bị gộp và đếm; INSUFFICIENT chỉ ở coverage_gaps
- **Actual:** 3 test pytest đạt, 0 lỗi
- **Evidence (pytest node):**
  - `tests/alerts/test_alerts.py::test_duplicate_group_is_suppressed_and_counted` → passed
  - `tests/alerts/test_alerts.py::test_insufficient_telemetry_is_coverage_gap_not_alert` → passed
  - `tests/api/test_api.py::test_detections_and_coverage_gaps` → passed
- **Known limitations:** Bucket 600 s là giá trị tạm

### AT-20 · R-04 · mức L · **PASS**

- **Mục tiêu:** Timeline + cây tiến trình đúng với mẫu
- **Preconditions:** Sự kiện synthetic có quan hệ cha-con
- **Steps:** 1. Gọi timeline và process-tree
- **Expected:** Thứ tự đúng, cảnh báo lệch giờ, tổ tiên thiếu được đánh dấu PARTIAL
- **Actual:** 2 test pytest đạt, 0 lỗi
- **Evidence (pytest node):**
  - `tests/alerts/test_alerts.py::test_timeline_orders_and_reports_skew_and_tree_flags_partial_ancestry` → passed
  - `tests/api/test_api.py::test_timeline_and_process_tree_404_without_process` → passed
- **Known limitations:** Chưa kiểm trên dữ liệu live

### AT-21 · R-05 · mức L · **PASS**

- **Mục tiêu:** Mặc định dry_run, không đổi hệ thống
- **Preconditions:** Policy mặc định
- **Steps:** 1. Duyệt và thực thi một hành động
- **Expected:** Chỉ ghi kế hoạch; tiến trình/tệp không đổi; execute cần cả hai khóa
- **Actual:** 6 test pytest đạt, 0 lỗi
- **Evidence (pytest node):**
  - `tests/response/test_response.py::test_shipped_policy_is_dry_run_and_locked` → passed
  - `tests/response/test_response.py::test_execute_needs_both_locks` → passed
  - `tests/response/test_response.py::test_dry_run_changes_nothing_and_records_plan` → passed
  - `tests/response/test_response.py::test_dry_run_quarantine_leaves_file` → passed
  - `tests/response/test_response.py::test_execute_blocked_without_both_locks_falls_back_to_dry_run` → passed
  - `tests/response/test_response.py::test_factory_never_enables_execute_on_non_windows` → passed
- **Known limitations:** Backend giả/Linux; không phải Windows

### AT-22 · R-05 · mức L · **PASS**

- **Mục tiêu:** Thiếu approval -> từ chối
- **Preconditions:** Hành động ở trạng thái REQUESTED
- **Steps:** 1. Thực thi khi chưa duyệt
- **Expected:** Bị từ chối; responder chỉ nhận hành động đã duyệt; không giả mạo audit
- **Actual:** 4 test pytest đạt, 0 lỗi
- **Evidence (pytest node):**
  - `tests/response/test_response.py::test_unapproved_action_not_executed` → passed
  - `tests/response/test_response.py::test_distinct_approver_enforced_when_configured` → passed
  - `tests/api/test_api.py::test_responder_cannot_claim_unapproved_or_forge_audit` → passed
  - `tests/api/test_api.py::test_response_request_approve_and_role_separation` → passed

### AT-23 · R-05 · mức L · **PASS**

- **Mục tiêu:** Mục tiêu thuộc allowlist bảo vệ -> từ chối
- **Preconditions:** Yêu cầu nhắm lsass.exe, explorer.exe, System, thư mục hệ thống
- **Steps:** 1. Gửi yêu cầu, kể cả khi đã duyệt
- **Expected:** Từ chối trước khi tới backend, kể cả có marker; marker ngoài thư mục lab vẫn bị từ chối
- **Actual:** 9 test pytest đạt, 0 lỗi
- **Evidence (pytest node):**
  - `tests/response/test_response.py::test_protected_process_names_always_denied_even_in_lab[lsass.exe]` → passed
  - `tests/response/test_response.py::test_protected_process_names_always_denied_even_in_lab[LSASS.EXE]` → passed
  - `tests/response/test_response.py::test_protected_process_names_always_denied_even_in_lab[explorer.exe]` → passed
  - `tests/response/test_response.py::test_protected_process_names_always_denied_even_in_lab[System]` → passed
  - `tests/response/test_response.py::test_protected_dir_and_non_lab_and_self_denied` → passed
  - `tests/response/test_response.py::test_marker_in_name_outside_lab_dir_is_still_denied_path_traversal` → passed
  - `tests/response/test_response.py::test_protected_target_denied_before_backend_even_if_approved` → passed
  - `tests/response/test_response.py::test_file_target_must_be_inside_lab` → passed
  - `tests/response/test_response.py::test_quarantine_outside_lab_denied` → passed
- **Known limitations:** Danh sách bảo vệ là tập tối thiểu, chưa đầy đủ cho mọi hệ thống

### AT-24 · R-05 · mức L · **PASS**

- **Mục tiêu:** PID tái sử dụng -> phát hiện và từ chối
- **Preconditions:** Backend giả báo creation time/image khác
- **Steps:** 1. Thực thi terminate
- **Expected:** Từ chối khi danh tính không khớp hoặc tiến trình đã biến mất
- **Actual:** 3 test pytest đạt, 0 lỗi
- **Evidence (pytest node):**
  - `tests/response/test_response.py::test_pid_reuse_is_refused` → passed
  - `tests/response/test_response.py::test_process_gone_is_refused` → passed
  - `tests/response/test_response.py::test_creation_time_iso_tolerance_and_filetime_conversion` → passed
- **Known limitations:** Giả lập; WinProcessApi chưa chạy trên Windows

### AT-25 · R-05 · mức W · **NOT RUN**

- **Mục tiêu:** Terminate tiến trình thử nghiệm (marker lab) khi execute + audit
- **Preconditions:** VM, người dùng tự đặt mode execute và execute_unlocked true trong config\\response-policy.yaml; đã tạo token vai trò responder (python -m api.auth --role responder) và đặt $env:EDR_RESPONDER_TOKEN TRƯỚC khi edr_ctl start (thiếu biến này responder không chạy, hành động đã duyệt sẽ không được thực thi)
- **Steps:** 1. Chạy tiến trình thử nghiệm nằm trong thư mục lab (%TEMP%\dacn_lab; tên marker KHÔNG đủ); 2. Yêu cầu và duyệt terminate (người duyệt khác người yêu cầu); 3. Kiểm tra Task Manager và audit
- **Expected:** Tiến trình bị kết thúc; audit trước/sau đủ
- **Actual:** Cần Windows 10 VM thật; Claude không chạy được.
- **Known limitations:** Chỉ tiến trình thử nghiệm

### AT-26 · R-05 · mức W · **NOT RUN**

- **Mục tiêu:** Quarantine tệp thử nghiệm rồi restore, hash khớp
- **Preconditions:** VM, tệp trong thư mục lab
- **Steps:** 1. Điều kiện như AT-25 (responder đã chạy); 2. Duyệt quarantine tệp trong %TEMP%\dacn_lab; 3. Restore; 4. So sha256 trước và sau (Get-FileHash)
- **Expected:** Hash khớp, không ghi đè, không xóa vĩnh viễn
- **Actual:** Cần Windows 10 VM thật; Claude không chạy được.
- **Known limitations:** Chỉ thư mục lab. Logic đã có test Linux (quarantine/restore) nhưng không thay cho Windows

### AT-27 · R-06 · mức L · **PASS**

- **Mục tiêu:** Xác thực - thiếu/sai token -> 401/403
- **Preconditions:** API với token store
- **Steps:** 1. Gọi endpoint không token, sai token, sai vai trò
- **Expected:** 401/403 mã lỗi thống nhất; /livez công khai và tối thiểu; token lưu dạng hash
- **Actual:** 11 test pytest đạt, 0 lỗi
- **Evidence (pytest node):**
  - `tests/api/test_api.py::test_endpoints_require_token[/health]` → passed
  - `tests/api/test_api.py::test_endpoints_require_token[/endpoint]` → passed
  - `tests/api/test_api.py::test_endpoints_require_token[/events]` → passed
  - `tests/api/test_api.py::test_endpoints_require_token[/alerts]` → passed
  - `tests/api/test_api.py::test_endpoints_require_token[/rules]` → passed
  - `tests/api/test_api.py::test_endpoints_require_token[/detections]` → passed
  - `tests/api/test_api.py::test_endpoints_require_token[/response/actions]` → passed
  - `tests/api/test_api.py::test_wrong_token_rejected_and_livez_is_public_and_minimal` → passed
  - `tests/api/test_api.py::test_viewer_cannot_write` → passed
  - `tests/api/test_api.py::test_responder_cannot_read_data` → passed
  - `tests/api/test_api.py::test_tokens_stored_hashed_and_cli_helper` → passed
- **Known limitations:** Chỉ loopback; không có TLS

### AT-28 · R-06 · mức L · **PASS**

- **Mục tiêu:** Validate input - tham số sai/quá lớn -> lỗi mã ổn định
- **Preconditions:** API
- **Steps:** 1. Gửi tham số sai, chuỗi SQLi, body quá 64 KB
- **Expected:** Lỗi định dạng {error:{code,message}}, không rò rỉ nội bộ
- **Actual:** 3 test pytest đạt, 0 lỗi
- **Evidence (pytest node):**
  - `tests/api/test_api.py::test_events_sqli_string_is_inert_and_bad_params_rejected` → passed
  - `tests/api/test_api.py::test_oversized_body_rejected_and_errors_do_not_leak` → passed
  - `tests/api/test_api.py::test_reject_needs_reason` → passed

### AT-29 · R-06 · mức L · **PASS**

- **Mục tiêu:** Endpoint events/detections/alerts/response trả đúng schema
- **Preconditions:** API với dữ liệu synthetic
- **Steps:** 1. Gọi các endpoint; 2. Đối chiếu openapi.json
- **Expected:** Đúng schema; phân trang; không lộ raw_data; openapi export khớp
- **Actual:** 8 test pytest đạt, 0 lỗi
- **Evidence (pytest node):**
  - `tests/api/test_api.py::test_events_pagination_filter_and_no_raw_data` → passed
  - `tests/api/test_api.py::test_alert_list_detail_and_validation` → passed
  - `tests/api/test_api.py::test_detections_and_coverage_gaps` → passed
  - `tests/api/test_api.py::test_incident_flow` → passed
  - `tests/api/test_api.py::test_rules_read_only` → passed
  - `tests/api/test_api.py::test_health_reports_measured_state_only` → passed
  - `tests/api/test_api.py::test_openapi_export` → passed
  - `tests/api/test_api.py::test_evidence_raw_only_for_allowed_roles_and_audited` → passed

### AT-30 · R-07 · mức L · **PASS**

- **Mục tiêu:** Dashboard hiển thị dữ liệu từ API, có tìm/lọc/chi tiết
- **Preconditions:** Node + Playwright Chromium, API với dữ liệu mẫu có nhãn SAMPLE
- **Steps:** 1. Chạy tests/dashboard/test_dashboard_ui.py
- **Expected:** Các kiểm tra UI đạt; banner dữ liệu mẫu hiển thị; XSS chỉ hiện dạng text
- **Actual:** 3 test pytest đạt, 0 lỗi
- **Evidence (pytest node):**
  - `tests/dashboard/test_dashboard_ui.py::test_dashboard_ui_checks` → passed
  - `tests/api/test_api.py::test_ui_is_served_with_strict_csp_and_no_cache` → passed
  - `tests/api/test_api.py::test_me_stats_and_data_label` → passed
- **Known limitations:** Fixture gắn nhãn DỮ LIỆU MẪU; một trình duyệt (Chromium)

### AT-31 · R-07 · mức L · **PASS**

- **Mục tiêu:** Trạng thái loading/lỗi/rỗng
- **Preconditions:** như AT-30
- **Steps:** 1. Token sai -> trạng thái lỗi; 2. Bộ lọc không có kết quả -> trạng thái rỗng
- **Expected:** Có trạng thái lỗi (role=alert), rỗng và loading
- **Actual:** 1 test pytest đạt, 0 lỗi
- **Evidence (pytest node):**
  - `tests/dashboard/test_dashboard_ui.py::test_dashboard_ui_checks` → passed

### AT-32 · R-07 · mức L · **PASS**

- **Mục tiêu:** Chi tiết alert hiển thị nguồn bằng chứng + kết quả response
- **Preconditions:** như AT-30
- **Steps:** 1. Mở chi tiết alert
- **Expected:** Hiển thị đường dẫn bằng chứng và trạng thái hành động response
- **Actual:** 1 test pytest đạt, 0 lỗi
- **Evidence (pytest node):**
  - `tests/dashboard/test_dashboard_ui.py::test_dashboard_ui_checks` → passed

### AT-33 · R-07 · mức W · **NOT RUN**

- **Mục tiêu:** Dashboard trên VM hiển thị cảnh báo thật của SC-01
- **Preconditions:** Hệ thống chạy trên VM
- **Steps:** 1. Chạy SC-01; 2. Mở /ui
- **Expected:** Alert DET-001 hiển thị với bằng chứng
- **Actual:** Cần Windows 10 VM thật; Claude không chạy được.

### AT-34 · R-08 · mức W · **NOT RUN**

- **Mục tiêu:** edr_ctl start/status/stop khởi động/dừng sạch, không tiến trình mồ côi trên Windows
- **Preconditions:** Windows VM
- **Steps:** 1. python -m edr_ctl start/status/stop --config C:\dacn_edr\edr.yaml --live (đã đặt $env:PYTHONPATH); 2. Kiểm tra tasklist trước start, sau start, sau stop (venv Windows có thể hiện 2 python.exe cho mỗi thành phần: launcher và tiến trình con); 3. Nếu stop báo STILL-RUNNING vì không xác minh được tiến trình thì ghi lại rồi mới dùng --force
- **Expected:** Không còn tiến trình mồ côi
- **Actual:** Cần Windows 10 VM thật; Claude không chạy được.
- **Known limitations:** Đã có test Linux (tests/test_edr_ctl.py, tests/e2e/test_edr_ctl_real_processes.py) - không thay cho Windows

### AT-35 · R-08 · mức W · **NOT RUN**

- **Mục tiêu:** Làm theo hướng dẫn cài từ VM sạch tới hệ thống chạy
- **Preconditions:** VM snapshot sạch
- **Steps:** 1. Làm từng bước EDR_INSTALL_GUIDE.md
- **Expected:** Hệ thống chạy; ghi lại bước nào sai
- **Actual:** Cần Windows 10 VM thật; Claude không chạy được.

### AT-36 · R-09 · mức W · **NOT RUN**

- **Mục tiêu:** Chuỗi đầy đủ SC-01 từ snapshot sạch
- **Preconditions:** VM snapshot sạch
- **Steps:** 1. Theo EDR_DEMO_PLAN mục 4
- **Expected:** SC-01 -> alert -> bằng chứng -> dashboard
- **Actual:** Cần Windows 10 VM thật; Claude không chạy được.

### AT-37 · R-09 · mức W · **NOT RUN**

- **Mục tiêu:** Chuỗi đầy đủ SC-03 -> alert -> duyệt response -> terminate/quarantine
- **Preconditions:** VM, execute bật bởi người dùng
- **Steps:** 1. Chạy SC03 bằng dacn_lab_scenarios.ps1; 2. SC-08 là thao tác thủ công, không có trong script: chạy tiến trình thử nghiệm sống lâu trong %TEMP%\dacn_lab, duyệt terminate/quarantine trên Dashboard (xem EDR_DEMO_PLAN.md dòng SC-08); 3. Đối chiếu audit
- **Expected:** Alert, duyệt, thực thi, audit
- **Actual:** Cần Windows 10 VM thật; Claude không chạy được.

### AT-38 · R-09 · mức W · **NOT RUN**

- **Mục tiêu:** Kiểm soát lành tính SC-06 không sinh alert đe dọa
- **Preconditions:** VM
- **Steps:** 1. SC-06
- **Expected:** NO_MATCH
- **Actual:** Cần Windows 10 VM thật; Claude không chạy được.
- **Known limitations:** Cỡ mẫu nhỏ

### AT-39 · R-09 · mức W · **NOT RUN**

- **Mục tiêu:** Thiếu telemetry SC-07 -> INSUFFICIENT/PENDING, không báo giả
- **Preconditions:** VM
- **Steps:** 1. SC-07
- **Expected:** PENDING_LATE_EVENTS hoặc INSUFFICIENT_TELEMETRY
- **Actual:** Cần Windows 10 VM thật; Claude không chạy được.

### AT-40 · R-09 · mức W · **NOT RUN**

- **Mục tiêu:** Lặp lại demo lần 2 từ snapshot sạch cho kết quả tương đương
- **Preconditions:** VM
- **Steps:** 1. Khôi phục snapshot; 2. Chạy lại demo
- **Expected:** Kết quả tương đương lần 1
- **Actual:** Cần Windows 10 VM thật; Claude không chạy được.

### AT-41 · R-10 · mức D · **PARTIAL**

- **Mục tiêu:** Tài liệu cài đặt/user guide/báo cáo đầy đủ, liên kết hợp lệ
- **Preconditions:** Repo
- **Steps:** 1. Kiểm tra liên kết tương đối trong docs/implementation
- **Expected:** Mọi liên kết tương đối trỏ tới tệp tồn tại
- **Actual:** 55 liên kết tương đối đã kiểm tra; hỏng: không
- **Chưa phủ:** Chỉ kiểm tra liên kết nội bộ; user guide, hướng dẫn cài đặt chưa được ai làm theo trên VM sạch (AT-35)

### AT-42 · R-11 · mức L · **PASS**

- **Mục tiêu:** Toàn bộ test contract/identity xanh; UUIDv5 từ Silver tái dựng được
- **Preconditions:** Repo
- **Steps:** 1. pytest poc/sysmon-collector tests/test_validator_poc_w5.py
- **Expected:** Tất cả đạt
- **Actual:** 33 test pytest đạt, 0 lỗi
- **Evidence (pytest node):**
  - `poc/sysmon-collector/test_bronze_contract.py::test_split_keeps_original_text` → passed
  - `poc/sysmon-collector/test_bronze_contract.py::test_records_conform_to_schema` → passed
  - `poc/sysmon-collector/test_bronze_contract.py::test_system_metadata_is_kept` → passed
  - `poc/sysmon-collector/test_bronze_contract.py::test_event_id_matches_poc_and_is_stable` → passed
  - `poc/sysmon-collector/test_bronze_contract.py::test_schema_rejects_bad_records` → passed
  - `poc/sysmon-collector/test_bronze_contract.py::test_unknown_fields_are_allowed` → passed
  - `poc/sysmon-collector/test_bronze_contract.py::test_collector_errors_use_reason_codes` → passed
  - `poc/sysmon-collector/test_bronze_contract.py::test_coverage_report_on_synthetic_samples` → passed
  - `poc/sysmon-collector/test_bronze_contract.py::test_coverage_accepts_poc_json_output` → passed
  - `poc/sysmon-collector/test_bronze_contract.py::test_coverage_accepts_bronze_jsonl_segment` → passed
  - `poc/sysmon-collector/test_canonical_bronze_contract.py::test_shared_xml_to_bronze_to_silver_input` → passed
  - `poc/sysmon-collector/test_canonical_bronze_contract.py::test_missing_bronze_identity_is_rejected` → passed
  - `poc/sysmon-collector/test_canonical_bronze_contract.py::test_raw_payload_mismatch_is_rejected` → passed
  - `poc/sysmon-collector/test_sysmon_collector_poc.py::test_reads_all_events_from_rootless_xml` → passed
  - `poc/sysmon-collector/test_sysmon_collector_poc.py::test_parse_hashes` → passed
  - `poc/sysmon-collector/test_sysmon_collector_poc.py::test_strip_guid_removes_braces_and_keeps_case` → passed
  - `poc/sysmon-collector/test_sysmon_collector_poc.py::test_process_event_mapping` → passed
  - `poc/sysmon-collector/test_sysmon_collector_poc.py::test_network_event_mapping` → passed
  - `poc/sysmon-collector/test_sysmon_collector_poc.py::test_registry_event_mapping` → passed
  - `poc/sysmon-collector/test_sysmon_collector_poc.py::test_file_event_mapping` → passed
  - `poc/sysmon-collector/test_sysmon_collector_poc.py::test_event_id_is_deterministic` → passed
  - `poc/sysmon-collector/test_sysmon_collector_poc.py::test_raw_data_is_kept` → passed
  - `poc/sysmon-collector/test_sysmon_collector_poc.py::test_registry_type_inference` → passed
  - `poc/sysmon-collector/test_sysmon_collector_poc.py::test_cli_exports_json_for_one_event_type` → passed
  - `poc/sysmon-collector/test_sysmon_collector_poc.py::test_cli_jsonl_output` → passed
  - `poc/sysmon-collector/test_sysmon_collector_poc.py::test_live_mode_gives_clear_error_without_pywin32` → passed
  - `tests/test_validator_poc_w5.py::TestDataPipelineW05::test_01_deterministic_uuidv5_matches_w3_real_samples` → passed
  - `tests/test_validator_poc_w5.py::TestDataPipelineW05::test_02_strip_guid_and_registry_heuristics` → passed
  - `tests/test_validator_poc_w5.py::TestDataPipelineW05::test_03_positive_event_id_22_dns_and_id_05_terminate` → passed
  - `tests/test_validator_poc_w5.py::TestDataPipelineW05::test_04_idempotent_deduplication_on_replay` → passed
  - `tests/test_validator_poc_w5.py::TestDataPipelineW05::test_05_negative_samples_routed_to_quarantine_dlq` → passed
  - `tests/test_validator_poc_w5.py::TestDataPipelineW05::test_06_time_skew_warning_and_shannon_entropy` → passed
  - `tests/pipeline/test_query_replay.py::test_replay_rebuilds_same_event_ids` → passed
- **Known limitations:** Phụ thuộc quyết định hostname (D-07); hợp đồng chưa được phê duyệt chéo

### AT-43 · R-12 · mức L · **PASS**

- **Mục tiêu:** Tắt ML = hành vi không đổi; detector giả hoạt động
- **Preconditions:** Repo
- **Steps:** 1. Chạy test ML interface
- **Expected:** ML tắt mặc định, không kích hoạt response
- **Actual:** 3 test pytest đạt, 0 lỗi
- **Evidence (pytest node):**
  - `tests/detection/test_rules_harness.py::test_ml_off_by_default_and_never_triggers_response` → passed
  - `tests/detection/test_ml_loader.py::test_enabled_fake_detector_does_not_change_rule_results` → passed
  - `tests/detection/test_ml_loader.py::test_load_ok_and_score_is_not_response_trigger` → passed
- **Known limitations:** Chưa có mô hình ML thật

### AT-44 · R-11 · mức L · **PARTIAL**

- **Mục tiêu:** Bản ghi Defender/PowerShell synthetic -> Bronze bronze-event/1.1, source đúng theo kênh, định danh theo ADR 0001
- **Preconditions:** Fixture tests/fixtures/windows_channels/*.synthetic.xml
- **Steps:** 1. build_bronze_record trên fixture Defender/PowerShell và Sysmon; 2. Kiểm tra source, schema_version, event_id; 3. Kênh lạ và source không khớp kênh
- **Expected:** Defender -> WINDOWS_DEFENDER, PowerShell -> POWERSHELL (1.1); Sysmon giữ 1.0; công thức event_id không đổi; kênh lạ -> C-007; adapter fail-closed với 1.1
- **Actual:** 12 test pytest đạt, 0 lỗi
- **Evidence (pytest node):**
  - `tests/pipeline/test_bronze_v11_channels.py::test_new_channels_get_their_own_source_and_v11[defender_1116.synthetic.xml-WINDOWS_DEFENDER]` → passed
  - `tests/pipeline/test_bronze_v11_channels.py::test_new_channels_get_their_own_source_and_v11[defender_5001.synthetic.xml-WINDOWS_DEFENDER]` → passed
  - `tests/pipeline/test_bronze_v11_channels.py::test_new_channels_get_their_own_source_and_v11[ps4104_single.synthetic.xml-POWERSHELL]` → passed
  - `tests/pipeline/test_bronze_v11_channels.py::test_sysmon_record_unchanged_v10` → passed
  - `tests/pipeline/test_bronze_v11_channels.py::test_identity_formula_unchanged_and_channel_separates_same_record_id` → passed
  - `tests/pipeline/test_bronze_v11_channels.py::test_unsupported_channel_is_c007_not_mislabelled` → passed
  - `tests/pipeline/test_bronze_v11_channels.py::test_source_or_version_not_matching_channel_is_rejected` → passed
  - `tests/pipeline/test_bronze_v11_channels.py::test_v10_schema_still_rejects_new_sources` → passed
  - `tests/pipeline/test_bronze_v11_channels.py::test_adapter_accepts_v11_and_names_event_type_by_channel` → passed
  - `tests/pipeline/test_bronze_v11_channels.py::test_adapter_still_fails_closed_on_v11_identity` → passed
  - `tests/pipeline/test_bronze_v11_channels.py::test_sysmon_validator_never_accepts_new_channels` → passed
  - `tests/pipeline/test_bronze_v11_channels.py::test_channel_table_helpers` → passed
- **Chưa phủ:** bronze-event/1.1 là bản bổ sung người dùng duyệt (D1-D2) thay cho Data/Software/Cyber, chưa phê duyệt chéo
- **Known limitations:** Dữ liệu synthetic

### AT-45 · R-02 · mức L · **PARTIAL**

- **Mục tiêu:** Route theo kênh vào bảng Silver v1.3, mã lỗi mới, dedup, view ghép 4104
- **Preconditions:** Fixture windows_channels; DDL v1.3 đề xuất
- **Steps:** 1. Nạp segment hỗn hợp Sysmon/Defender/PowerShell; 2. Kiểm tra bảng đích, DLQ, view v_powershell_scriptblocks_complete; 3. Nạp lại segment
- **Expected:** Mỗi bản ghi vào đúng bảng hoặc DLQ với mã ERR_* cụ thể; block thiếu phần không có trong view (không bịa); nạp lại idempotent; Sysmon không đổi
- **Actual:** 18 test pytest đạt, 0 lỗi
- **Evidence (pytest node):**
  - `tests/pipeline/test_silver_windows_channels.py::test_defender_detection_and_action_share_detection_id` → passed
  - `tests/pipeline/test_silver_windows_channels.py::test_defender_cmdline_resource_and_unknown_process` → passed
  - `tests/pipeline/test_silver_windows_channels.py::test_defender_config_events` → passed
  - `tests/pipeline/test_silver_windows_channels.py::test_defender_missing_threat_goes_to_dlq` → passed
  - `tests/pipeline/test_silver_windows_channels.py::test_scriptblock_parts_and_complete_view` → passed
  - `tests/pipeline/test_silver_windows_channels.py::test_incomplete_block_not_in_view_and_not_fabricated` → passed
  - `tests/pipeline/test_silver_windows_channels.py::test_bad_part_number_and_missing_field` → passed
  - `tests/pipeline/test_silver_windows_channels.py::test_unsupported_event_id_in_supported_channel` → passed
  - `tests/pipeline/test_silver_windows_channels.py::test_replay_is_idempotent_and_lineage_written` → passed
  - `tests/pipeline/test_silver_windows_channels.py::test_sysmon_still_routed_to_sysmon_tables_in_mixed_segment` → passed
  - `tests/pipeline/test_silver_windows_channels.py::test_validator_rejects_unsupported_channel_and_bad_timestamp` → passed
  - `tests/pipeline/test_silver_windows_channels.py::test_split_resource[file:_C:\\a\\b.txt-expected0]` → passed
  - `tests/pipeline/test_silver_windows_channels.py::test_split_resource[CmdLine:_cmd /c x-expected1]` → passed
  - `tests/pipeline/test_silver_windows_channels.py::test_split_resource[C:\\no\\prefix.txt-expected2]` → passed
  - `tests/pipeline/test_silver_windows_channels.py::test_split_resource[-expected3]` → passed
  - `tests/pipeline/test_silver_windows_channels.py::test_split_resource[None-expected4]` → passed
  - `tests/pipeline/test_silver_windows_channels.py::test_raw_data_kept_verbatim` → passed
  - `tests/pipeline/test_ingest_batching.py::test_mixed_channels_in_batches` → passed
- **Chưa phủ:** DDL v1.3 là đề xuất chưa duyệt chéo
- **Known limitations:** Dữ liệu synthetic

### AT-46 · R-03 · mức L · **PARTIAL**

- **Mục tiêu:** DACN-DET-201..204 trên fixture; alert không chứa script; không response tự động
- **Preconditions:** Fixture windows_channels
- **Steps:** 1. Chạy DetectionEngine và AlertBuilder trên fixture Defender/PowerShell; 2. Kiểm tra outcome, severity, gom alert, nội dung alert
- **Expected:** DET-201 gom 1116/1117 theo detection_id; DET-202 severity theo Event ID, 5007 lọc theo khóa và hướng thay đổi; DET-203/204 MATCH đúng mẫu, alert chỉ có tên mẫu và sha256; rule chỉ alert
- **Actual:** 64 test pytest đạt, 0 lỗi
- **Evidence (pytest node):**
  - `tests/detection/test_defender_rules.py::test_det201_eicar_detection_and_action_become_one_external_alert` → passed
  - `tests/detection/test_defender_rules.py::test_det201_different_detections_are_separate_alerts` → passed
  - `tests/detection/test_defender_rules.py::test_det202_severity_by_event_id_and_mitre` → passed
  - `tests/detection/test_defender_rules.py::test_defender_only_ingestion_after_first_run_is_evaluated` → passed
  - `tests/detection/test_defender_rules.py::test_incremental_run_with_only_channel_data_and_no_sysmon` → passed
  - `tests/detection/test_defender_rules.py::test_defender_timestamps_do_not_move_correlation_watermark` → passed
  - `tests/detection/test_defender_rules.py::test_defender_alert_evidence_resolves_to_raw_xml` → passed
  - `tests/detection/test_defender_rules.py::test_engine_without_v13_tables_skips_channel_rules` → passed
  - `tests/detection/test_defender_rules.py::test_loader_rejects_bad_source_events[kw0-ch\u1ec9 khai m\u1ed9t]` → passed
  - `tests/detection/test_defender_rules.py::test_loader_rejects_bad_source_events[kw1-kh\xf4ng c\xf3 b\u1ea3ng Silver]` → passed
  - `tests/detection/test_defender_rules.py::test_loader_rejects_bad_source_events[kw2-kh\xf4ng h\u1ed7 tr\u1ee3 Event ID]` → passed
  - `tests/detection/test_defender_rules.py::test_loader_rejects_bad_source_events[kw3-EXTERNAL_DEFENDER]` → passed
  - `tests/detection/test_defender_rules.py::test_loader_rejects_bad_source_events[kw4-ch\u1ec9 d\xf9ng rule 'scriptblock']` → passed
  - `tests/detection/test_defender_rules.py::test_loader_rejects_bad_source_events[kw5-source_events ch\u1ec9 d\xf9ng]` → passed
  - `tests/detection/test_defender_rules.py::test_loader_rejects_bad_source_events[kw6-sysmon_event_ids ho\u1eb7c source_events]` → passed
  - `tests/detection/test_defender_rules.py::test_loader_normalizes_channel_case_without_mutating_input` → passed
  - `tests/detection/test_defender_rules.py::test_evaluator_severity_by_and_context_only_on_match` → passed
  - `tests/detection/test_defender_rules.py::test_shipped_defender_rules_are_alert_only` → passed
  - `tests/detection/test_defender_rules.py::test_det201_detection_across_10_minute_boundary_stays_one_alert` → passed
  - `tests/detection/test_defender_rules.py::test_det201_1117_processed_first_keeps_earliest_first_seen` → passed
  - `tests/detection/test_defender_rules.py::test_det201_different_detection_ids_far_apart_are_not_merged` → passed
  - `tests/detection/test_defender_rules.py::test_det202_without_group_by_field_still_uses_time_buckets` → passed
  - `tests/detection/test_defender_rules.py::test_det202_v2_internal_5007_changes_do_not_alert` → passed
  - `tests/detection/test_defender_rules.py::test_det202_v2_security_related_5007_alerts[TamperProtection = 0x1]` → passed
  - `tests/detection/test_defender_rules.py::test_det202_v2_security_related_5007_alerts[DisableBmNetworkSensor = 0x1]` → passed
  - `tests/detection/test_defender_rules.py::test_det202_v2_security_related_5007_alerts[DisableRealtimeMonitoring = 0x]` → passed
  - `tests/detection/test_defender_rules.py::test_det202_v2_security_related_5007_alerts[dacn_lab = 0x0]` → passed
  - `tests/detection/test_defender_rules.py::test_det202_v2_security_related_5007_alerts[SubmitSamplesConsent = 0x2]` → passed
  - `tests/detection/test_defender_rules.py::test_det202_v2_security_related_5007_alerts[SpynetReporting = 0x0]` → passed
  - `tests/detection/test_defender_rules.py::test_det202_v2_security_related_5007_alerts[DisableBehaviorMonitoring = 0x]` → passed
  - `tests/detection/test_defender_rules.py::test_det202_v3_strengthen_or_noop_5007_does_not_alert[dacn_lab = 0x0]` → passed
  - `tests/detection/test_defender_rules.py::test_det202_v3_strengthen_or_noop_5007_does_not_alert[DisableBmNetworkSensor = 0x0]` → passed
  - `tests/detection/test_defender_rules.py::test_det202_v3_strengthen_or_noop_5007_does_not_alert[DisableRealtimeMonitoring = 0x]` → passed
  - `tests/detection/test_defender_rules.py::test_det202_v3_strengthen_or_noop_5007_does_not_alert[TamperProtection = 0x1]` → passed
  - `tests/detection/test_defender_rules.py::test_det202_v3_strengthen_or_noop_5007_does_not_alert[disableioavprotection = 0X0]` → passed
  - `tests/detection/test_defender_rules.py::test_det202_v3_records_change_class_in_match` → passed
  - `tests/detection/test_defender_rules.py::test_det202_v2_5001_still_alerts_high` → passed
  - `tests/detection/test_defender_rules.py::test_classify_registry_change[None-None-None]` → passed
  - `tests/detection/test_defender_rules.py::test_classify_registry_change[--None]` → passed
  - `tests/detection/test_defender_rules.py::test_classify_registry_change[HKLM\\X\\Real-Time Protection\\DisableRealtimeMonitoring = 0x0-HKLM\\X\\Real-Time Protection\\DisableRealtimeMonitoring = 0x1-WEAKEN]` → passed
  - `tests/detection/test_defender_rules.py::test_classify_registry_change[HKLM\\X\\DisableAntiSpyware = 1-HKLM\\X\\DisableAntiSpyware = 0-STRENGTHEN]` → passed
  - `tests/detection/test_defender_rules.py::test_classify_registry_change[-HKLM\\X\\DisableAntiSpyware = 0x1-WEAKEN]` → passed
  - `tests/detection/test_defender_rules.py::test_classify_registry_change[-HKLM\\X\\DisableAntiSpyware = 0x0-CHANGE]` → passed
  - `tests/detection/test_defender_rules.py::test_classify_registry_change[HKLM\\X\\DisableAntiSpyware = 0x1-HKLM\\X\\DisableAntiSpyware = 0x2-CHANGE]` → passed
  - `tests/detection/test_defender_rules.py::test_classify_registry_change[HKLM\\X\\DisableFoo = abc-HKLM\\X\\DisableFoo = def-CHANGE]` → passed
  - `tests/detection/test_defender_rules.py::test_classify_registry_change[-HKLM\\X\\Exclusions\\Paths\\C:\\lab = 0x0-WEAKEN]` → passed
  - `tests/detection/test_defender_rules.py::test_classify_registry_change[HKLM\\X\\Exclusions\\Paths\\C:\\lab = 0x0--STRENGTHEN]` → passed
  - `tests/detection/test_defender_rules.py::test_classify_registry_change[HKLM\\X\\Exclusions\\Paths\\C:\\a = 0x0-HKLM\\X\\Exclusions\\Paths\\C:\\b = 0x0-WEAKEN]` → passed
  - `tests/detection/test_defender_rules.py::test_classify_registry_change[HKLM\\X\\Features\\TamperProtection = 0x0-HKLM\\X\\Features\\TamperProtection = 0x1-CHANGE]` → passed
  - `tests/detection/test_defender_rules.py::test_classify_registry_change[HKLM\\X\\Features\\TamperProtection = 0x1-hklm\\x\\features\\tamperprotection = 0X1-NOOP]` → passed
  - `tests/detection/test_defender_rules.py::test_classify_registry_change[HKLM\\X\\Spynet\\SpynetReporting = 0x2-HKLM\\X\\Spynet\\SpynetReporting = 0x0-CHANGE]` → passed
  - `tests/detection/test_defender_rules.py::test_classify_registry_change[khong co dau bang-khong co dau bang 2-CHANGE]` → passed
  - `tests/detection/test_powershell_rules.py::test_det203_match_alert_has_no_script_text` → passed
  - `tests/detection/test_powershell_rules.py::test_benign_block_no_result` → passed
  - `tests/detection/test_powershell_rules.py::test_pattern_split_across_parts_matches_when_block_complete` → passed
  - `tests/detection/test_powershell_rules.py::test_missing_part_no_fake_join_and_partial_coverage` → passed
  - `tests/detection/test_powershell_rules.py::test_late_part_completes_block_and_is_evaluated` → passed
  - `tests/detection/test_powershell_rules.py::test_det204_decodes_utf16_base64_and_det203_does_not_see_it` → passed
  - `tests/detection/test_powershell_rules.py::test_decode_candidates_limits` → passed
  - `tests/detection/test_powershell_rules.py::test_evaluator_uses_gap_and_hashes_clean_text` → passed
  - `tests/detection/test_powershell_rules.py::test_shipped_powershell_rules` → passed
  - `tests/detection/test_powershell_rules.py::test_existing_benign_fixtures_do_not_trigger[ps4104_single.synthetic.xml]` → passed
  - `tests/detection/test_powershell_rules.py::test_existing_benign_fixtures_do_not_trigger[ps4104_three_parts.synthetic.xml]` → passed
  - `tests/api/test_script_redaction.py::test_alert_list_and_detail_never_contain_script` → passed
- **Chưa phủ:** Mọi rule synthetic_only; chưa có số đo FP trên tải lành tính
- **Known limitations:** Dữ liệu synthetic; danh sách mẫu/khóa do người dùng duyệt thay Cyber (w8 mục 12.15-12.16)

### AT-47 · R-01 · mức W · **NOT RUN**

- **Mục tiêu:** Agent đọc ba kênh trên VM, checkpoint riêng; một kênh thiếu quyền không chặn Sysmon
- **Preconditions:** Windows 10 VM, Sysmon chạy, Script Block Logging bật, agent.channels bật ba kênh
- **Steps:** 1. python -m edr_ctl start --config C:\dacn_edr\edr.yaml --live; 2. Xem C:\dacn_edr\agent\health.json (channels) và checkpoint_live_<kênh>.json; 3. Theo docs/implementation/acceptance/W8_DEFENDER_POWERSHELL_VM_GUIDE.md mục 3 (V1), 8 (V6)
- **Expected:** Ba kênh running/idle, errors rỗng, ba checkpoint; dừng/chạy lại không mất sự kiện; kênh thiếu quyền -> degraded, Sysmon vẫn chạy
- **Actual:** Cần Windows 10 VM thật; Claude không chạy được.
- **Known limitations:** Quan sát thủ công 2026-11-28, một VM, một lần (w8 mục 12.11): ba kênh idle, errors rỗng, ba checkpoint; 4104 phát sinh khi dừng (RecordId 914) vào Silver sau khi chạy lại; ledger cân bằng ba kênh. Phần kênh thiếu quyền (degraded) CHƯA chạy trên VM

### AT-48 · R-04 · mức W · **NOT RUN**

- **Mục tiêu:** EICAR -> Defender 1116 -> alert DET-201 -> truy vết raw_xml
- **Preconditions:** Như AT-47; Defender real-time protection bật
- **Steps:** 1. powershell -ExecutionPolicy Bypass -File scripts\lab\dacn_lab_scenarios.ps1 -Scenario SC05 -Eicar (sau -WhatIf); 2. GET /alerts?source=DEFENDER, /alerts/{id}/evidence?include_raw=true, /alerts/{id}/process-links; 3. Theo W8_DEFENDER_POWERSHELL_VM_GUIDE.md mục 6 (V4)
- **Expected:** Một alert DET-201 (1116+1117), source_label Defender, evidence FULL có raw_xml và tham chiếu Bronze
- **Actual:** Cần Windows 10 VM thật; Claude không chạy được.
- **Known limitations:** Quan sát thủ công 2026-11-28, một VM, một lần (w8 mục 12.11): một alert DET-201 với 1116+1117, evidence FULL có raw_xml; FILE_CREATE UNIQUE, PROCESS_NAME_LIFETIME AMBIGUOUS. Bản sửa gom alert (12.12) và DET-202 v3 (12.14) chưa chạy lại trên VM

### AT-49 · R-02 · mức W · **NOT RUN**

- **Mục tiêu:** 4104 thật (một phần và nhiều phần) vào Silver đúng; che bí mật ở API
- **Preconditions:** Như AT-47
- **Steps:** 1. Chạy script lành tính dài và hai dòng thử V3 theo W8_DEFENDER_POWERSHELL_VM_GUIDE.md mục 4-5; 2. python tests\e2e\w8_channel_report.py --silver ... --bronze ... --since <T0>; 3. GET /alerts/{id}/script với viewer và analyst (?reveal=true)
- **Expected:** Block nhiều phần ghép đủ; DET-203/204 MATCH; /script che chuỗi giả theo mặc định; reveal chỉ cho quyền raw và có audit SCRIPT_RAW_VIEW
- **Actual:** Cần Windows 10 VM thật; Claude không chạy được.
- **Known limitations:** Quan sát thủ công 2026-11-28, một VM, một lần (w8 mục 12.11): 554/554 block ghép đủ (33 nhiều phần); 548/554 nối UNIQUE về powershell.exe; /script redacted, viewer reveal 403, analyst reveal có audit. Nút xem bản gốc trên dashboard chưa quan sát

### AT-50 · R-03 · mức L · **PARTIAL**

- **Mục tiêu:** Nạp tập con rule Sigma theo manifest ghim sha256; rule không hỗ trợ bị loại kèm mã SIG-E* và lý do
- **Preconditions:** config/sigma-rules.yaml (mặc định tắt), src/detection/sigma/manifest.yaml (28 rule SigmaHQ @ddf1d4f87fd2)
- **Steps:** 1. PYTHONPATH=src:poc/sysmon-collector python -m detection.sigma list; 2. python -m detection.sigma check <tệp.yml>
- **Expected:** 28 rule nạp được, 0 bị loại; rule sai sha256/logsource/field/modifier/condition/keyword/status bị loại đúng mã; trùng rule_id loại mọi bên; mặc định tắt
- **Actual:** 53 test pytest đạt, 0 lỗi
- **Evidence (pytest node):**
  - `tests/detection/test_sigma_compiler.py::test_equals_case_insensitive_and_wildcards` → passed
  - `tests/detection/test_sigma_compiler.py::test_question_mark_and_escaped_wildcard` → passed
  - `tests/detection/test_sigma_compiler.py::test_contains_startswith_endswith_list_is_or` → passed
  - `tests/detection/test_sigma_compiler.py::test_contains_all_is_and` → passed
  - `tests/detection/test_sigma_compiler.py::test_cased_modifier` → passed
  - `tests/detection/test_sigma_compiler.py::test_regex_search_case_sensitive_unless_i` → passed
  - `tests/detection/test_sigma_compiler.py::test_windash_expands_dash_and_slash_at_word_start` → passed
  - `tests/detection/test_sigma_compiler.py::test_cidr` → passed
  - `tests/detection/test_sigma_compiler.py::test_base64offset_contains_matches_any_alignment` → passed
  - `tests/detection/test_sigma_compiler.py::test_utf16le_base64offset` → passed
  - `tests/detection/test_sigma_compiler.py::test_base64_plain` → passed
  - `tests/detection/test_sigma_compiler.py::test_null_and_exists` → passed
  - `tests/detection/test_sigma_compiler.py::test_numeric_compare_and_int_value_equality` → passed
  - `tests/detection/test_sigma_compiler.py::test_fieldref` → passed
  - `tests/detection/test_sigma_compiler.py::test_condition_and_not_with_explanation` → passed
  - `tests/detection/test_sigma_compiler.py::test_one_of_them_and_parentheses_and_or` → passed
  - `tests/detection/test_sigma_compiler.py::test_missing_field_gives_unknown_with_missing_list` → passed
  - `tests/detection/test_sigma_compiler.py::test_unknown_is_absorbed_by_definite_false` → passed
  - `tests/detection/test_sigma_compiler.py::test_field_not_defined_for_event_type_is_false_not_unknown` → passed
  - `tests/detection/test_sigma_compiler.py::test_rejections[det0-SIG-E004]` → passed
  - `tests/detection/test_sigma_compiler.py::test_rejections[det1-SIG-E004]` → passed
  - `tests/detection/test_sigma_compiler.py::test_rejections[det2-SIG-E004]` → passed
  - `tests/detection/test_sigma_compiler.py::test_rejections[det3-SIG-E005]` → passed
  - `tests/detection/test_sigma_compiler.py::test_rejections[det4-SIG-E005]` → passed
  - `tests/detection/test_sigma_compiler.py::test_rejections[det5-SIG-E005]` → passed
  - `tests/detection/test_sigma_compiler.py::test_rejections[det6-SIG-E005]` → passed
  - `tests/detection/test_sigma_compiler.py::test_rejections[det7-SIG-E005]` → passed
  - `tests/detection/test_sigma_compiler.py::test_rejections[det8-SIG-E006]` → passed
  - `tests/detection/test_sigma_compiler.py::test_rejections[det9-SIG-E003]` → passed
  - `tests/detection/test_sigma_compiler.py::test_rejections[det10-SIG-E010]` → passed
  - `tests/detection/test_sigma_compiler.py::test_rejections[det11-SIG-E010]` → passed
  - `tests/detection/test_sigma_compiler.py::test_unsupported_logsource_rejected` → passed
  - `tests/detection/test_sigma_compiler.py::test_commandline_in_file_event_rejected_not_in_sysmon_event11` → passed
  - `tests/detection/test_sigma_compiler.py::test_windefend_eventids_outside_collected_set_noted` → passed
  - `tests/detection/test_sigma_loader.py::test_packaged_manifest_loads_all_selected_rules` → passed
  - `tests/detection/test_sigma_loader.py::test_level_status_and_mitre_mapping` → passed
  - `tests/detection/test_sigma_loader.py::test_disabled_config_loads_nothing_but_reports` → passed
  - `tests/detection/test_sigma_loader.py::test_default_config_is_disabled` → passed
  - `tests/detection/test_sigma_loader.py::test_config_rejects_unknown_key` → passed
  - `tests/detection/test_sigma_loader.py::test_rules_dir_merge_has_no_collision` → passed
  - `tests/detection/test_sigma_loader.py::test_local_rule_loads` → passed
  - `tests/detection/test_sigma_loader.py::test_sha256_mismatch_rejected` → passed
  - `tests/detection/test_sigma_loader.py::test_id_mismatch_rejected` → passed
  - `tests/detection/test_sigma_loader.py::test_prefix_collision_rejects_both` → passed
  - `tests/detection/test_sigma_loader.py::test_experimental_needs_flag_and_informational_or_deprecated_rejected` → passed
  - `tests/detection/test_sigma_loader.py::test_max_rules` → passed
  - `tests/detection/test_sigma_loader.py::test_unsupported_logsource_and_missing_file` → passed
  - `tests/detection/test_sigma_loader.py::test_multi_document_rejected` → passed
  - `tests/detection/test_sigma_loader.py::test_sha256_ignores_crlf_line_endings` → passed
  - `tests/detection/test_sigma_loader.py::test_manifest_sha_matches_files_in_repo` → passed
  - `tests/detection/test_sigma_cli.py::test_check_supported_prints_manifest_entry` → passed
  - `tests/detection/test_sigma_cli.py::test_check_rejected_has_code` → passed
  - `tests/detection/test_sigma_cli.py::test_list_default_config` → passed
- **Chưa phủ:** Thiết kế Sigma người dùng duyệt thay Cyber (docs/implementation/SIGMA_RULES.md mục 2), chưa review độc lập
- **Known limitations:** Dữ liệu synthetic; độ phủ cú pháp không phải tỷ lệ phát hiện

### AT-51 · R-03 · mức L · **PARTIAL**

- **Mục tiêu:** Rule Sigma chạy trong DetectionEngine, ra DetectionResult -> alert detection_source SIGMA có giải thích và ghi công tác giả; không response
- **Preconditions:** Fixture Silver synthetic có nhãn (tests/detection/test_sigma_engine.py)
- **Steps:** 1. Chạy DetectionEngine với rule DACN + rule Sigma; 2. AlertBuilder; 3. GET /sigma/rules, /alerts?source=SIGMA; 4. Dashboard: nguồn Sigma, khung Rule Sigma
- **Expected:** TP/TN/INSUFFICIENT đúng nhãn; script 4104 không vào kết quả; alert có matched_fields.sigma và attribution.author; nhóm rủi ro SIGMA không cộng thưởng đa dạng với RULE; module Sigma không import response
- **Actual:** 19 test pytest đạt, 0 lỗi
- **Evidence (pytest node):**
  - `tests/detection/test_sigma_engine.py::test_labeled_fixture_outcomes` → passed
  - `tests/detection/test_sigma_engine.py::test_scriptblock_assembled_and_text_not_copied` → passed
  - `tests/detection/test_sigma_engine.py::test_explanation_and_attribution` → passed
  - `tests/detection/test_sigma_engine.py::test_alerts_have_sigma_source_and_gaps_for_insufficient` → passed
  - `tests/detection/test_sigma_engine.py::test_default_rules_have_no_sigma` → passed
  - `tests/detection/test_sigma_engine.py::test_sigma_rule_change_triggers_rescan_without_duplicates` → passed
  - `tests/detection/test_sigma_safety.py::test_sigma_package_never_imports_response_or_exec` → passed
  - `tests/detection/test_sigma_safety.py::test_all_sigma_rules_alert_only` → passed
  - `tests/detection/test_sigma_safety.py::test_validator_rejects_sigma_misuse` → passed
  - `tests/api/test_sigma_api.py::test_sigma_rules_listing_and_detail` → passed
  - `tests/api/test_sigma_api.py::test_sigma_rules_when_disabled_or_absent` → passed
  - `tests/api/test_sigma_api.py::test_alerts_source_filter_sigma` → passed
  - `tests/risk/test_sigma_risk.py::test_config_v3_has_sigma` → passed
  - `tests/risk/test_sigma_risk.py::test_sigma_points_and_cap` → passed
  - `tests/risk/test_sigma_risk.py::test_sigma_and_rule_are_not_independent_for_diversity` → passed
  - `tests/risk/test_sigma_risk.py::test_config_without_sigma_rejected` → passed
  - `tests/risk/test_sigma_risk.py::test_service_maps_sigma_alert_to_sigma_category` → passed
  - `tests/dashboard/test_dashboard_sigma.py::test_dashboard_sigma` → passed
  - `tests/e2e/test_atomic_compare.py::test_sigma_option_reports_sigma_matches_separately_and_keeps_verdicts` → passed
- **Chưa phủ:** Mọi rule Sigma synthetic_only; level chưa hiệu chỉnh cho DACN
- **Known limitations:** Dữ liệu synthetic; chưa đo hiệu năng

### AT-52 · R-03 · mức W · **NOT RUN**

- **Mục tiêu:** Rule Sigma trên Windows 10 VM - nạp đủ sau checkout Windows, so rule khớp DACN và Sigma theo atomic, alert Sigma truy vết tới raw_xml
- **Preconditions:** Windows 10 VM như AT-47; config/sigma-rules.yaml enabled true
- **Steps:** 1. Theo docs/implementation/acceptance/SIGMA_VM_GUIDE.md mục 3-5 (V-S1..V-S3); 2. python tests\e2e\atomic_compare.py ... --sigma
- **Expected:** 28 loaded, 0 rejected; báo cáo atomic_compare có mục so sánh DACN và Sigma; alert Sigma có khung Rule Sigma và evidence FULL
- **Actual:** Cần Windows 10 VM thật; Claude không chạy được.
- **Known limitations:** CHƯA chạy trên VM
