# EDR — Báo cáo nghiệm thu (sinh tự động)

> Sinh bởi `scripts/acceptance/run_acceptance.py`; **không chỉnh tay**. Trạng thái suy ra từ kết quả pytest.
> Mức bằng chứng `L` = Linux + dữ liệu synthetic/giả lập, **không thay cho kiểm chứng trên Windows VM**.

## Môi trường chạy

- Thời điểm (UTC): 2026-11-08T13:24:32Z · thời lượng: 25.8 s
- Commit: `00d5645` (cây làm việc có thay đổi chưa commit)
- Python 3.13.18 · Linux 6.18.44-fc-v310
- Thư viện: pytest 9.2.0, duckdb 2.0.0, fastapi 0.162.2, uvicorn 0.54.0, httpx 0.28.1, pydantic 2.13.5, PyYAML 6.0.3, jsonschema 4.26.0
- Mức bằng chứng: L (Linux, dữ liệu synthetic/giả lập); W (Windows) chưa chạy

## Tổng hợp

| Trạng thái | Số AT |
|---|---|
| PASS | 25 |
| PARTIAL | 4 |
| FAIL | 0 |
| NOT RUN | 14 |

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
- **Steps:** 1. python -m agent --live; 2. Sinh sự kiện (mở notepad); 3. wevtutil qe ... /f:xml so với raw_xml trong Bronze
- **Expected:** raw_xml trong Bronze trùng EventRecordID/nội dung với wevtutil
- **Actual:** Cần Windows 10 VM thật; Claude không chạy được.
- **Known limitations:** Một VM, một phiên bản Sysmon

### AT-04 · R-01 · mức W · **NOT RUN**

- **Mục tiêu:** Không có quyền đọc channel -> lỗi C-006 rõ ràng
- **Preconditions:** Windows, chạy agent bằng tài khoản không có quyền
- **Steps:** 1. Chạy agent --live bằng user thường; 2. Xem bronze/errors/collector_errors.jsonl
- **Expected:** Mã lỗi C-006, agent không crash âm thầm
- **Actual:** Cần Windows 10 VM thật; Claude không chạy được.
- **Known limitations:** Phần logic ánh xạ lỗi đã có test Linux (test_access_denied_maps_to_c006) nhưng đó không phải bằng chứng trên Windows

### AT-05 · R-01 · mức W · **NOT RUN**

- **Mục tiêu:** Kill agent giữa chừng trên Windows -> phục hồi
- **Preconditions:** Windows VM, agent live đang chạy
- **Steps:** 1. taskkill /F agent; 2. Khởi động lại; 3. Kiểm tra recover và không mất sự kiện
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
- **Steps:** 1. Chạy dacn_lab_scenarios.ps1 SC01-SC04; 2. python tests/e2e/compare_expected.py
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
- **Preconditions:** VM, người dùng bật execute_unlocked và mode execute
- **Steps:** 1. Chạy tiến trình marker; 2. Duyệt terminate; 3. Kiểm tra Task Manager và audit
- **Expected:** Tiến trình bị kết thúc; audit trước/sau đủ
- **Actual:** Cần Windows 10 VM thật; Claude không chạy được.
- **Known limitations:** Chỉ tiến trình thử nghiệm

### AT-26 · R-05 · mức W · **NOT RUN**

- **Mục tiêu:** Quarantine tệp thử nghiệm rồi restore, hash khớp
- **Preconditions:** VM, tệp trong thư mục lab
- **Steps:** 1. Duyệt quarantine; 2. Restore; 3. So sha256
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

### AT-31 · R-07 · mức L · **PARTIAL**

- **Mục tiêu:** Trạng thái loading/lỗi/rỗng
- **Preconditions:** như AT-30
- **Steps:** 1. Token sai -> trạng thái lỗi; 2. Bộ lọc không có kết quả -> trạng thái rỗng
- **Expected:** Có trạng thái lỗi (role=alert), rỗng và loading
- **Actual:** 1 test pytest đạt, 0 lỗi
- **Evidence (pytest node):**
  - `tests/dashboard/test_dashboard_ui.py::test_dashboard_ui_checks` → passed
- **Chưa phủ:** Test UI hiện kiểm tra trạng thái lỗi và rỗng; trạng thái loading chưa có kiểm tra tự động riêng

### AT-32 · R-07 · mức L · **PARTIAL**

- **Mục tiêu:** Chi tiết alert hiển thị nguồn bằng chứng + kết quả response
- **Preconditions:** như AT-30
- **Steps:** 1. Mở chi tiết alert
- **Expected:** Hiển thị đường dẫn bằng chứng và trạng thái hành động response
- **Actual:** 1 test pytest đạt, 0 lỗi
- **Evidence (pytest node):**
  - `tests/dashboard/test_dashboard_ui.py::test_dashboard_ui_checks` → passed
- **Chưa phủ:** Chưa kiểm tra tự động rằng màn chi tiết alert hiển thị kết quả response; cần xác nhận bằng ảnh chụp/ngắm thủ công

### AT-33 · R-07 · mức W · **NOT RUN**

- **Mục tiêu:** Dashboard trên VM hiển thị cảnh báo thật của SC-01
- **Preconditions:** Hệ thống chạy trên VM
- **Steps:** 1. Chạy SC-01; 2. Mở /ui
- **Expected:** Alert DET-001 hiển thị với bằng chứng
- **Actual:** Cần Windows 10 VM thật; Claude không chạy được.

### AT-34 · R-08 · mức W · **NOT RUN**

- **Mục tiêu:** edr_ctl start/status/stop khởi động/dừng sạch, không tiến trình mồ côi trên Windows
- **Preconditions:** Windows VM
- **Steps:** 1. edr_ctl start/status/stop; 2. Kiểm tra tasklist
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
- **Steps:** 1. SC-03; 2. SC-08
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
- **Actual:** 46 liên kết tương đối đã kiểm tra; hỏng: không
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

### AT-43 · R-12 · mức L · **PARTIAL**

- **Mục tiêu:** Tắt ML = hành vi không đổi; detector giả hoạt động
- **Preconditions:** Repo
- **Steps:** 1. Chạy test ML interface
- **Expected:** ML tắt mặc định, không kích hoạt response
- **Actual:** 1 test pytest đạt, 0 lỗi
- **Evidence (pytest node):**
  - `tests/detection/test_rules_harness.py::test_ml_off_by_default_and_never_triggers_response` → passed
- **Chưa phủ:** Chưa có test cho detector giả bật ML ngoài việc kiểm tra tắt mặc định
- **Known limitations:** Chưa có mô hình ML thật
