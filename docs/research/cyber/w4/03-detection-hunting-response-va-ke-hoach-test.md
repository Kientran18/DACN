# W04 Cyber — Ý tưởng DET/Hunt/Response, khoảng trống và kế hoạch Atomic Red Team an toàn

**Issue:** #20 · **Status:** đề xuất thiết kế, chưa triển khai/benchmark. Căn cứ W03: [detection feasibility](../w3/detection_feasibility_notes_v1.md), [telemetry gaps](../w3/telemetry_gap_list_v1.md), [behavior mapping](../w3/behavior_to_telemetry_mapping_v1.md).

## 1. Ý tưởng tái sử dụng theo nguồn

| Nguồn tham khảo | Rule/detection | Hunt/investigation | Response/playbook | Điều kiện |
|---|---|---|---|---|
| Sysmon | ProcessGuid lineage, Event 1/3/11/12/13/22/26 | Trace process tree, file path/hash, network DNS timeline | Không thực thi response; chuyển evidence vào engine riêng | Cấu hình lọc đúng, giữ raw XML, xác nhận timestamp |
| Wazuh | Decoder/rule-ID, severity, suppression, MITRE-tag | Alert timeline, condition correlation | Active-response-inspired **approval + allowlist + audit + rollback**, không copy script thực thi | Test false positive và quyền; không cài Wazuh manager |
| osquery | SQL scheduled query/packs | Hunt autoruns, services, processes, sockets; DuckDB SQL views | Chỉ enrichment/read-only ở P1 | Snapshot stale; không tương đương live event |
| Velociraptor | Artifact definitions và provenance | Artifact collection, timeline, incident bundles | Học quy trình triage/thu bằng chứng với confirmation | Không gọi arbitrary command trên endpoint |
| Atomic Red Team | Test metadata/expected Event IDs | Gắn label test_run và điều tra event trong window | Cleanup chỉ thay đổi do test tạo, trước/sau test | VM snapshot, người duyệt, kiểm tra prerequisites |

### Thiết kế rule/query (không tuyên bố đã chạy)

- **DET-001:** `Event 1 + Image PowerShell + suspicious parent/flags`; benign control: administrator scripts; lưu evidence command line, parent GUID, image, record ID.
- **DET-003:** `Event 13 TargetObject Run/RunOnce` và path writable bất thường; benign control: installer/login application; normalize HKCU/HKU SID.
- **DET-004:** `schtasks /create` Event 1 kết hợp Security 4698/4702; ghi rõ nếu nguồn audit chưa bật.
- **DET-005/006:** 3/22 và process lineage, đếm theo window, rarity và DNS correlation; benign control: software update, browser browsing; không gán nhãn C2 dựa 443.
- **DET-007:** cần heartbeat độc lập và Windows Service events; Event 5/4/16 riêng lẻ không đủ khẳng định bị kill/tamper.
- **DET-008:** không dùng Event 11 làm đếm file writes. Muốn phân biệt encryption phải bổ sung write/rename/content entropy hoặc nguồn EDR khác và benign bulk file test.
- **DET-010:** `Event 11 → 1 → 26` cùng normalized path/host/time và hash nếu có; benign control: installer/update; định nghĩa cửa sổ từ time source đã xác thực.

Ví dụ hunt bằng SQL tương lai (minh họa logic, tên cột/bảng cần đồng bộ với schema v1.1, **không phải truy vấn đã thực thi**):

```sql
-- Pseudocode: trace correlated events for a candidate process GUID
SELECT event_time, event_type, process_guid, raw_data
FROM normalized_endpoint_events
WHERE host_id = :host_id AND process_guid = :process_guid
ORDER BY event_time;
```

Alert contract đề xuất W6: `alert_id, rule_id, rule_version, technique_ids, severity, confidence, evidence_event_ids, process_guid, host_id, window_start/end, missing_fields, analyst_decision, response_status`. Không tự gọi terminate/quarantine từ rule thử nghiệm; response phải có gate và audit.

## 2. Các gap cần chuyển giao

| ID | Mức | Rủi ro/chứng cứ thiếu | Owner đề xuất | Công việc sau W4 |
|---|---|---|---|---|
| SEC-W4-01 | P1 | File write/rename/full coverage thiếu cho T1486 | Software + Cyber | Khảo sát bổ sung ETW/USN/event source; không claim ransomware detect |
| SEC-W4-02 | P1 | Scheduled-task 4698/4702 chưa thu | Software | Điều chỉnh audit policy + benign task test |
| SEC-W4-03 | P1 | Agent health/tamper chưa có watchdog độc lập | Software + Cyber | Thiết kế heartbeat, service status, audit trail |
| SEC-W4-04 | P1 | Windows Sysmon 3/22 timestamp chênh | Software + Data | Kiểm tra semantics TimeCreated vs UtcTime |
| SEC-W4-05 | P1 | DNS Event22 và Event5 nullability chưa phù hợp mọi schema | Data | Nullable field theo EventID, riêng DNS view |
| SEC-W4-06 | P1 | Mẫu gốc `sanitized:false` chứa thông tin máy lab | Team | Sanitize artifact public và rà soát commit history |
| SEC-W4-07 | P1 | Review chính thức chưa có; PR #23 chưa merge | Team | Review bằng PR/comments, reconciliation và nghiệm thu M1 |
| SEC-W4-08 | P2 | Event7,14,15, PowerShell4104, HTTP metadata thiếu | Software/Cyber | Ưu tiên theo 13 techniques và chi phí event-volume |
| SEC-W4-09 | P1 | Detection chưa có test dương/âm hay FPR | Cyber/Data | W10 labelled test matrix và benchmark |

## 3. Quy trình Atomic Red Team **đề xuất**, không thực thi tại W4

1. **Chuẩn bị:** Windows VM cô lập, snapshot/restore được kiểm tra, tài khoản không phải admin trừ test được duyệt riêng, audit Sysmon bật, cấu hình hash và logging theo W3; tránh máy thật và dữ liệu thật.
2. **Duyệt test:** map từng `technique_id` với `atomic_test_guid` cụ thể, xem kỹ source YAML, `executor`, `input_arguments`, `dependencies` và `cleanup_command` trước khi chạy. Không tự động chạy cả technique khi chưa duyệt từng atomic.
3. **Whitelist danh mục kịch bản vô hại:** PowerShell/CMD thông thường T1059.001/.003; `whoami`/host inventory T1082; liệt kê thư mục test T1083; tạo registry Run trong HKCU test và xóa ngay T1547.001; tạo scheduled task vô hại chỉ khi audit/cleanup đầy đủ T1053.005; tạo/xóa file tạm T1070.004. Không chạy test có network download lạ, persistence ngoài lab, security agent tampering, mã hóa hàng loạt, xóa dữ liệu người dùng.
4. **Theo dõi:** lưu `test_run_id`, atomic GUID/version/commit, host, timezone, timestamp UTC trước/sau, operator, permissions, expected events, observed EventRecordIDs, process GUID, execution status, cleanup status. Đảm bảo baseline benign trước/sau và nhiều mẫu negative.
5. **Cleanup và rollback:** thực thi cleanup *đã review*, kiểm tra xóa khóa/task/file chỉ do lab tạo; nếu cleanup thất bại restore snapshot. Không coi cleanup có sẵn trong YAML là mặc nhiên an toàn.
6. **Nghiệm thu:** so sánh expected↔observed telemetry; ghi missing event & false positives; chưa bật response tự động. Ghi nhãn những event có correlation, không gán nhãn toàn bộ cửa sổ.

**Ràng buộc:** M1 yêu cầu khảo sát test tooling, không yêu cầu chạy Atomic; triển khai và demo theo kế hoạch W10. Dẫn nguồn: [Atomic Red Team](https://github.com/redcanaryco/atomic-red-team), [Invoke-AtomicRedTeam](https://github.com/redcanaryco/invoke-atomicredteam), [MITRE](https://attack.mitre.org/).
