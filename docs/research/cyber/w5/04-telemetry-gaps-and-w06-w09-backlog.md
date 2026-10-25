# W05 Cyber — Telemetry Gap / Data Risk Notes & W06/W09 Backlog

**Issue:** [#28](https://github.com/Kientran18/DACN/issues/28) · **Mục tiêu:** ưu tiên những chỗ dữ liệu cản detection và investigation; không coi đây là issue phần mềm đã triển khai.

## 1. Backlog tổng hợp

| ID | Mức | Vấn đề | Tác động tới rule/điều tra | Owner đề xuất | Công việc/đầu ra |
|---|---|---|---|---|---|
| W5-CY-01 | **P0** | Chưa có W05 canonical Bronze schema nhất quán Data vs Software | Mọi DET & replay | Data + Software | Chốt JSON/JSONL contract, field adapter, version, golden sample; link vào #26 |
| W5-CY-02 | **P0** | Chưa có raw_ref bất biến trên từng Silver event / alert → XML | Investigation, forensic proof | Data + Software | Segment/line/sha & ingest/mapping version trong Silver; test TRACE-01 |
| W5-CY-03 | **P0** | Event-specific nullability ID5/22 và ID4/16 | False reject, DET-001/006/007 | Data | Conditional validation + positive/negative cases |
| W5-CY-04 | **P0** | Thiếu detection coverage field và no-data semantics | False negative/positive DET-001..010 | Cyber + Data | `INSUFFICIENT_TELEMETRY`, `PARTIAL_ANCESTRY`, reason fields trong alert contract W06 |
| W5-CY-05 | **P1** | Thiếu file write/rename/entropy đủ tin cậy | T1486/DET-008 | Cyber + Software | Khảo sát event/ETW/USN và giới hạn, không claim ransomware detection |
| W5-CY-06 | **P1** | Chưa thu scheduled task Security 4698/4702 | T1053.005/DET-004 | Software | Bật audit theo lab được duyệt và thu positive benign |
| W5-CY-07 | **P1** | Không có agent watchdog/heartbeat độc lập | T1562.001/DET-007 | Software + Cyber | Health events, System Service audit, tamper-state model |
| W5-CY-08 | **P1** | Timestamp chênh SystemTime/UtcTime ~12s | Correlation windows, lineage | Data + Software | Time skew quality metrics, lateness policy, watermark/re-evaluate |
| W5-CY-09 | **P1** | Chưa đồng bộ schema v1.1, cột DNS/29 và field naming với validator & contract checker | DET-005/006, provenance | Data + Software | Kiểm bằng XML thật 3/22/5/26/29 và 4 JSON; migration/adapter |
| W5-CY-10 | **P1** | UUIDv5 va chạm khi EventRecordID reset/host rename | Evidence identity & replay | Data + Software | Persist log epoch, conflict handling, tests reset/replay |
| W5-CY-11 | **P1** | Chưa giữ retention hold cho alert/incident | Truy vết W09 | Data + Cyber | Evidence-hold & RAW_EXPIRED semantics |
| W5-CY-12 | **P1** | Mẫu raw public `sanitized:false` | Privacy, credential leaks | Team + Software | Sanitize bản chia sẻ và rà soát commit history; giữ bản nội bộ bảo toàn chứng cứ |
| W5-CY-13 | **P2** | Thiếu PowerShell 4104, Sysmon7/14/15 & HTTP metadata | T1059.001/T1218/T1071.001 | Software + Cyber | Ưu tiên nguồn theo rule, cấu hình/volume test |
| W5-CY-14 | **P1** | Chưa có labelled detection validation/false-positive measurements | 13 MITRE, DET-001..010 | Cyber + Data | Test matrix W10 benign/atomic-safe, expected vs observed |
| W5-CY-15 | **P1** | Thiếu review chứng thực giữa Cyber/Data/Software; Data báo APPROVED, Software còn DRAFT | Chặn #26 nghiệm thu | Team | Biên bản/PR links, các quyết định một nguồn chính thức |

## 2. Phân chia đầu vào W06 và W09

**W06 Detection Engine thiết kế**
- Chốt source rule fields từ [01 mapping](01-detection-required-fields-and-mitre-to-data.md): DET-001..010, event combinations, thresholds chỉ là hypothesis trước khi có benign/attack-like labelled tests.
- Rule metadata `rule_id,rule_version,mitre_technique_ids,category,severity,confidence,evidence_event_ids,window_start/end,missing_fields,coverage_status`; không nâng Critical từ 1 event lẻ.
- Rule state `MATCH / NO_MATCH / INSUFFICIENT_TELEMETRY / PENDING_LATE_EVENTS`. Missing data **không đồng nghĩa NO_MATCH**.
- Tăng cường telemetry đúng chỗ: task audit cho DET-004; independent agent health DET-007; file-write source DET-008; process tree lineage; DNS/IP correlation.
- Alert traceability thiết kế trong [02](02-alert-to-source-traceability-requirements.md).

**W09 Investigation/Hunting/Response thiết kế**
- Query process tree theo GUID/host, incident timeline theo SystemTime/source-order và thông tin time skew.
- Từ alert link tới từng Silver event, raw/XML reference + hash; giữ nguồn đã hết TTL ở dạng có provenance và flag.
- Hunting filter process/file/registry/network/DNS, raw event vs inferred field, confidence & completeness.
- Response phải cần approval/allowlist/audit, chưa tự động khi evidence chain chưa hoàn chỉnh.

## 3. Test evidence hiện có và cần bổ sung

**Có trong repository:** raw W03 Event 1/3/5/11/12/13/22/26/29/4/16; JSON normalized riêng Event 1/3/11/13; evidence PoC benign với host/marker. Các file XML có thể có nhiều record; phải dẫn đúng `EventRecordID`. Raw DNS ID22 ở `raw_dns_query_event22.xml` là **record 196**; một ví dụ Data W05 dùng record 193 cho synthetic edge case, **không phải raw record trên file đó**.

**Chưa có bằng chứng:** chạy detector thật với 13 ATT&CK, response, query investigation Gold→Bronze end-to-end; benchmark đầy đủ W10; Python collector live mode chạy trên Windows với bookmark; Data/Software review đã ký nhận #28. Không tự đổi trạng thái các mục này sang DONE.

## 4. Checklist bàn giao #28 và #26

- [x] Đối chiếu 13/13 MITRE cùng DET-001..010 với các nhóm Process/File/Registry/Network/DNS.
- [x] Đánh dấu critical / optional / unavailable và rủi ro thiếu field.
- [x] Review hợp đồng Bronze–Silver, schema v1.1, quality, retention và raw lineage.
- [x] Có ví dụ truy vết dựa trên EventRecordID, ProcessGuid và raw W03, không bịa cảnh báo.
- [x] Đã phân công **owner đề xuất** & backlog ưu tiên W06/W09.
- [ ] Data xác nhận adapter/Bronze contract/provenance, schema/quality tests.
- [ ] Software xác nhận raw XML/collector interface/Windows feasibility.
- [ ] Team #26 ghi biên bản thống nhất chính thức.

**Nguồn:** [W03 telemetry gaps](../w3/telemetry_gap_list_v1.md), [W04 MITRE matrix](../w4/02-ma-tran-cong-cu-mitre-w4.md), [W05 Data](../../../architecture/w5/), [W05 Software](../../software/w5/).
