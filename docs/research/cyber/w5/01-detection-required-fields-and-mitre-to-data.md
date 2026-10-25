# W05 Cyber — Detection-required Fields & MITRE-to-Data Mapping v1

**Issue:** [#28](https://github.com/Kientran18/DACN/issues/28) · **Ngày đối chiếu:** 25/10/2026 · **Trạng thái:** bản Cyber để Data và Software xác nhận; **chưa hiện thực Detection Engine**.

## 1. Nguồn đối chiếu và mức độ chứng minh

Cơ sở: [Threat Model](../../../architecture/threat_model_v1.md), [13 MITRE techniques](../../../scope/selected_mitre_techniques_v1.md), [W03 feasibility](../w3/detection_feasibility_notes_v1.md), [W03 gaps](../w3/telemetry_gap_list_v1.md), [W04 MITRE matrix](../w4/02-ma-tran-cong-cu-mitre-w4.md), [W05 Data contract](../../../architecture/w5/data_pipeline_architecture_and_contracts_v1.md), [Schema v1.1](../../../architecture/w5/schema_reconciliation_and_dictionary_v1_1.md) và [W05 Software Bronze contract](../../software/w5/01-collector-to-bronze-interface-contract-v1.md).

Bằng chứng lab: [manifest Sysmon](../../../../references/samples/raw/export_manifest.json) xác nhận Sysmon 15.22, mẫu raw ID 1/3/5/11/12/13/22/26/29/4/16; JSON normalized cho ID 1/3/11/13. **Đã có một event type không có nghĩa đã nhận diện thành công một kỹ thuật tấn công.** Chưa có tập kiểm thử rule positive/negative chính thức hoặc thống kê precision/FPR.

**Ký hiệu:** C = trường cần cho *rule candidate* (thiếu thì rule không được kết luận match đáng tin, **không đồng nghĩa NOT NULL trên mọi hàng Silver**); O = tùy chọn/enrichment; U = thiếu hoặc không chứng minh được bằng nguồn hiện có.

## 2. Ma trận 13/13 techniques

| MITRE | Rule/observable | Trường C / nguồn yêu cầu | O | U / rủi ro | Tình trạng mẫu |
|---|---|---|---|---|---|
| **T1204.002** User Execution: Malicious File | DET-010, file được chạy | ID11 `TargetFilename`; ID1 `Image,ProcessGuid,ParentProcessGuid`; host/time/path | hash, ID29 | Không có bằng chứng user click hoặc file malicious | Có 11,1; chưa có user action |
| **T1059.001** PowerShell | DET-001 | ID1 `Image,CommandLine,ProcessGuid,ParentProcessGuid` | ParentImage, hash, User | Chưa có PowerShell 4104; parent/flag đơn lẻ không chứng minh tấn công | Có ID1 |
| **T1059.003** Windows Command Shell | DET-002 | ID1 `Image,CommandLine,ParentProcessGuid` + ancestor join | ParentImage, User | Có thể thiếu ancestor khi collector khởi động muộn | Có ID1, chưa chứng minh CMD abuse |
| **T1218** System Binary Proxy Execution | LOLBin candidate | ID1 `Image,CommandLine,ParentProcessGuid` + điều kiện proxy command | hash, signer, ID7 | ID7 chưa có; không kết luận proxy chỉ theo Image | Thiếu kịch bản |
| **T1547.001** Run Keys/Startup | DET-003 | ID13 `TargetObject,Details,ProcessGuid`; HKU/SID mapping | ID12, User, Image | Chưa có mẫu Run/RunOnce thật; Event13 ở key khác | Có 13 lab |
| **T1053.005** Scheduled Task | DET-004 | ID1 schtasks command **hoặc** Security 4698/4702 cho xác nhận task | TaskScheduler log | Chưa thu audit 4698/4702 | Thiếu |
| **T1562.001** Disable/Modify Tools | DET-007 | Heartbeat độc lập + service/audit status + actor/time | Sysmon ID5,4,16 | 5/4/16 một mình không chứng minh tamper | Có ID5/4/16 nhưng không chứng minh tamper |
| **T1082** System Information Discovery | DET-009 | ID1 Image/CommandLine/ProcessGuid khi phát qua CLI | command ancestry | API discovery không được Sysmon 1 ghi trực tiếp | Chưa có labelled test |
| **T1083** File/Directory Discovery | DET-009 | ID1 Image/CommandLine với dir/tree CLI | file activity | Không có full file enumeration qua API | Chưa có labelled test |
| **T1105** Ingress Tool Transfer | DET-005 | ID3/22 network/DNS + ID11/29 file + ID1 execution; host/GUID/time/path | hash, DNS result | Gần thời gian không đồng nghĩa download/có cùng remote source | Chưa có chain transfer được xác minh |
| **T1071.001** Web Protocol C2 | DET-006 | ID3 `DestinationIp,DestinationPort,Protocol,ProcessGuid` + time; ID22 QueryName nếu có | frequency, DNS results, allowlist | Thiếu HTTP/SNI/payload; TCP 443 không tự là C2 | Có 3/22, chưa có beacon test |
| **T1070.004** File Deletion | DET-010 | ID11 path → ID1 Image → ID26/23 TargetFilename theo host/time | hash, actor lineage | ID26 phụ thuộc Sysmon filter; benign cleanup vẫn tạo chuỗi | Có raw 11→1→26 |
| **T1486** Data Encrypted for Impact | DET-008 | Cần telemetry write/rename/entropy/biến đổi nội dung thực tế để kết luận mã hóa | ID11/26 counts | Sysmon 11/26 không phải full write monitor: **không đủ detection T1486** | GAP P1 |

## 3. Contract tối thiểu để W06 viết DET-001..010

| Rule | Must-have cho điều kiện match | Nếu thiếu |
|---|---|---|
| DET-001 | ID1 command line + image + actor/parent context | `INSUFFICIENT_TELEMETRY`, không coi benign |
| DET-002 | ID1 process tree bằng `(hostname,process_guid,parent_guid)` | Flag `PARTIAL_ANCESTRY` |
| DET-003 | ID13 `TargetObject,Details` + normalize HKU/HKCU | Không kết luận Run persistence |
| DET-004 | ID1 schtasks hoặc Security task audit; phân biệt execution candidate và task confirmed | No audit ⇒ confidence thấp |
| DET-005 | Có các event network + file cùng process/ancestor/time | Nếu correlation không đầy đủ ⇒ hypothesis |
| DET-006 | Series ID3/22 có timestamp, process, dest/domain | Không kết luận C2 theo port |
| DET-007 | Independent heartbeat/service audit để xác nhận agent tamper | Sysmon 5 chỉ ghi terminate |
| DET-008 | Nguồn file write/rename/entropy phù hợp | Mark rule blocked, chỉ ghi suspicious file activity |
| DET-009 | ID1 cmd line / ancestry / window | Không extrapolate API discovery |
| DET-010 | ID11 create + ID1 execute + ID26 delete, cùng normalized path/host/window | Missing step ⇒ partial chain |

Các rule trên là **thiết kế W06**, không phải trạng thái đã thử nghiệm.

## 4. Trường bắt buộc theo tầng — *không ép mọi loại event như nhau*

| Tầng | Critical cho Cyber | Quy tắc khi thiếu |
|---|---|---|
| Collector → Bronze | Raw XML hoặc raw reference **bất biến**, `Computer,Channel,EventRecordID,EventID,TimeCreated`, source/schema/collector version, segment/line/checksum | Dữ liệu lỗi phải được lưu lại và báo gap; không tạo default giả |
| Silver (mọi loại được hỗ trợ) | `event_id,hostname,channel,record_id,source,sysmon_event_id,event_type,timestamp,raw_data` và truy xuất được raw origin | Thiếu natural key/timestamp: quarantine + health signal |
| Process ID1 | `ProcessGuid,Image,ProcessId`; parent fields cho lineage theo đặc tả ID1 | Thiếu parent không dựng cây giả |
| Process ID5 | `ProcessGuid,Image,ProcessId`; **không** yêu cầu ParentProcessGuid/CommandLine | NULL hợp lệ; nối Event1 cũ nếu có |
| File ID11/26/29 | `TargetFilename` và ProcessGuid khi nguồn có; phân biệt 11/26/29; hash chỉ khi event cung cấp | NULL hash không phải lỗi toàn bộ |
| Registry 12/13/14 | `TargetObject,EventType`; `Details` khi cần DET-003 | Không kết luận persistent startup từ key không liên quan |
| Network ID3 | `ProcessGuid,DestinationIp,DestinationPort,Protocol` cùng host/time, source fields theo event | Không suy ra ứng dụng/web content |
| DNS ID22 | `ProcessGuid,QueryName`, QueryResults nếu có; **không** yêu cầu socket src/dest IP/port | Cho phép NULL socket |
| Feature → Alert | `source_event_ids[],rule_id,rule_version,contributing_event_ids[],confidence/severity_reason` và raw refs; `missing_fields/coverage_status` (đề xuất) | Không sinh auto-response khi lineage mất |

**Lưu ý:** \`process_guid\` không có trong Sysmon state/config event ID4/16; ID3/22 có \`EventData.UtcTime\` chênh ~12 giây so với \`System.TimeCreated.SystemTime\` trong mẫu W3. Thống nhất trục `timestamp` = SystemTime theo ADR 0006, giữ event UTC time riêng; không nối DNS như socket.

## 5. Nguyên tắc correlation để tránh false positives

- **Process:** join bằng `(hostname,process_guid)` và `(hostname,parent_guid)`, không dùng PID một mình; parent của ID5 có thể lấy từ Event1 đã lưu, nếu thiếu phải ghi incomplete.
- **File:** normalize path case-insensitive / quotes, giữ path gốc ở raw. Actor tạo file, process chạy file, actor xóa file không nhất thiết cùng GUID.
- **DNS:** join theo host/GUID/time và DNS IP tập hợp khi phù hợp, chấp nhận cached DNS/multi-IP/IPv4-mapped IPv6; không tạo socket fields cho Event22.
- **Windows time:** timestamp nguồn chính theo SystemTime; có detection-time watermark/lateness, đồng thời giữ ingest time và raw string.
- **Scoring:** MITRE tag, port 443, Powershell flag, sự kiện một lần không tự cho phép severity Critical. Rule cần matched fields, missing fields và phản ví dụ benign.

Tài liệu kèm theo: [Alert traceability](02-alert-to-source-traceability-requirements.md), [Schema/security review](03-security-review-schema-quality-retention.md), [Gap backlog](04-telemetry-gaps-and-w06-w09-backlog.md).
