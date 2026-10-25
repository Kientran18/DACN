# W04 Cyber — Ma trận 13 MITRE techniques × 5 công cụ

**Issue #20** · Ngày 25/10/2026 · Scope: 13/13 techniques từ [W02](../../../scope/selected_mitre_techniques_v1.md), kiểm tra tính khả dụng của nguồn theo [W03](../w3/detection_feasibility_notes_v1.md) và [gaps](../w3/telemetry_gap_list_v1.md).

**Cách đọc:** `S` = Sysmon source/field theo event config; `W` = Wazuh rules hoặc ingest Sysmon; `O` = osquery query/enrichment; `V` = Velociraptor VQL/artifact; `A` = Atomic Red Team test case *nếu có atom phù hợp và an toàn*. Các ký hiệu là **khả năng khảo sát qua tài liệu**, không phải chứng nhận hoạt động hay coverage theo phần trăm. `[X]` = chỉ có mẫu sự kiện loại đó trong repo. `[G]` = thiếu kiểm thử của kỹ thuật/điều kiện hoặc thiếu telemetry. W/O/V/A **chưa được chạy thực nghiệm**.

| Technique (ưu tiên) | Dấu hiệu, DET | Sysmon + Windows: nguồn / giới hạn | Wazuh | osquery | Velociraptor | Atomic Red Team | Tình trạng W03 |
|---|---|---|---|---|---|---|---|
| **T1204.002** Malicious File | file user executes, DET-010 | S: 11→1, 29; không chứng minh user click | W: correlate event rules | O: process/file metadata | V: timeline/process artifacts | A: chọn atom benign execution | [X] có tạo/chạy mẫu; [G] chưa có click/MotW |
| **T1059.001** PowerShell | suspicious command/parent, DET-001 | S: 1 command line, parent GUID; Windows 4104 bổ sung | W: command-line rule | O: process query; short-lived gap | V: hunt command line | A: atom PowerShell an toàn | [X] process; [G] chưa có encoded/Office chain |
| **T1059.003** CMD | cmd/parent chain, DET-002 | S: 1; command line,parent | W: process rules | O: process state | V: process/command hunt | A: benign CMD atom | [X] activity; [G] cần ID1 CMD rõ ràng |
| **T1218** Binary proxy execution | LOLBin pattern | S: 1; 7 ImageLoad chỉ nếu bật | W: LOLBin rules | O: command/loaded-module tables tùy source | V: binaries/process artifacts | A: chọn atom proxy non-invasive | [G] chưa kiểm chứng proxy execution |
| **T1547.001** Run/Startup | registry persistence, DET-003 | S: 12/13 + 11; HKU↔HKCU correlation | W: registry/FIM rules | O: startup_items/registry query | V: autorun artifacts | A: temporary HKCU key, cleanup | [X] registry test; [G] chưa có Run key thật |
| **T1053.005** Scheduled Task | schtasks/create, DET-004 | S: 1 + Windows Security 4698/4702, TaskScheduler/TaskCache | W: eventchannel rules | O: scheduled_tasks on supported OS | V: scheduled-task artifacts | A: benign scheduled task; cleanup | [G] audit/task sample chưa có |
| **T1562.001** Disable Tools | agent stop/tamper, DET-007 | S: 5/4/16 + System service logs + watchdog | W: service/config checks and alerts | O: services/process state | V: agent/service artifacts | A: **không chạy destructive tamper** tại M1 | [X] Event 5/4/16; [G] không chứng minh tamper |
| **T1082** System Discovery | whoami/hostname, DET-009 | S: 1 (CLI); source API cần bổ sung | W: cmd process rules | O: OS facts query | V: host inventory artifacts | A: benign inventory | [G] thiếu event chain đầy đủ |
| **T1083** File/Dir Discovery | dir/tree commands, DET-009 | S: 1 cho CLI; không có full API enumeration | W: process rules | O: file inventory query | V: filesystem artifacts | A: benign directory listing | [G] chưa có enumeration sample |
| **T1105** Ingress Tool Transfer | DNS/network→file, DET-005 | S: 3/22 + 11/29 + 1; theo GUID/time/path | W: correlated rules | O: sockets/files snapshots | V: downloaded file artifacts | A: **chỉ local test file**, tránh remote payload | [X] nguồn từng loại; [G] chưa có cùng download chain |
| **T1071.001** Web Protocols | C2-like beacon, DET-006 | S: 3/22 metadata, không có payload/định danh C2 | W: network/IOC rules | O: connection state | V: connection/network artifacts | A: benign outbound request, không C2 thật | [X] DNS+TCP; [G] chưa kiểm chứng beacon |
| **T1070.004** File Deletion | drop→execute→delete, DET-010 | S: 26 + 11/1 (hoặc Event 23 nếu cấu hình) | W: FIM/correlation | O: file snapshot/diff tùy scan | V: file timeline | A: delete **temp file do lab tạo** | [X] chuỗi PoC; [G] chưa đo detection |
| **T1486** Data Encrypted for Impact | ransomware-like, DET-008 | S: 11/26 chỉ proxy create/delete, không phải write/entropy chứng minh encrypt | W: FIM/rules cần custom | O: file changes polling hạn chế | V: artifacts/timeline và entropy bằng chứng | A: **không chạy mã hóa hàng loạt** | [G] rất yếu, thiếu write/rename/entropy |

## Cách diễn giải năng lực

1. Nguồn dữ liệu có mặt **không đồng nghĩa** detect đúng hành vi, MITRE detection coverage, giảm false positive hay phản ứng thành công.
2. Wazuh cần decoder/rule và source bật đúng; một MITRE ID trong rule metadata không xác nhận độ chính xác.
3. osquery snapshot có blind spots; evented tables phụ thuộc platform/cấu hình. Velociraptor artifacts thường mang tính hunt/triage theo truy vấn, không tự là detector luôn bật. Atomic Red Team test catalog không chứng minh detector đạt kỹ thuật.
4. Detection nên dựa correlation theo `hostname`, `process_guid`, timestamp được xác minh, cùng path/hash theo sự kiện phù hợp; `EventID 22 DNS` không bắt buộc fields `DestinationIp/Port`.
5. Các kịch bản chưa có trong mẫu W03 được đánh [G], không ghi PASS. Từ W10 mới nên chạy test matrix có expected vs observed, labelled benign/attack-like, precision/FPR.

## Minh chứng và dẫn nguồn

Mẫu W03: `references/samples/raw/raw_process_create_event1.xml`, `raw_file_create_event11.xml`, `raw_registry_setvalue_event13.xml`, `raw_network_connect_event3.xml`, `raw_dns_query_event22.xml`, `raw_file_delete_event26.xml`. Manifest: `references/samples/raw/export_manifest.json`. Các nguồn chính thức cho năm công cụ và MITRE liệt kê trong [Báo cáo đánh giá](01-bao-cao-danh-gia-nang-luc-bao-mat.md); ma trận này dựa trên cùng bộ nguồn và phân loại bằng chứng.
