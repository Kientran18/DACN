# W04 Cyber — Báo cáo đánh giá năng lực bảo mật của 5 công cụ

**Issue:** #20 · **Ngày đánh giá:** 25/10/2026 · **Trạng thái:** Cyber hoàn thành bản nghiên cứu, **chờ Data và Software review**.  
**Phạm vi:** nghiên cứu/thiết kế Phase 1 trên một Windows endpoint, chưa phải chứng nhận sản phẩm hoặc thử nghiệm so sánh hiệu năng.

## 1. Phương pháp, đầu vào và mức độ bằng chứng

Đầu vào nội bộ: [Threat Model v1](../../../architecture/threat_model_v1.md), [13 MITRE techniques](../../../scope/selected_mitre_techniques_v1.md), [feasibility DET-001..010](../w3/detection_feasibility_notes_v1.md), [telemetry gap list](../w3/telemetry_gap_list_v1.md), [Sysmon samples](../../../../references/samples/raw/), [Software W4](../../software/w4/01-bao-cao-danh-gia-kien-truc-cong-cu.md), [Data W4](../../data/w4/open_source_edr_tools_data_model_survey.md).

Quy ước: **[R]** khả năng ghi trong tài liệu nhà phát triển; **[X]** loại event/field đã có mẫu XML/JSON thực tế trong repo ngày 18/10; **[D]** đề xuất thiết kế chưa triển khai; **[G]** khoảng trống/điều kiện cần kiểm chứng. [X] chỉ áp dụng cho **Sysmon + hoạt động collector đã có mẫu**, KHÔNG khẳng định rule detection hoặc hành vi ATT&CK đã được phát hiện; cũng không chứng minh triển khai Wazuh, osquery, Velociraptor hay Atomic Red Team. Không có benchmark CPU/RAM, false-positive-rate, coverage độc lập hoặc kiểm thử response.

Tài liệu chính thức tham khảo ngày 25/10/2026 (đường dẫn theo phiên bản/current nên nội dung có thể thay đổi):
- Sysmon: https://learn.microsoft.com/en-us/sysinternals/downloads/sysmon ; mô tả event: https://learn.microsoft.com/en-us/sysinternals/downloads/sysmon#events
- Wazuh: https://documentation.wazuh.com/current/user-manual/capabilities/index.html ; rules: https://documentation.wazuh.com/current/user-manual/ruleset/rules/index.html ; active response: https://documentation.wazuh.com/current/user-manual/capabilities/active-response/index.html
- osquery: https://osquery.readthedocs.io/en/stable/ ; schema: https://osquery.io/schema/ ; evented tables: https://osquery.readthedocs.io/en/stable/deployment/process-auditing/
- Velociraptor: https://docs.velociraptor.app/ ; artifacts: https://docs.velociraptor.app/docs/artifacts/ ; VQL: https://docs.velociraptor.app/docs/vql/
- Atomic Red Team: https://github.com/redcanaryco/atomic-red-team ; Invoke-AtomicRedTeam: https://github.com/redcanaryco/invoke-atomicredteam
- MITRE ATT&CK techniques: https://attack.mitre.org/techniques/

**Phiên bản:** mẫu lab xác nhận Sysmon **15.22** theo `references/samples/raw/export_manifest.json`. Software W4 khảo sát Sysmon 15.22, Wazuh 4.14.9, osquery 5.23.1, Velociraptor 0.77.3; Data W4 có phiên bản khảo sát khác (Sysmon 15.15, Wazuh 4.9.x, osquery 5.13.x, Velociraptor 0.72.x). Các phiên bản này là **mốc tham chiếu từ tài liệu đồng đội**, không được diễn giải là đã kiểm chứng chạy trên cùng lab; cần đồng bộ baseline trước M1. Atomic Red Team là tập test và công cụ chạy kịch bản, không phải EDR sensor.

## 2. Bảng so sánh cùng tiêu chí

Ký hiệu: **Có** = có chức năng theo tài liệu; **Phụ thuộc** = cần nguồn dữ liệu/cấu hình hoặc module khác; **Không** = không phải chức năng chính; không phải thang điểm chất lượng.

| Công cụ/vai trò | Telemetry | Detection | Investigation | Hunting | Response | MITRE ATT&CK | Phù hợp Phase 1 |
|---|---|---|---|---|---|---|---|
| **Sysmon** — sensor ghi Event Log | Có, process/file/registry/network/DNS theo Event ID và cấu hình [R,X] | Không có rule engine; cần viết DET [R] | Cung cấp ProcessGuid, parent và context [X] | Qua query Event Log/collector [D] | Không phải response engine [R] | Event fields có thể ánh xạ ATT&CK; KHÔNG tự nhận diện technique [D] | **Sử dụng**, nguồn chính |
| **Wazuh** — agent + manager/rule engine | Agent thu thập log Sysmon/Windows, FIM (khả năng tùy cấu hình) [R] | Rules/decoders, correlation và alert [R] | Alert timeline/agent context [R] | Search/hunting trên indexer/dashboard [R] | Active response theo rule, cần kiểm soát quyền [R] | MITRE mapping ở rule metadata, không chứng minh độ phủ tự động [R] | **Tham khảo**, không triển khai stack server trong Phase 1 |
| **osquery** — SQL trên trạng thái/hệ điều hành | Snapshot/differential và một số evented tables tùy OS/config [R] | Scheduled query/packs tạo tín hiệu, không tự thay DET engine [R] | Truy vấn tiến trình, autoruns, services, sockets [R] | SQL hunt, snapshots [R] | Không phải response engine tổng quát [R] | Cần mapping query→technique thủ công [D] | **Tham khảo**, enrichment/hunt ideas |
| **Velociraptor** — DFIR/hunting | Artifacts, event monitoring/client collection theo triển khai [R] | Hunt/artifact-based detections và queries [R] | Thu thập bằng chứng, timeline/forensics [R] | VQL + artifacts/hunts [R] | Có khả năng tác vụ điều tra/response qua client, nhạy quyền [R] | Artifact/technique mapping cần cấu hình và kiểm chứng [D] | **Tham khảo**, tránh thêm server/client |
| **Atomic Red Team** — kiểm thử hành vi | **Không** là telemetry collector | **Không** tạo alert; sinh hành vi để kiểm thử rule | Metadata test hỗ trợ ground truth [R] | Không phải hunt engine | Không phải response engine | Tests được gắn ATT&CK technique, coverage test ≠ coverage detection [R] | **Sử dụng có kiểm soát** cho lab/labeling |

Không nên so sánh năm công cụ như năm phương án thay thế 1:1: Sysmon là nguồn sự kiện; Wazuh là SIEM/XDR, osquery là query framework, Velociraptor là DFIR platform, Atomic là test library.

## 3. Đánh giá từng công cụ và trường hợp sử dụng

### 3.1 Sysmon — **Adopt, sensor chính**
- **[X]** Mẫu ngày 18/10 có Event 1 (process), 11/26/29 (file), 12/13 (registry), 3 (network), 22 (DNS) và 4/5/16, có `ProcessGuid`, `ParentProcessGuid` khi event hỗ trợ; collector chuyển đổi sang JSON. Tham chiếu `export_manifest.json` và các XML tương ứng.
- **[D]** DET-001/002 dựa process tree/command line; DET-003 registry persistence; DET-005/006 phối hợp network/DNS/file; DET-010 drop→execute→delete.
- **[G]** Event 11 không tương đương mọi lần write/rename; chưa có file-encryption telemetry đảm bảo T1486. Event 3/22 chỉ có metadata, không chứng minh C2. Event 5 không xác nhận tác nhân đã kill process; thiếu service watchdog, scheduled task audit 4698/4702, PowerShell 4104, các Event 7/14/15. Bộ lọc Sysmon ảnh hưởng độ phủ, phải xác minh nguồn và version cấu hình thực tế.

### 3.2 Wazuh — **Reference-only**
- **[R]** Tham khảo cấu trúc decoder/rule, điều kiện tương quan, severity, MITRE tagging, alert context, active response và audit trail. Đọc Sysmon qua Windows eventchannel nếu bật; FIM là bổ sung, không đồng nghĩa Sysmon native process lineage.
- **[D]** Tái sử dụng ý tưởng `rule_id`, `mitre_technique_id`, `matched_fields`, `severity`, `response_audit` cho detection/alert model W6.
- **[G]** Triển khai manager/indexer/dashboard tăng phụ thuộc vận hành trái phạm vi single-endpoint. Chưa cài/chạy/đo RAM và CPU; không gán kết quả đo giả định.

### 3.3 osquery — **Reference-only**
- **[R]** SQL query tables `processes`, `process_open_sockets`, `services`, `startup_items`, scheduled/differential queries; một số evented sources có thể cần audit/extension/cấu hình riêng, không được giả định mọi endpoint đều hỗ trợ.
- **[D]** Tái sử dụng mẫu hunt SQL cho process ancestry, autoruns, service changes và IOC lookup trong Silver DuckDB. Dùng snapshot làm enrichment khi thiếu thuộc tính.
- **[G]** Snapshot polling bỏ sót hoạt động ngắn hạn; process PID không thay được Sysmon ProcessGuid cho correlation. Không dùng osquery làm sensor chính tại M1.

### 3.4 Velociraptor — **Reference-only**
- **[R]** Artifact-based collection, VQL truy vấn và liên kết evidence; phù hợp hậu điều tra, triage, timeline và phản hồi có giám sát.
- **[D]** Học cấu trúc artifact versioning, provenance, read-only hunt, evidence bundles, collection manifest và playbook điều tra.
- **[G]** Client/server, quyền cao và artifact execution là bề mặt cần kiểm soát; chưa xác nhận độ phủ event hoặc chi phí trên lab.

### 3.5 Atomic Red Team — **Adopt as controlled test tooling**
- **[R]** Các YAML atomics chứa technique ID, executor, input args, dependencies, cleanup (nếu định nghĩa); Invoke-AtomicRedTeam hỗ trợ chọn test.
- **[D]** Chọn subset benign/non-destructive theo #20, tạo `test_run_id`, `technique_id`, `atomic_test_guid`, khoảng thời gian, host, expected Event IDs, stdout/status và `cleanup_status`; gắn nhãn evidence bằng host/process GUID/time-window có kiểm chứng, không label tất cả log cùng thời gian là tấn công.
- **[G]** Chưa chạy Atomic Red Team trong lab trong bộ bằng chứng W1–W4; không tuyên bố test coverage/detection efficacy.

## 4. Kết luận Cyber và điều kiện triển khai

**Đề xuất:** Adopt Sysmon cho process/file/registry/network telemetry; adopt Atomic Red Team **chỉ trong lab** làm nguồn kịch bản/ground truth; tham khảo Wazuh, osquery, Velociraptor, **không nhúng toàn bộ** vào Phase 1. Đồng hướng với Data ADR 0004 và Software W4, **chưa thay chữ ký/biên bản đồng thuận**. Bất kỳ thay đổi nào cần review chéo và ADR.

**Các ưu tiên W5–W10:** giữ raw XML, host/process GUID, Event ID thực và nguồn thời gian; kiểm tra mapping per Event ID (DNS Event 22 khác socket Event 3), đóng telemetry gaps theo kế hoạch; làm detector positive/negative tests và response chỉ khi có xác nhận người vận hành. Không công bố detection accuracy hay tỷ lệ CPU/RAM trước benchmark.

Đối chiếu đầy đủ 13 technique: [Ma trận riêng](02-ma-tran-cong-cu-mitre-w4.md). Tái sử dụng, gap và lab: [Ghi chú an toàn/ứng dụng](03-detection-hunting-response-va-ke-hoach-test.md). Review: [Hồ sơ bàn giao](04-ban-giao-review-w4-cyber.md).
