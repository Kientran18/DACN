# DACN — Local EDR Reference Architecture v2.0

> **Trạng thái: PROPOSAL / FOR REVIEW** — 04/11/2026. Tài liệu kiến trúc mục tiêu, **không phải mô tả các tính năng đã triển khai**.
>
> **Phạm vi:** 01 Windows 10/11 endpoint, triển khai local-first, agent user-space, không yêu cầu server quản trị tập trung. Kế thừa W01–W05; hướng dẫn hiện thực W06+.
>
> **Tham chiếu chính:** [EDR/XDR Architecture and Operations](https://github.com/Richardmsbr/cybersecurity-architecture/blob/main/defensive-security/edr-xdr.md); [NIST SP 800-61r3](https://csrc.nist.gov/pubs/sp/800/61/r3/final); [Microsoft Sysmon](https://learn.microsoft.com/sysinternals/downloads/sysmon); [MITRE Detection Strategies](https://attack.mitre.org/detectionstrategies/); [OCSF](https://ocsf.io/).
>
> **Sơ đồ riêng:** [EDR v2 diagrams](../../diagrams/edr-v2-architecture.md). **ADR:** [ADR 0007](../decisions/0007_local_edr_modular_architecture.md).

## 1. Tóm tắt quyết định

DACN cần chuyển từ sơ đồ tuyến tính "Collector → Normalization → Detection → Alert → Response" sang **modular local EDR** với ba nhóm:

1. **Data plane:** telemetry collection → durable raw/Bronze → validation/quarantine → Silver → enrich/features → detection → alert/incident → investigation.
2. **Control plane:** versioned rule/config, policy, allowlist, approval, access control, signed updates theo khả năng hiện thực.
3. **Operations & trust:** health/watchdog, checkpoint/replay, audit, privacy/retention, response safety, recovery, đo hiệu năng trên VM.

**Không triển khai XDR tập trung** (network/cloud/email/identity connectors, multi-tenant SOC, SOAR, cloud HA) trong Phase 1. Dành giao diện extension cho tương lai, không dựng các dịch vụ giả.

**Định hướng triển khai:** ưu tiên *modular monolith*, các module Python chạy cùng host, giao tiếp bằng hàm/thông điệp nội bộ và file JSONL đã niêm phong, sử dụng DuckDB/Parquet như ADR 0005. Tránh Kafka, Elasticsearch cluster, Kubernetes và cloud services trong VM đồ án.

## 2. So sánh kiến trúc gốc và v2

| Câu hỏi kiến trúc | Gốc W01 | Yêu cầu v2 | Lý do |
| --- | --- | --- | --- |
| Dữ liệu lấy từ đâu? | Event Collection chung | Sysmon chính; Windows Event Log bổ sung có chọn lọc; ETW/WMI để sau | Độ phủ telemetry có giới hạn theo nguồn |
| Mất dữ liệu xử lý ra sao? | Chưa thể hiện | Collector checkpoints, bounded queue, sealed JSONL segments, manifest/checksum, replay | Đứt pipeline không được mất bằng chứng âm thầm |
| Sự kiện lỗi thế nào? | Normalization đơn lẻ | Conditional validator, Quarantine DLQ, data-quality metrics | Giảm false negative do schema sai |
| Phát hiện cái gì? | 03 kiểu detection | IOC/hash + single-event rule + multi-event correlation; AI adapter tùy chọn | Phân định thực thi và năng lực mở rộng |
| Thiếu telemetry thì sao? | Chưa thể hiện | MATCH / NO_MATCH / INSUFFICIENT_TELEMETRY / PENDING_LATE_EVENTS | Thiếu dữ liệu không phải benign |
| Điều tra bằng gì? | Timeline/Process Tree là output | Event/alert/raw bi-directional provenance; timeline, GUID tree, hunt queries | Phân biệt bằng chứng với suy đoán |
| Phản ứng như thế nào? | Terminate/Quarantine/Block | Policy gate, xác nhận người dùng, verify target, audit, recovery | Tránh hành động phá hỏng máy do false positive |
| Agent tự bảo vệ? | Chưa thể hiện | Heartbeat, exception metrics, integrity checks, independent watchdog là kế hoạch | Giám sát gián đoạn, chưa nhận là tamper-resistant |
| Vận hành và quản lý? | Chưa thể hiện | Rule/config lifecycle, data retention, backpressure, health, rollback | Hỗ trợ bảo trì và demo có thể lặp lại |

## 3. Ranh giới và kiến trúc logic

**Phạm vi tin cậy A — Windows host và OS:** Sysmon driver/service ghi vào Event Log, có thể thêm Security/System logs theo quyền hợp lệ. Sensor không tự cung cấp detection hay response.

**Phạm vi tin cậy B — Local EDR runtime:** Collector (ưu tiên quyền chỉ đọc log), durable spool, pipeline processor, detection evaluator, alert writer, investigation API. Chỉ *Response Executor* được cấp quyền nhạy cảm khi thực sự cần.

**Phạm vi tin cậy C — Operator/UI:** giao diện/CLI ở localhost theo role, tách read-only analyst và privileged approver; không tự bật remote terminal. Không chấp nhận cấu hình/rule từ request không xác thực.

~~~mermaid
flowchart TB
  subgraph HOST["WINDOWS ENDPOINT — Phase 1 (local-first)"]
    subgraph SENS["1. TELEMETRY SOURCES"]
      S1["Sysmon Event Log<br/>Process / File / Registry / Network / DNS"]
      S2["Windows Security/System<br/>(optional, gated)"]
      S3["ETW / WMI enrichment<br/>(future spike)"]
    end
    subgraph ACQ["2. ACQUISITION & DURABILITY"]
      C["Collector Service<br/>source adapters + bookmark"]
      Q["Bounded Buffer<br/>backpressure / health"]
      B["Immutable Bronze JSONL<br/>sealed segment + manifest + hash"]
      CP["Checkpoint / Replay Ledger"]
    end
    subgraph PIPE["3. DATA ENGINEERING"]
      V["Validation + Conditional Schema<br/>Dedup / Quality"]
      DLQ["Quarantine / DLQ"]
      SI["Silver DuckDB<br/>Process / File / Registry / Network-DNS"]
      EN["Context Enrichment<br/>Process graph / known-good / features"]
    end
    subgraph DET["4. DETECTION & DECISIONS"]
      R1["Signature / IOC / Hash matcher"]
      R2["Versioned Rule Engine"]
      R3["Temporal Correlator<br/>GUID / host / window"]
      ML["AI anomaly scorer<br/>(optional, later)"]
      E["Detection Evaluation<br/>coverage + evidence + confidence"]
    end
    subgraph SOC["5. ANALYST WORKFLOW"]
      A["Alert Manager<br/>dedup / severity / case links"]
      G["Gold / Alert Store"]
      I["Investigation + Hunting<br/>timeline / process tree / raw trace"]
      UI["Local UI / CLI<br/>read-only views"]
    end
    subgraph RESP["6. CONTROLLED RESPONSE"]
      P["Policy / Allowlist / Approval Gate"]
      RX["Privileged Response Executor<br/>terminate / quarantine / block"]
      AU["Action Audit + Recovery Metadata"]
    end
    subgraph OPS["CROSS-CUTTING / CONTROL PLANE"]
      CFG["Config & Rule Registry<br/>version / validation / rollback"]
      H["Health / Telemetry Gap Monitor<br/>metrics / heartbeat / disk"]
      SEC["NTFS ACL / Least Privilege<br/>retention / privacy / integrity"]
    end
  end
  S1 --> C
  S2 -.-> C
  S3 -.-> C
  C --> Q --> B --> V
  CP <--> C
  CP <--> B
  V -->|valid| SI
  V -->|invalid| DLQ
  DLQ -.->|authorized replay| V
  SI --> EN
  SI --> R1
  SI --> R2
  EN --> R3
  EN -.-> ML
  R1 --> E
  R2 --> E
  R3 --> E
  ML -.-> E
  E --> A --> G --> I --> UI
  A --> P
  P -->|manual approval only| RX --> AU
  AU --> G
  CFG -.-> R2
  CFG -.-> P
  H -.-> C
  H -.-> V
  H -.-> E
  SEC -.-> B
  SEC -.-> G
~~~

Ghi chú: đường liền chỉ luồng xử lý dự kiến; đường chấm chỉ tích hợp tùy chọn, quản trị hoặc chưa hiện thực. **Sơ đồ là target architecture, không phải runtime đã hoạt động.**

## 4. Hợp đồng và trách nhiệm từng thành phần

| Module / owner đề xuất | Input | Output | Trách nhiệm chính | Tình trạng hiện có |
| --- | --- | --- | --- | --- |
| Sysmon Adapter / Software | Event Log XML, Security/System sau | parsed event, metadata | Đọc event, không tự suy đoán threat | XML + Collector file-mode PoC, live-mode có code chưa xác nhận chạy ổn định |
| Collector Runtime / Software | event stream | Bronze record / health | Bookmark, retry, backpressure, batching | **Chưa có** service liên tục + checkpoint bền vững |
| Bronze Writer / Software | XML + source identifiers | canonical JSONL + manifest | Append/rotate/atomic seal, checksum, raw retention | Contract code + synthetic examples, **chưa có** sealed segment writer end-to-end |
| Validation & DLQ / Data | Bronze/adapter input | Silver event hoặc lỗi | Event-specific rules, dedup, quality, replay | W05 validator PoC, không phải daemon/ETL hoàn chỉnh |
| Silver Store / Data | valid events | normalized tables | Một writer quản lý DuckDB, versioned schema/migration | 04 bảng và SQL schema là thiết kế; PoC DuckDB in-memory |
| Enrichment & Feature / Data | Silver rows | process lineage, aggregate windows | GUID join, per-host time windows, optional signatures | SQL/feature design; chưa chứng minh pipeline live |
| Detection / Cyber | Silver/events/features + rules | DetectionResult | IOC, rule matching, temporal correlation, missing-data semantics | DET-001..010 **đặc tả**, chưa có engine hoạt động |
| Alert Manager / Cyber+Data | DetectionResult | alert/incident | severity rationale, dedup, case state, raw evidence refs | Gold schema **thiết kế**, không có end-to-end alert engine |
| Investigation / Cyber+Software | alert, Silver, raw refs | timeline/tree/hunt | Audit, query, evidence integrity, partial coverage | Yêu cầu thiết kế W05; UI chưa triển khai |
| Response / Software+Cyber | approved action | audited result | Approval, target identity, safe execution, recovery | **Chưa triển khai**, mặc định disabled |
| Config + Monitoring / Software | policy/rules, counters | rule revisions, health alerts | ACL, signature/hash verification, service health, disk budgets | Đề xuất mới, chưa triển khai |

**Phân chia trách nhiệm:** Cyber định nghĩa điều kiện detection, alert/risk policy và kịch bản kiểm thử; Data sở hữu Bronze→Silver, schema, evidence lineage và feature/query; Software sở hữu log reader, collector lifecycle, OS API, packaging, UI/response executor. Bất kỳ giao diện chéo nào đều cần 03 bên review.

## 5. Data plane: nguồn và chất lượng telemetry

### 5.1. Nguồn hiện tại / nguồn sẽ bổ sung

- **Hiện có bằng chứng W03:** Sysmon ID 1/3/5/11/12/13/22/26/29 và state/config 4/16; 04 file JSON normalized chủ yếu ID 1/3/11/13. Bộ mẫu chủ yếu hoạt động benign; "có loại event" không có nghĩa có attack detection.
- **Ưu tiên bổ sung sau:** Windows Security task 4698/4702 nếu được bật audit đúng; service status/health; PowerShell 4104 khi cân đối privacy/volume.
- **Nghiên cứu/không mặc định có:** ETW/USN file write/rename, full HTTP/SNI/payload, Process Access, Sysmon ImageLoad/driver events. Không suy ra ransomware hoặc C2 chỉ từ Sysmon 11/26 hay port 443.
- **Context enrichment:** signer/hash/known-good reputation, username/SID và event grouping phải versioned và có timestamp; không tự gọi external threat feed khi chưa có quyền/đường mạng.

### 5.2. Ingestion durable và checkpoint

1. Đọc event theo channel bằng bookmark/record key khi hiện thực, không xem chế độ đọc "newest 20" PoC là continuous subscription.
2. Serialize **canonical bronze-event/1.0** theo [W05 proposal](w5/contracts/README.md), giữ nguyên raw_xml + event_data + thông tin nguồn; không phát sinh thêm Bronze schema v1.1 song song.
3. Ghi vào tệp .part trong data/bronze, fsync/flush phù hợp Windows, niêm phong segment bằng rename nguyên tử + manifest SHA-256. Consumer chỉ đọc segment sealed.
4. Ghi commit ledger/checkpoint sau khi segment sealed bền vững, tránh bỏ qua event sau crash. Nếu đọc lại, dedup/replay phải idempotent.
5. Đo backlog, disk remaining, dropped/skipped event, parse errors, ingestion latency. Khi quá ngưỡng: cảnh báo telemetry gap và áp dụng backpressure có giới hạn; không âm thầm bỏ qua record.
6. Recovery phải phân biệt crash trước/sau seal, manifest hỏng, record duplicate, Event Log cleared/reset và source time lệch.

**P0 unresolved:** UUIDv5(hostname|channel|EventRecordID) hiện có rủi ro va chạm khi reset Event Log. Đề xuất thêm **channel_epoch / log_instance** vào identity v2 có migration/crosswalk, nhưng **không lặng lẽ thay đổi event_id legacy** trước review Data/Software và test replay. Giữ source key và event_id cũ trong lineage cho dữ liệu W03.

### 5.3. Bronze → Silver → Feature/Gold

- Validation theo **event-specific required fields**. ID5 không có parent; DNS22 không có src/dest socket tuple; ID4/16 không có ProcessGuid và phải được xử lý health-event riêng hoặc có schema phù hợp. Không tự tạo default giả.
- Silver giữ hostname, channel, record_id, event_id, sysmon_event_id, source timestamp, ingest timestamp, raw provenance, GUID/path/hash khi có. Normalize case của path để join nhưng phải giữ original raw.
- Data cần bổ sung một provenance record/columns bền vững: bronze_segment_id, line/offset, content_hash, schema_version, mapper_version, ingest_run_id, channel_epoch. **bronze_source** trong adapter hiện chỉ là metadata PoC, chưa thành physical Silver lineage được chứng minh.
- Correlation clock = System.TimeCreated.SystemTime; giữ EventData.UtcTime riêng; ghi nhận skew, late events và watermark. Dữ liệu W03 có sự kiện mạng/DNS lệch timestamp đáng kể; correlation window không thể tự nhận là chính xác theo 5 giây.
- Gold lưu features/alerts với danh sách source_event_ids và raw refs; dùng immutable evidence trail/retention hold khi mở incident.
- **DuckDB là embedded analytical store**, nên tránh UI và collector cùng trực tiếp ghi. Pipeline single-writer; UI truy vấn read-only qua service/snapshot, cân nhắc SQLite chỉ cho low-volume state/config/approval nếu cần, không coi đó là đổi ADR 0005.
- Quarantine DLQ tách collector errors, schema errors, corrupt segments; lưu mã lỗi, source_ref, payload/hash, retry count, human review. Tái xử lý có phiên bản, không sửa raw bất biến.

### 5.4. Schema theo chuẩn bên ngoài

OCSF có thể dùng làm **mapping tham khảo** để tương thích tương lai. Trong Phase 1 **giữ schema v1.1 của DACN**, không thay toàn bộ Bronze/Silver bằng OCSF/ECS làm vỡ hợp đồng W05. Nếu sau này xuất OCSF, thêm export adapter và unit tests riêng.

## 6. Detection plane

### 6.1. Ba năng lực ưu tiên

1. **IOC/Signature (MVP):** hash SHA-256 / known-good / allowlist, bản ghi có signature source/version; YARA chỉ cân nhắc nếu có thư viện/permissions/test rõ.
2. **Event rules (W06):** process creation + command line, registry Run, task creation candidate, suspicious path/parent. Rule metadata, evidence, MITRE technique, error/no-data semantics.
3. **Behavior correlation (W06–W08):** nhiều sự kiện theo (hostname,process_guid,parent_guid,path), window, lateness, process tree, DNS↔network, drop→execute→delete. Chống trùng alert/correlation state cần replay-safe.

**AI anomaly scoring** chỉ dùng khi có dữ liệu và nhãn/biện pháp đánh giá, đặt sau rule engine; không dùng AI thay thế raw evidence hoặc tự kích hoạt response.

### 6.2. Rule contract đề xuất

~~~yaml
rule_id: DACN-DET-010
legacy_id: DET-010
rule_version: "1.0.0"
title: Drop Execute Delete Candidate
mitre_technique_ids: [T1070.004]
category: behavioral_correlation
event_types: [FILE_CREATE, PROCESS_START, FILE_DELETE]
required_fields:
  FILE_CREATE: [hostname, timestamp, file_path]
  PROCESS_START: [hostname, timestamp, image_path, process_guid]
  FILE_DELETE: [hostname, timestamp, file_path]
correlation_keys: [hostname, normalized_file_path]
time_window: TBD_AFTER_LABELLED_TESTS
severity: medium
response_policy: alert_only
~~~

Ví dụ trên là **contract nháp**, không phải rule đã chạy. Chỉ gọi MATCH khi đủ evidence; đánh dấu partial khi thiếu Event 26. **Rule IDs nội bộ** đã dùng DET-001..010; MITRE ATT&CK hiện cũng dùng mã "DETxxxx" cho *Detection Strategies* nên khuyến nghị external ID có namespace **DACN-DET-001..010**, và giữ legacy_id để tương thích tài liệu cũ. Phải phân biệt **MITRE Technique Txxxx** và **MITRE Detection Strategy DETxxxx**.

### 6.3. Evaluation contract

Một DetectionResult nên chứa:
- evaluation_id, rule_id/version, event_time/window, hostname, process_guid nếu có.
- outcome: **MATCH | NO_MATCH | INSUFFICIENT_TELEMETRY | PENDING_LATE_EVENTS**.
- matched_fields, missing_fields, coverage_status, contributing_event_ids[], bronze_raw_references[], matched_indicators[], analysis_notes.
- severity, reason và optional confidence_score, **chỉ chấm điểm nếu đã định nghĩa cách hiệu chỉnh**.

Alert Manager nhận DetectionResult theo policy, áp dụng dedup/grouping (rule_id + host + process/subject + bounded window), lưu suppression reason/version và analyst override; không được gộp thành một alert khi sự kiện khác actor/host.

**Điều kiện bất biến:** evidence ID phải resolve được về record trong Silver/Bronze hoặc báo PARTIAL/RAW_EXPIRED; tuyệt đối không tạo GUID/hash/IP giả để làm rule pass.

## 7. Analyst workflow, điều tra và phản ứng

### 7.1. Incident / Investigation

~~~mermaid
flowchart LR
  A[Detection result] --> B[Alert triage]
  B --> C[Incident / case]
  C --> D[Process Tree]
  C --> E[Timeline + query]
  C --> F[Evidence trace]
  F --> G[Silver event]
  G --> H[Bronze segment]
  H --> I[Original Sysmon XML]
  C --> J{Containment needed?}
  J -->|No| K[Monitor / close with reason]
  J -->|Yes| L[Approval and safety gate]
  L --> M[Response executor]
  M --> N[Audit / recovery]
~~~

- Basic hunting: filter host/time, process/parent GUID, path, hash, registry key, DNS, dest IP/port của ID3, rule/severity, missing-data/quarantine; query lineage/graph được ưu tiên hơn UI phức tạp.
- Triage lifecycle: NEW → TRIAGED → INVESTIGATING → (FALSE_POSITIVE | CONFIRMED | CLOSED), có reviewer/timestamp và notes; không ghi "confirmed attack" khi chỉ có một trường trùng chỉ báo.
- Investigation UI hiển thị **observed facts**, **inferred relations**, **missing data**, phân biệt bằng mắt; mở raw XML theo quyền chỉ đọc có audit.

### 7.2. Response safety-by-default

- **MVP mặc định alert-only.** Không tự terminate, cô lập host hoặc xóa file chỉ vì mức "Critical" hay khớp một rule đơn.
- Actions Phase 1 dự kiến: terminate process có kiểm tra PID + creation time/process GUID và signer/allowlist; quarantine bằng copy/rename có lưu hash/ACL/metadata và khả năng restore; block hash là policy của ứng dụng (không tuyên bố chặn toàn hệ điều hành nếu chưa có enforcement hook).
- Gating: rule confidence & evidence completeness; protected process/path allowlist; authorized approval; anti-TOCTOU revalidation; dry run; structured audit (actor, reason, target identity, outcome, rollback pointer). Fail closed khi không đủ quyền hay raw reference.
- Không cung cấp remote live shell, tự động cắt mạng hay tắt dịch vụ trên Windows endpoint trong phạm vi đầu tiên. Những hành động này rủi ro làm mất kết nối, hỏng dữ liệu/OS và không có rollback tin cậy.
- Tham khảo **NIST SP 800-61r3** cho Detect/Respond/Recover và cải tiến liên tục; không nhầm thuật toán detection với chính sách incident response.

## 8. Control plane, operations, privacy

### 8.1. Rule/config lifecycle

Cấu hình đề xuất: collector.yaml, pipeline.yaml, detection/rules/*.yaml, response-policy.yaml (chỉ là tên tương lai). Validation schema + signed release hoặc checksum manifest, version và reviewer; atomic config change và rollback sau lỗi. Không cho UI analyst sửa rule ở chế độ production.

### 8.2. Service health / reliability

Metrics: last_sysmon_event_at, last_collector_read_at, last_bronze_seal_at, checkpoint_lag, queue_depth, disk_free, DLQ_count, duplicate_rate, validation_fail_by_code, rule_latency p50/p95, late_event_rate, time_skew, rule_version, response_failures, raw_ref_resolution_rate.

Health alert **khác** threat alert. Mất heartbeat chỉ chứng minh visibility gap; muốn tuyên bố tampering cần watchdog độc lập hoặc system/service audit có bằng chứng.

Failure drills: dừng ingestor trong lúc collector hoạt động; restart giữa tệp .part; thay đổi cấu hình; mất ổ đĩa/thiếu dung lượng; hỏng JSON; DNS22 thiếu socket; ID5 thiếu parent; late Event26; log reset và reprocessing. Mỗi test lưu expected vs observed.

### 8.3. Bảo vệ dữ liệu

- NTFS least privilege: Bronze và evidence chỉ service/operator được quyền; UI chỉ đọc output đã lọc; response executor tách quyền. Sensitive log query/export cần audit.
- Raw XML có thể chứa username, SID, file paths, command-line secrets. **Mẫu W03 hiện được đánh dấu sanitized:false**: không tái sử dụng trực tiếp trong slide/public export nếu chưa rà soát.
- Retention phải dựa dung lượng VM và rủi ro điều tra, có quota theo tầng, policy khi đầy, evidence hold và RAW_EXPIRED. **30–90 ngày trong tài liệu tham khảo không phải cấu hình mặc định**. Mốc lưu giữ, CPU/RAM/IO và MTTD/FPR chỉ đặt ngưỡng sau benchmark.
- Threat model thêm: attacker sửa rule/config, xóa log/reset record id, thay/quét bằng chứng, privilege escalation của response component, denial-of-service do log volume và false-positive gây response sai.
- Ghi rõ PoC chạy user-space dựa trên Sysmon **không tương đương kernel self-protection/tamper-proof EDR thương mại**.

## 9. Deployment topology Phase 1

~~~text
Windows 10/11 (VirtualBox lab / 1 host)
  Sysmon installed on Windows
  Local EDR (Python runtime; components run as modules initially)
    - collector: reads Windows Event Log (read capability)
    - ingestor: seals/validates Bronze, single-writer Silver DuckDB
    - detector: reads Silver snapshots, runs versioned rules
    - alert/analyst: local read-only API/CLI initially
    - responder: optional, disabled unless manually approved
  Local data:
    config/     bronze/     quarantine/     silver/
    features/   gold/       checkpoints/    audit/
~~~

**Không thêm remote management server, cloud ingestion, distributed message broker, container orchestration** trong Phase 1. Chuẩn bị interface export/upload tùy chọn với authentication, buffering, privacy và version negotiation cho giai đoạn mở rộng; không gọi đó là XDR trước khi thực sự có cross-domain correlation.

## 10. Hiện trạng thực tế và dependency blockers (tại thời điểm review)

| Evidence trong repo | Đã có | Chưa được chứng minh |
| --- | --- | --- |
| [Collector PoC](../../poc/sysmon-collector/sysmon_collector_poc.py) + [raw samples](../../references/samples/raw/) | parser/normalizer, file-mode, lab XML | service liên tục, checkpoint live, delivery guarantee |
| [Bronze contract](w5/contracts/README.md), [schema](../../poc/sysmon-collector/bronze-event.schema.json), [adapter](../../poc/sysmon-collector/bronze_to_silver_adapter.py) | proposal, synthetic fixtures/tests | signed cross-team agreement, segment writer, manifest/replay end-to-end |
| [Validator](../../src/pipeline/validator_poc.py) + [unit tests](../../tests/test_validator_poc_w5.py) | W05 validation/dedup/DLQ PoC | production ingestion, all edge events in persistent Silver |
| [Silver/Gold SQL](../../src/pipeline/sql/silver_gold_schema_and_views_v1_1.sql) | DDL for four event groups, features, alerts | operational feature/detection/alert store |
| [Cyber mapping](../research/cyber/w5/01-detection-required-fields-and-mitre-to-data.md) | 13 MITRE techniques, DET-001..010 requirements | rule engine, positive/negative benchmarks |
| [Alert traceability](../research/cyber/w5/02-alert-to-source-traceability-requirements.md) | design & raw event example | fully linked alert→Silver→Bronze proof |
| [ADR 0005](../decisions/0005_medallion_storage_and_quarantine_isolation.md) / [ADR 0006](../decisions/0006_schema_v1_1_reconciliation_and_dns_support.md) | architecture choices documented | W05 canonical owner sign-off reconciled with docs labelling "approved" |

**Priority P0 trước khi gọi kiến trúc đã hiện thực:** (i) owner sign-off Bronze 1.0 + adapter & event-specific schema; (ii) lineage and identity epoch; (iii) Windows collector lifecycle/test; (iv) alert contract fields & permissions.

## 11. Roadmap thực thi và Definition of Done — aligned với kế hoạch gốc W6–W12

> **Lịch ưu tiên được đồng bộ với [Kế hoạch 12 tuần DACN cập nhật W6–W12](../plan/ke-hoach-12-tuan-dacn-edr-v2-w6-w12.md)** (kế thừa file Word gốc do nhóm cung cấp). W1–W5 không thay đổi; **W7 vẫn là Static/Whitelist/Signature, W8 vẫn là AI/Risk/Anomaly**. Các mô-đun về durability/health là workstream hỗ trợ chéo, không dùng thay nội dung học thuật của các tuần.

| Tuần / owner chính | Mục tiêu gốc phải giữ | Bổ sung phù hợp EDR v2 | Minh chứng / DoD thiết kế |
| --- | --- | --- | --- |
| **W06 — Cyber lead** | Detection Engine: rule model, process/file/registry/network/parent-child, severity, traceability | Rule Registry/versioning, single event + temporal correlator, evaluation states, evidence completeness; DET-001/003/010 ưu tiên | Detection Architecture v1; 10 rule specifications; Alert/Evidence Contract; positive/benign/missing-data fixtures; Data/Software interface review |
| **W07 — Cyber + Data; Software interface** | Static Analysis, Whitelist và Threat Knowledge/Signature | SHA-256, entropy, PE/signature metadata, versioned local IOC/allowlist, suspicious candidate review lifecycle | Static Feature List; Whitelist/Signature Schema; Candidate Workflow/Review State; signed/allowlist policy và example fixtures |
| **W08 — Data/AI lead** | AI Design, Risk Scoring/Anomaly Detection, datasets/baselines/evaluation plan | Feature lineage, risk aggregator contract, model output/version, leakage & false-positive evaluation methodology | AI Design; Feature List; Dataset Plan; Model Baseline Plan; Precision/Recall/F1/FPR Evaluation Plan |
| **M2 — cuối W08** | Hoàn thành **thiết kế lõi** Data Pipeline W05 + Detection W06 + Static W07 + AI W08 | Inter-module compatibility review, residual risk & implementation backlog | Không đòi live enterprise EDR hoặc production ML |
| **W09 — Cyber lead** | Investigation, Process Tree, Timeline, Hunting, Alert/Incident, Response design | Raw evidence provenance; manual response approval, audit, protected-target allowlist, recovery metadata | Investigation/Response Design; Incident Schema; Hunt Query Set; Dashboard Wireframe; safety gate |
| **W10 — Cyber scenarios, Data expected, Software VM** | Test Scenario Matrix theo MITRE/Atomic Red Team, expected telemetry/detection/alerts và demo plan | Positive/negative/missing evidence; crash/replay/DLQ/late-event drills; measured-vs-expected evidence | Test Scenario Matrix; Demo Plan; Expected Telemetry/Alert Set; Test Environment Notes; optional verified PoC |
| **M3 — cuối W10** | Thiết kế Investigation/Response và bộ kịch bản kiểm thử/demo hoàn tất | Defensible evidence and limitations | Không nhận đã có response production nếu chỉ có workflow |
| **W11 — Cả nhóm** | Tổng hợp, review và đóng băng kiến trúc: Agent/Collector/Pipeline/Detection/AI/Storage/Risk/Alert/Investigation/Dashboard | Trust boundaries, control/operations planes, versioned contracts, ADR/open-decision log | Architecture Final v1; Component/Data Flow/Data Model/Sequence; ADRs; owners and cross-team design freeze |
| **W12 — Cả nhóm** | Validation, final report/slide, architecture package, backlog Luận văn, optional PoC demo | Requirements→design→test traceability, attack coverage & gap disclosure, evidence-based status | Final Report; Presentation; Final Architecture Package; Thesis Backlog; optional demo |
| **M4 — cuối W12** | Giai đoạn 1 bàn giao thiết kế kỹ thuật làm đầu vào cho Luận văn | Experimental reproducibility + bounded scope | Phân biệt Designed / Implemented / Tested / Deferred |

### Workstream kỹ thuật xuyên suốt (không thay trọng tâm từng tuần)

| Workstream | Owner | Cách lồng vào tiến độ |
| --- | --- | --- |
| **P0: Hợp đồng Bronze/Silver** | Data + Software, Cyber review | Chốt W05 \`bronze-event/1.0\`, mapping, nullable rules, raw reference trước khi test tích hợp; không giả định owner đã ký |
| **P0: Evidence/identity** | Data + Software | Traceability, \`channel_epoch\`/log reset, Silver provenance ở W06 contract, W09 hunting, W10 tests |
| **Durable Collector/Replay PoC** | Software + Data | Spike W07–W10 **nếu có thời gian**; không thay W07 Static hoặc W08 AI |
| **Telemetry Health/Privacy/Retention** | Software + Cyber + Data | Cross-cutting policy, failure test W10, architecture freeze W11 |
| **Response Safety/Auth/Audit** | Cyber + Software | W09 design, W10 safe tests; Phase 1 default **alert-only** |

**Ranh giới nghiệm thu:** toàn bộ W06–W12 là **thiết kế có thể hiện thực và kiểm chứng PoC có kiểm soát**. PoC gốc tùy tiến độ: Windows Sysmon/Collector → JSON/Bronze → normalize → **2–5 detection rules** → alert/dashboard đơn giản. Không yêu cầu continuous production service, full remote response, cloud XDR, AI production/large training corpus. Thời điểm W10 đo detection quality chỉ công bố chỉ số khi có dữ liệu gắn nhãn và kết quả chạy thực tế.

### Test matrix tối thiểu

- **DATA-01:** XML→canonical Bronze retains raw_xml/event_data and natural key; one recorded source reference per event.
- **DATA-02:** sealed segment corruption detected by manifest hash; replay deterministic, no duplicate.
- **DATA-03:** DNS22 nullable socket fields, Event5 parent optional, Event4/16 classification explicit.
- **DATA-04:** source log reset produces new channel_epoch or explicit collision alert; no silent evidence overwrite.
- **DET-01:** suspicious PowerShell candidate + benign PowerShell example differentiated by context, missing command line → INSUFFICIENT.
- **DET-03:** Run/RunOnce persistence case vs unrelated registry set.
- **DET-10:** Event11→1→26 ordered/host/path; missing Event26 → PENDING/PARTIAL, not false full-chain MATCH.
- **TRC-01:** alert’s source_event_ids resolve to Silver and immutable raw XML, or flag RAW_EXPIRED/PARTIAL.
- **OPS-01:** crash/restart, bounded queue, disk quota, corrupt record and privilege failures produce visible health signals.
- **RSP-01:** no automatic destructive action; unauthorized approval rejected; test protected-path allowlist and rollback metadata.

Nghiệm thu thực tế phải đính kèm command, phiên bản Python/Windows/Sysmon, test output, input hash, issue/PR và owner review. **Tài liệu này không tự động đóng W05 #26–#29, không chứng minh tests passed hay component đã chạy.**

## 12. Nguồn & nguyên tắc sử dụng

1. [Richardmsbr / EDR-XDR Architecture and Operations](https://github.com/Richardmsbr/cybersecurity-architecture/blob/main/defensive-security/edr-xdr.md): nhóm capabilities (telemetry, layered detection, incident response, hunting, operations) và phân biệt EDR/XDR. Tài liệu hướng tham khảo, không dùng các KPI/retention ví dụ làm tuyên bố của DACN.
2. [Microsoft Sysmon documentation](https://learn.microsoft.com/sysinternals/downloads/sysmon): giới hạn Sysmon là sensor/logging, không thực hiện detection/response thay EDR.
3. [NIST SP 800-61r3](https://csrc.nist.gov/pubs/sp/800/61/r3/final): incident response quản trị theo Detect/Respond/Recover và continuous improvement.
4. [MITRE ATT&CK Detection Strategies](https://attack.mitre.org/detectionstrategies/): ATT&CK từ 10/2025 có Detection Strategies/Analytics; tránh nhầm mã DET nội bộ.
5. [OCSF](https://ocsf.io/): chuẩn sự kiện đa nguồn để cân nhắc adapter tương lai, không bắt buộc thay schema v1.1.
6. DACN internal: [Preliminary architecture](preliminary-security-architecture.md), [W05 data](w5/data_pipeline_architecture_and_contracts_v1.md), [W05 software](../research/software/w5/03-local-storage-and-pipeline-integration-design.md), [W05 cyber gap](../research/cyber/w5/04-telemetry-gaps-and-w06-w09-backlog.md).

**Quy tắc đọc:** mọi sơ đồ, cấu hình và checklist trong tài liệu là **architecture proposal**, không coi như mã/feature hiện hữu. Các phần đã được thử nghiệm chỉ xác nhận ở phạm vi rõ ràng trong chính tài liệu nguồn và test logs.
