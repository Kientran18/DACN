# W05 Cyber — Security Review: Schema, Data Quality, Quarantine, Retention

**Issue:** #28 · **Ngày:** 25/10/2026 · **Trạng thái:** Cyber review kỹ thuật; các đề xuất dưới đây chờ Data/Software chấp nhận.

## 1. Review hợp đồng Data/Software

Đã đọc: [Data pipeline v1](../../../architecture/w5/data_pipeline_architecture_and_contracts_v1.md), [Schema v1.1](../../../architecture/w5/schema_reconciliation_and_dictionary_v1_1.md), [Validation/Lineage](../../../architecture/w5/validation_quality_lineage_and_governance_v1.md), [ADR 0006](../../../decisions/0006_schema_v1_1_reconciliation_and_dns_support.md), [Software Bronze](../../software/w5/01-collector-to-bronze-interface-contract-v1.md) và [Software mismatch](../../software/w5/02-field-compatibility-mapping.md).

| Rủi ro | Phát hiện | Cyber yêu cầu | Ưu tiên / Owner đề xuất |
|---|---|---|---|
| SEC-W5-01: Bronze contract split | Data v1.1 dùng `raw_data,timestamp,bronze_ingest_utc,collector_batch_id,raw_payload_sha256`; Software `bronze-event/1.0` dùng `event_data,raw_xml,time_created,ingest.*,host_id` | Chốt **một** schema có version, adapter rõ ràng, XML gốc và checksum; test cả hai phía | **P0** Data+Software |
| SEC-W5-02: Raw provenance đứt | DDL Silver có `event_id,raw_data` nhưng không chuẩn hóa `_bronze_segment,_bronze_line,_ingest_run_id` | Bắt buộc trace event→segment/offset/hash/raw XML; record lỗi vẫn có raw reference | **P0** Data+Software |
| SEC-W5-03: Epoch/UUIDv5 | UUIDv5(hostname, channel, record_id) lặp sau clear/reset channel hoặc rename host; ADR đề xuất epoch | Persist epoch & reset audit; không dùng timestamp suy đoán đơn độc để thay thế identity | **P1** Data+Software |
| SEC-W5-04: Event-specific null | Event5 không parent, ID22 không socket; ID4/16 không process GUID | Constraint/validation theo `sysmon_event_id`; không tạo GUID/IP mặc định | **P0** Data |
| SEC-W5-05: Timestamp skew | Mẫu ID3/22 có SystemTime ↔ UtcTime lệch ~12s | Dùng SystemTime làm trục chính, giữ raw timestamp chính xác; quality flag & allowed lateness; không kết luận từ một window 5s | **P1** Data+Cyber |
| SEC-W5-06: Detection-critical missing | Missing CommandLine/hash/parent hoặc source ID | `INSUFFICIENT_TELEMETRY`/`PARTIAL_ANCESTRY` ở **rule level**; không đánh dấu event benign và không tự nâng confidence | **P0** Cyber+Data |
| SEC-W5-07: Quarantine visibility | Một số valid-but-missing-event hoặc corrupt log có thể rơi vào quarantine, làm false negatives | Mỗi failure lưu reason/source/record/hash/time; metric và truy vấn investigation; phân biệt telemetry missing do collector, filter hay validator | **P0** Data+Software |
| SEC-W5-08: Windows privacy | XML/raw command line có thể chứa credential, SID, user path; manifest hiện `sanitized:false` | NTFS ACL, audit export, sanitize **bản chia sẻ** và history public; tránh sửa chứng cứ gốc mà không lưu nguồn | **P0** Team |
| SEC-W5-09: Retention gap | Bronze đề xuất 14 ngày, Silver 90, Alert/Gold 365; truy vết cần raw XML | Legal/evidence hold khi alert mở; khi hết raw phải đánh `RAW_EXPIRED`, không tự tuyên bố "điều tra 100%" | **P1** Data+Cyber |
| SEC-W5-10: False coverage claims | File 11/26 không phải write/rename toàn diện; không chứng minh T1486, 443 không chứng minh C2 | Coverage flag theo kỹ thuật; không dùng raw event presence làm validation DET success | **P1** Cyber |
| SEC-W5-11: Evidence versioning | Mapping/schema v1, v1.1, contract 1.0 chưa có migration/provenance chung | Lưu `schema_version,collector_version,mapping_version,rule_version`, replay test | **P1** Data+Software |

**Điều cần quyết định trước W06:** Data định nghĩa **Silver canonical** với tên `hostname,src_ip,src_port,dest_ip,dest_port` (ADR 0006); Software Bronze có thể dùng `event_data/time_created` nếu adapter chuyển đổi được kiểm thử. Tuyệt đối không ép gộp trường DNS QueryResults vào DestinationIp như kết nối thực.

## 2. Chính sách validation Cyber đề xuất

- **Source malformed/natural key**: thiếu `Computer,Channel,EventRecordID,EventID,TimeCreated` ⇒ quarantine, giữ raw XML nếu có, log `collector_error`. Không tự tạo `event_id` giả.
- **Event schema**: validation theo ID; ID1 cần process identity/image và parent fields theo nguồn, ID5 parent NULL hợp lệ; ID3 network tuple, ID22 query name, socket fields NULL; Event4/16 giữ riêng system/source envelope nếu mở scope.
- **Optional context**: hash không có ở Event11 là bình thường; CMD/PowerShell command line có thể trống nếu nguồn/cấu hình khác. Rule thiếu field cần cờ insufficiency, không xóa bản ghi đã hợp lệ.
- **Conflicting time**: lưu `timestamp_source` và `event_utc_time` riêng; không sửa timestamp nguồn để khớp window, ghi `time_skew_seconds` và trạng thái confidence.
- **Dedup**: event_id ổn định trong 1 log epoch; duplicate count riêng, không quarantine bản ghi hợp lệ chỉ vì trùng; detect source conflicts nếu cùng natural key nhưng raw payload hash khác.
- **Late/out-of-order**: bookmark/segment có thể tới trễ, process child có thể trước parent; hỗ trợ deferred join/re-evaluate và watermark, tránh false "no match".
- **Quarantine/replay**: kiểm tra mã lỗi, actor, raw reference, mapping version; không âm thầm drop; replay phải giữ evidence chain và không phát alert trùng.

## 3. Ví dụ positive/negative acceptance criteria (thiết kế)

| Case | Input | Expected | Vì sao quan trọng |
|---|---|---|---|
| Q-01 | ID5 XML thật, parent missing | VALID, parent NULL | Không làm mất process termination |
| Q-02 | ID22 XML thật, socket IP/port missing | VALID, DNS fields retained | Tránh False Negative DNS |
| Q-03 | ID3 thiếu dest IP bắt buộc | QUARANTINE với raw_ref & reason | Không tự điền `0.0.0.0` |
| Q-04 | ID1 có process nhưng thiếu CommandLine | Lưu event nếu schema cho phép, rule DET-001 = INSUFFICIENT | Phân biệt data validity và detector |
| Q-05 | Raw Event11→1→26 trong nhiều nguồn | Partial/complete trace có nguồn và version | Không bịa event_id cho raw-only |
| Q-06 | Event đến muộn đảo thứ tự nguồn | Re-evaluate / mark incomplete | Tránh false negative cửa sổ |
| Q-07 | Replay cùng key và raw hash | 1 Silver event, duplicate count; alert dedup | Idempotency |
| Q-08 | Replay cùng key nhưng raw hash khác | Raise SOURCE_IDENTITY_CONFLICT, không overwrite raw | Phát hiện log reset/reuse |
| Q-09 | Bronze vượt TTL nhưng alert còn mở | Retention hold hoặc RAW_EXPIRED rõ ràng | Bảo toàn khả năng điều tra |
| Q-10 | Xuất XML public chưa sanitize | BLOCK export, report redaction | Tránh lộ dữ liệu hệ thống |

**Chưa chạy các test trên như test suite thống nhất.** W05 có `validator_poc.py` và test riêng; các bằng chứng Data ghi về số lượng case/benchmark còn phải đối chiếu theo mã hiện có.

## 4. Retention theo nhu cầu điều tra

Đề xuất W05 của Data: Bronze 14 ngày, Quarantine 30, Silver 90, Gold alert 365. Cyber không coi đây là cấu hình đã benchmark/phê duyệt. Để phục vụ W09 phải có:

1. Trước khi xóa raw Bronze, kiểm tra alert/incident được gắn `evidence_hold`, tình trạng legal/audit nếu có; không xóa evidence đang sử dụng.
2. Nếu raw thực sự hết hạn: giữ `raw_sha256`, collector/mapping version, time/host/channel/record ID, `evidence_expired_at` và lý do thiếu raw; không hứa khôi phục XML từ Silver JSON.
3. Chỉ người có quyền mới truy cập command line, đường dẫn người dùng, SID, dữ liệu nghi chứa secret; mọi export phải redaction rõ ràng và log.
4. Backup/restore, quản lý key và xóa an toàn để sang Giai đoạn 2 thiết kế; không coi các cơ chế này đã triển khai ở W05.

## 5. Kết luận và review cần thực hiện

- **Cyber đồng ý về hướng kiến trúc** Sysmon → Bronze → validation → Silver → Feature/Detection/Gold và lựa chọn DuckDB cho P1.
- **Cyber chưa thể xác nhận hợp đồng data end-to-end đã "APPROVED"** vì còn SEC-W5-01/02 và trạng thái Software DRAFT; đề nghị #26 chốt bằng PR/biên bản.
- Không khẳng định 13/13 kỹ thuật đã được detection, không claim precision/FPR, không tự ghi phê duyệt hộ Data/Software.
- Việc phát hiện hành vi cần rule/version/source+confidence, cùng dấu hiệu không đầy đủ.
