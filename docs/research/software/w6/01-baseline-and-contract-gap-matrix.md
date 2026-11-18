# W06 baseline và contract gaps (#40)

17/11/2026 — Designed; chờ review liên nhóm. Nền triển khai `claude_implement` commit `685b3c7`; không coi nhánh main chỉ có W05 là hiện trạng engine.

| Đầu vào đã rà | Đã có | Khoảng trống / owner |
|---|---|---|
| Collector W03 và raw/JSON samples | Parser, file/live API, UUIDv5 | Live Event Log/Sysmon VM chưa kiểm trong lần này — Software |
| `bronze_contract.py` / schema | Bronze 1.0, raw_xml/event_data | W05 sign-off chưa có; không đổi identity — Data/Software |
| `bronze_to_silver_adapter.py` | Integrity check, clock, raw_data | `bronze_source` PoC; persistent store nhánh triển khai dùng lineage v1.2 proposal — Data |
| `validator_poc.py` | Event-specific validation, quarantine, dedup | Event4/16 state; enum/time/host decisions còn mở — Data/Cyber |
| Silver/Gold DDL v1.1 | 4 event tables + Gold draft | Required confidence/process fields, thiếu outcome/version/completeness; không lấp bằng giả — Data |
| DDL v1.2 proposal + runtime | Alert/coverage/evidence/audit | Runtime phụ thuộc proposal, chưa được liên nhóm duyệt — Data/Cyber/Software |
| Cyber W05 DET-001/003/010 | Field/rule/evidence requirements | Mẫu lab không tự là nhãn attack; conditions/severity cần Cyber review |

## Field coverage để bắt đầu detector

| Rule | Raw → Silver cần dùng | Khi thiếu |
|---|---|---|
| DET-001 | ID1 Image/CommandLine/ProcessGuid/parent context → image_path,command_line,process_guid,parent_* | INSUFFICIENT; trường đã có phủ định điều kiện thì NO_MATCH |
| DET-003 | ID13 TargetObject/Details/ProcessGuid → target_object,details,process_guid | Không kết luận mọi registry set là persistence |
| DET-010 | ID11 TargetFilename → file_path; ID1 Image → image_path; ID23/26 TargetFilename; host/SystemTime | Pending/partial; normalize path chắc chắn; khác actor GUID vẫn được xét |
| IOC/static | Telemetry Hashes chỉ khi có → file_sha256 | W07 đọc bytes riêng, ghi observation time; hash current khác telemetry → HASH_MISMATCH |
| Alert/raw | event_id → silver_event_lineage → segment,line,sha256 | NO_LINEAGE/RAW_EXPIRED, không giả raw ref |

Q-W05: chấp thuận Bronze 1.0, identity log-reset/epoch, host normalization, precision µs, enum Event4/16, DDL v1.2. Đây là phụ thuộc ghi rõ; #40 không tự sửa hoặc duyệt thay #26–#29.
