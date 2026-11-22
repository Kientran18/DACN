# W06 Rule Loading / Configuration Design

## Hiện thực

`src/detection/{schema,loader,evaluator,correlator,engine,result,process_context}.py`, `src/detection/rules/`, `tests/detection/`. Loader `safe_load`, reject duplicate ID, schema/regex/unsupported type, correlation thiếu window, blocked thiếu reason, MITRE thiếu basis. Default response_policy là alert_only. Không Python eval/plugin từ rule. `rule_version` integer; đổi rule phải tăng version để tạo evaluation mới. Fingerprint engine nay bao gồm toàn bộ rule content; rule/IOC set thay đổi gây rescan.

## Lifecycle thiết kế

1. Operator có quyền đưa package local vào staging; package có manifest schema_version/ruleset_version/file hashes/reviewer/source.
2. Validate schema major, version, supported operators, regex, required fields theo Event ID và fixtures negative. Từ chối toàn package nếu bất kỳ file sai.
3. Freeze ruleset cho mỗi cycle; writer giữ khóa khi đổi reference; không đổi object đang được evaluate.
4. Atomic publish staged manifest; giữ last-known-good. Activation/rollback ghi actor/reason/timestamp/revision; rollback chỉ revision đã validate.
5. Không tự tải feed, không `eval`, không nhận đường dẫn rule từ API analyst. Hash kiểm corruption, không thay signature/trust verification.

**Ranh giới trạng thái:** loader/validation/fingerprint là Implemented; atomic hot-activation nhiều YAML + signed release là Designed/Future. Không giả đã có registry daemon. W07 có `KnowledgeStore` activate/rollback chạy được, contract riêng không thay loader W06.

## Cache và phiên bản

Rule map đóng băng trong CoreService tới restart/reload có kiểm soát; không sửa rule cùng version. W07 giữ snapshot kiến thức mỗi analysis, kiểm expiry lúc verdict. Không cache bytes theo path/mtime rồi bỏ đọc: cùng path có thể bị thay. Mở rộng cache phải dùng file identity+SHA256+extractor version+knowledge revision và TTL không vượt expiry sớm nhất; error result không cache. Hiện thực W07 ưu tiên rescan có byte/time budget, không có cache stale.

Mọi threshold gồm 300s correlation, 600s alert grouping, 16MiB/5s static là giá trị giới hạn PoC; chưa là budget CPU/RAM/latency đã đo.
