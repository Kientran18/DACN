# W07 Candidate Review API / integration flow

Các endpoint dùng Bearer token và role hiện có; loopback. Không đưa actor/token vào examples. Root mặc định `<EDR_HOME>/lab`, knowledge tại `<EDR_HOME>/static-knowledge`. Hai kho mới tách khỏi legacy `ioc/ioc.yaml`: legacy phục vụ telemetry IOC/response, W07 package phục vụ file observation. Không double-write, không âm thầm thay verdict behavioral; operator chủ động duyệt version cả hai nếu cần đồng bộ.

| Method / path | Quyền | Request / response |
|---|---|---|
| POST `/static/analyses` | analyst/approver | `{path,source_event_ids:[]}` → candidate v1 gồm features/verdict/detection/alert IDs |
| GET `/static/candidates?limit=100&offset=0` | viewer/analyst/approver | pagination tối đa500 |
| GET `/static/candidates/{id}` | read | candidate immutable observation + current review state |
| GET `/static/candidates/{id}/history` | read | audit sequence, actor,reason,time,row hash |
| POST `/static/candidates/{id}/transition` | analyst triage; approver final | `{to_state,expected_revision,reason}` → updated candidate |
| GET `/static/knowledge` | read | `{revision,bundle}` |
| POST `/static/knowledge/activate` | approver | `{bundle,expected_revision,reason}` → revision |
| POST `/static/knowledge/rollback` | approver | `{revision,expected_revision,reason}` → revision |

Lỗi auth401, permission403, missing404, invalid body422, CAS/state/package409. Phân tích file thất bại là một candidate với `analysis.status=ERROR` + reason, không HTTP200 giả successful features. Package input không hợp lệ không publish một phần. Chưa có asynchronous queue; bounded synchronous lab request, chỉ một writer; scale phải thiết kế admission control trước production.

Review verdict không đồng nghĩa cập nhật global whitelist. Sau TRIAGED→ALLOWLISTED, approver tạo package version mới với exact SHA256/source/expiry và activate; không wildcard path/publisher. Nếu observation có unresolved IOC hit thì không cho ALLOWLISTED; phải review/gỡ conflict bằng package mới và tạo analysis mới, giữ evidence cũ.

## Integration acceptance

1. File lab benign biết trước hash → static result đúng; pattern marker là test fixture không malware.
2. Activate package hash marker → standalone candidate HIT/MATCH, không alert nếu không source event thật.
3. Source Silver đúng path/hash → MATCH → AlertBuilder, contributing IDs truy vết bằng EvidenceResolver; không tự fabricate Bronze nếu source fixture không có lineage.
4. Allowlist hash + IOC conflict → verdict static allowlisted nhưng giữ hit/suppression evidence; không sửa detections/alerts behavioral đã tồn tại.
5. Triage + final review có expected revision, actor/reason từ token; revision cũ từ chối; mọi thay đổi có audit.
6. Package corrupt/wrong major/expiry/hash/rollback stale → reject hoặc bỏ indicator expired; last-known-good giữ nguyên.

Schema [W07 contracts](../../../architecture/w7/contracts/README.md); architecture [static design](../../../architecture/w7/static-whitelist-signature-design-v1.md). Phần W08 nhận snapshot/version/reasons không risk score giả. Phần W09 đọc history + refs, không tự gọi response.
