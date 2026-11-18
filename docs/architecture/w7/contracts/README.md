# W07 versioned JSON contracts

Source: `src/static_analysis/contracts.py` và `knowledge.py`; các file `.schema.json` ở đây export từ source, có test chống drift.

| File | Ý nghĩa |
|---|---|
| static-result.schema.json | Current-byte observation, hash/size/entropy/PE/signature status, source refs, errors |
| signature-hit.schema.json | IOC IDs, literal pattern IDs và suppression flag |
| whitelist-verdict.schema.json | Exact-hash verdict + policy + knowledge revision/version/time |
| candidate.schema.json | Observation/verdict/DetectionResult, state/revision, creator/time/alert IDs |
| knowledge.schema.json | Versioned local IOC/allowlist/pattern update package |
| examples.json | Synthetic outputs và package, không bytes/định danh thật |
| openapi-static.json | Request models, routes và lỗi HTTP xuất từ API thật; output JSON contracts xem schemas riêng ở trên |

Mọi format dùng `/1.0`; breaking field/meaning cần major mới, Data/Cyber review. JSON hash là revision checksum, không chữ ký nhà phát hành. Digital signature trong PoC luôn UNAVAILABLE; provider mở rộng cần contract review. DDL static_candidates là extension proposal, không sửa Silver v1.1/UUID/Bronze. Xem [module/API design](../static-whitelist-signature-design-v1.md).
