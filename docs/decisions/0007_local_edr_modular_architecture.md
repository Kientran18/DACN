# ADR 0007: Kiến trúc Local EDR modular, có bảo toàn dữ liệu và phản ứng được kiểm soát

- **Trạng thái:** PROPOSED / chưa phê duyệt
- **Ngày:** 2026-11-04
- **Đề xuất:** Nâng cấp kiến trúc tổng thể DACN dựa trên nghiên cứu EDR/XDR, thích ứng phạm vi một Windows endpoint.
- **Tài liệu kiến trúc:** [Local EDR v2](../architecture/local-edr-reference-architecture-v2.md)
- **Sơ đồ:** [EDR v2 diagrams](../../diagrams/edr-v2-architecture.md)
- **Kế thừa:** ADR 0001 (identity), 0002 (process GUID), 0003 (raw preservation), 0004 (tool roles), 0005 (local medallion), 0006 (schema reconciliation).
- **Nguồn tham khảo:** [Richardmsbr EDR/XDR Architecture and Operations](https://github.com/Richardmsbr/cybersecurity-architecture/blob/main/defensive-security/edr-xdr.md).

## Bối cảnh

Tài liệu hiện tại \`preliminary-security-architecture.md\` mô tả luồng chung từ Windows Events đến Collector, Normalization, Detection, Alert, Investigation/Response, nhưng chưa mô tả đầy đủ:
1. Độ bền và phục hồi pipeline: bookmark, segment seal, manifest, checkpoint, replay và DLQ.
2. Detection interfaces: required fields, correlation windows, late events, incomplete telemetry.
3. Traceability từ alert đến Silver và XML gốc.
4. Điều khiển và an toàn response: quyền, phê duyệt, allowlist, audit, rollback.
5. Rules/config lifecycle, health monitoring, privacy, retention và kiểm thử thất bại.

Phạm vi W01 xác định một Windows endpoint và local DB. Tài liệu tham khảo rộng tới XDR nhiều nguồn, không đồng nghĩa DACN cần multi-tenant cloud platform.

## Các phương án

| Lựa chọn | Mô tả | Đánh giá |
|---|---|---|
| A. Giữ sơ đồ pipeline đơn giản | Chỉ bổ sung thuyết minh tại các nút | Ít sửa nhưng thiếu kiểm soát lỗi và ranh giới trách nhiệm |
| **B. Modular monolith local-first** | Các module collector, data, detect, analyst, controlled response, config/health, cùng host Windows | **Đề xuất**: khả thi về scope, phát triển theo từng phần, bám code W03/W05 |
| C. Distributed EDR/XDR enterprise | Broker, cloud/service cluster, multi-domain connectors và SOC | Không phù hợp Phase 1, tăng deployment và vận hành |

## Quyết định đề xuất

**Chọn B**, với những nguyên tắc bắt buộc nếu được duyệt:

- Dùng Sysmon telemetry làm source chính; Windows Security/System bổ sung khi được cấu hình và kiểm thử. ETW/OCSF/XDR connector là extension.
- Kế thừa **canonical Bronze proposal \`bronze-event/1.0\`**, Silver v1.1, DuckDB/Parquet theo ADR 0005. *Phải có cross-team sign-off, không coi metadata ví dụ là storage persistent.*
- Phải thiết kế durable queue/segment, checkpoint/replay, ingestion idempotent và evidence lineage.
- Conditional validation theo Sysmon event type, data-quality/coverage state. Không false-success khi thiếu telemetry.
- Detection phân IOC / single-event / correlation; AI optional. Dùng external rule ID \`DACN-DET-xxx\` để tránh nhầm với MITRE ATT&CK Detection Strategy identifiers \`DETxxxx\`.
- Alert chứa source event IDs/raw reference, status, severity reason; có schema migration và test.
- Response phase đầu mặc định **alert-only**; mọi thao tác OS có rủi ro phải kiểm tra quyền, allowlist, evidence, phê duyệt, audit và khả năng phục hồi.
- Control plane cho rule/config revisions; health metrics theo pipeline và disk/resource budget được đo thực tế trên VM.

## Hệ quả và tradeoffs

**Ưu điểm:** giải thích được luồng end-to-end, giảm mất dữ liệu âm thầm, cải thiện traceability và an toàn phản ứng, chia việc rõ cho Cyber/Data/Software.

**Chi phí:** phải xử lý tính nhất quán contract, Windows service lifecycle, DuckDB single-writer, rollback/checkpoint, quyền NTFS và quality policy; không thể hoàn thành mọi module trong W06.

**Không phải tuyên bố đã kiểm thử:** các tính năng mới (persistent spool, watcher, incident UI, automatic response) đều là target design.

## Các quyết định vẫn mở

1. Cross-team acceptance Bronze 1.0/adapter, pending #26/#27/#29.
2. Định danh \`event_id\` khi EventRecordID reset: migration epoch-aware và crosswalk legacy IDs.
3. Schema cho health event ID4/16 và event-specific nullability, physical Silver lineage.
4. Cách đóng tệp atomic trên NTFS và kiểm thử Windows restart.
5. Rule DSL và window lateness policy; severity/confidence calibration từ labelled fixtures.
6. Local UI (CLI trước hay web), quyền đọc nhạy cảm, config signing/rollback.
7. Resource budget/retention từ benchmark trên Windows 10 VirtualBox.

## Điều kiện chấp thuận ADR

- Cyber xác nhận rule/alert/evidence + response policy.
- Data xác nhận schemas/versioned interfaces, Silver lineage, single-writer/replay.
- Software xác nhận Collector lifecycle, spool/manifest, Windows OS permissions.
- PR review của cả ba vai trò; không tự động coi ADR Accepted vì file đã được commit.
