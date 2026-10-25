# W05 Cyber — Review Handoff & Definition of Done (#28)

**Ngày:** 25/10/2026 · **Trạng thái:** Cyber deliverables được tạo; review Data/Software **chưa được xác nhận**, nên chưa tự đóng #28.

## Sản phẩm & vị trí

| Yêu cầu #28 | File bàn giao | Tình trạng |
|---|---|---|
| Mapping 13 MITRE, critical/optional/unavailable fields, rule W06 | [01 — Required Fields & MITRE](01-detection-required-fields-and-mitre-to-data.md) | Nội dung Cyber hoàn thành |
| Luồng alert → event → Bronze/raw, process tree, timeline, hunt & case từ W03 | [02 — Traceability](02-alert-to-source-traceability-requirements.md) | Thiết kế Cyber hoàn thành |
| Review schema, validation, quarantine, dedup, retention, privacy | [03 — Security Review](03-security-review-schema-quality-retention.md) | Review Cyber hoàn thành; chờ Data/Software phản hồi |
| Ưu tiên telemetry/data risks trước W06/W09 | [04 — Gaps & Backlog](04-telemetry-gaps-and-w06-w09-backlog.md) | Backlog owner đề xuất |
| Review chéo và liên kết #26 | File này + PR và issue | **Chờ review thực tế** |

## Ba yêu cầu cần chốt trong #26

1. **Canonical Bronze contract:** Data mô tả bản v1.1 với `raw_data/timestamp/collector_batch_id`; Software bản `bronze-event/1.0` với `event_data/raw_xml/time_created/ingest.*`. Đề nghị chọn một interface hoặc adapter có version + gold samples + manifest schema.
2. **Traceability:** cần xác nhận raw_ref/segment/line/integrity hash và mapping/collector version được đưa đến Silver và alert; `event_id` đơn lẻ chưa đủ để biết vị trí byte/raw nguồn.
3. **Mức chứng cứ:** giữ ranh giới SOURCE ACTUAL vs DESIGN vs TESTED; không đánh dấu coverage 13/13 DET hay performance benchmark chưa thực hiện. Đặc biệt phải test raw Event5/22, timestamp skew, UUIDv5 reset.

## Review checklist

- [x] 13/13 MITRE techniques được map vào nguồn EventID và field theo W03/W04.
- [x] DET-001..010 có điều kiện dữ liệu tối thiểu, bổ sung insufficiency flags và rủi ro.
- [x] Có luồng truy vết alert → Silver → Bronze và ví dụ raw/JSON với record ID 182→184→188.
- [x] Có yêu cầu retention, quarantine, out-of-order, evidence gaps và owner đề xuất.
- [ ] Data owner: xác nhận schema/provenance và chiến lược các bản ghi thiếu.
- [ ] Software owner: xác nhận Bronze format, raw XML preservation, recovery và các sample thực.
- [ ] Team #26: chốt biên bản, link PR/commit và đánh dấu tiêu chí nghiệm thu có bằng chứng.

## Review sign-off (điền bởi người review; không được tự ghi hộ)

| Bộ phận | Người xác nhận | Ngày | Review/comment URL | Kết luận |
|---|---|---|---|---|
| Cyber | Kientran18 | Chờ | PR W05 Cyber | Đã nộp nội dung |
| Data | NhatHuynhHuu2005 | Chờ | Chờ | Chưa xác nhận |
| Software | BuiCuongTuan | Chờ | Chờ | Chưa xác nhận |
| Team #26 | Cả nhóm | Chờ | Chờ | Chưa nghiệm thu |

**Không yêu cầu:** xây engine, model AI, response hay dashboard trong #28 W05. Mục tiêu đúng là design/review trước Detection Engine W06.

**Links:** [Issue #28](https://github.com/Kientran18/DACN/issues/28) · [Team #26](https://github.com/Kientran18/DACN/issues/26) · [Data #27](https://github.com/Kientran18/DACN/issues/27) · [Software #29](https://github.com/Kientran18/DACN/issues/29).
