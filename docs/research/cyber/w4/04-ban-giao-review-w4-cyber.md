# W04 Cyber — Bàn giao, truy xuất nguồn và checklist nghiệm thu issue #20

**Ngày:** 25/10/2026. **Phạm vi:** đóng góp Cyber W4 vào [issue #19](https://github.com/Kientran18/DACN/issues/19). **Trạng thái:** sản phẩm nội dung Cyber sẵn sàng review; **chưa có xác nhận Data/Software**.

## 1. Deliverables

| Yêu cầu issue #20 | Tài liệu | Tình trạng |
|---|---|---|
| Đánh giá đủ 5 công cụ, vai trò/telemetry/detection/investigation/hunting/response, tài liệu tham khảo | [01 — Báo cáo](01-bao-cao-danh-gia-nang-luc-bao-mat.md) | Nội dung đã soạn |
| Bảng so sánh năng lực với 13 MITRE techniques và điều kiện giới hạn | [02 — Ma trận](02-ma-tran-cong-cu-mitre-w4.md) | Nội dung đã soạn |
| Ý tưởng rule/hunt/response, gap list, Atomic Red Team safety/cleanup | [03 — Tái sử dụng & Lab](03-detection-hunting-response-va-ke-hoach-test.md) | Nội dung đã soạn |
| Đề xuất Adopt/Reference, đầu vào W5/6/10 và quyết định liên nhóm | 01 + 03; [Data ADR 0004](../../../decisions/0004_edr_tool_selection_and_role_allocation.md), [Software ADN](../../software/w4/04-ghi-chu-quyet-dinh-kien-truc-lua-chon-cong-cu.md) | Đề xuất Cyber đã ghi; **chờ đối soát/xác nhận** |
| Review Data & Software, liên kết Team #19 | Chính PR W4 Cyber, issue #19 | **Chưa đạt**, cần người được phân công review |

## 2. Truy vết bằng chứng và giới hạn

- EPP/EDR, attack scenarios: `docs/architecture/threat_model_v1.md`, `docs/scope/selected_mitre_techniques_v1.md`.
- W3: `docs/research/cyber/w3/*`, `references/samples/raw/*.xml`, `references/samples/json/*.json`, `references/samples/evidence/poc_run_20261018_021142.json`.
- Báo cáo độc lập: Data `docs/research/data/w4/`, Software `docs/research/software/w4/`.
- `[X]` chỉ là bằng chứng **đã thu được loại event trên máy lab**, không đồng nghĩa đã tấn công, đã chạy test Atomic, đã vận hành detection/response hay đã benchmark; `[R]` tham khảo tài liệu; `[D]` chưa hiện thực; `[G]` chưa xác minh.
- Mâu thuẫn cần giải quyết: Software W4 vẫn ghi chưa có mẫu thật và tài liệu chờ review; Data W4/ADR có diễn giải đã PASS và dùng phiên bản khác. `references/samples/raw/export_manifest.json` thực tế ghi Sysmon 15.22 và `sanitized:false`. Không tự động sửa lời xác nhận của nhóm khác.

## 3. Checklist phục vụ review

- [x] Đã đối chiếu 13/13 MITRE technique với nguồn Windows/Sysmon và khả năng **tham khảo** ở Wazuh, osquery, Velociraptor, Atomic.
- [x] Đã nêu phân vai 5 công cụ, không coi chúng có chức năng giống nhau.
- [x] Đã đưa security-relevant rule/query/hunting/response ideas, limitation và nguồn chính thức.
- [x] Đã nêu Atomic Red Team safe lab prerequisites, permission, cleanup và không claim đã chạy.
- [x] Đã đề xuất Sysmon/Atomic sử dụng có điều kiện; ba công cụ còn lại tham khảo.
- [ ] Data (NhatHuynhHuu2005) review mapping/schema/ground truth và đồng bộ với ADR 0004.
- [ ] Software (BuiCuongTuan) review event source, cấu hình, quyền và hạn chế collector/Sysmon.
- [ ] Cyber (Kientran18) chốt phạm vi/ưu tiên DET cùng reviewer.
- [ ] Team #19 ghi quyết định M1, linked PR/reviews và backlog tồn đọng W5.

**Mẫu ghi review (người thật điền):**

| Reviewer | Ngày | PR/comment URL | Đồng ý / cần sửa | Ghi chú |
|---|---|---|---|---|
| Data | Chờ | Chờ | Chờ | Kiểm tra field mapping và labeling |
| Software | Chờ | Chờ | Chờ | Xác minh Sysmon và triển khai |
| Cyber/Team | Chờ | Chờ | Chờ | Chốt bộ ma trận M1 |

**DoD:** nội dung báo cáo có thể trình review và PR, nhưng issue #20 chỉ nên được xác nhận hoàn tất toàn bộ sau khi review liên nhóm có bằng chứng. Không tự ghi PASS/approval hộ reviewer.
