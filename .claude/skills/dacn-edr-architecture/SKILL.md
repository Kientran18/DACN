---
name: dacn-edr-architecture
description: Dùng khi phân tích, đánh giá hoặc đề xuất kiến trúc EDR của DACN - ranh giới module, data flow và control flow, coupling, độ tin cậy, khả năng bảo trì, lộ trình từ PoC lên hệ thống tích hợp trong giới hạn 12 tuần. Chỉ phân tích và đề xuất; không tự đổi kiến trúc hoặc ADR đã phê duyệt.
---

# Kiến trúc EDR DACN

## Mục tiêu và phạm vi
Giúp đánh giá và thiết kế kiến trúc **local-first, một endpoint Windows 10/11, modular monolith** theo các tài liệu hiện có. Không dùng cho: rà soát hợp đồng dữ liệu chi tiết (`dacn-contract-review`), lập kế hoạch issue (`writing-plans`), mô hình đe dọa (`dacn-security-threat-modeling`).

## Đọc trước (xác minh đường dẫn bằng `ls`)
- `docs/architecture/local-edr-reference-architecture-v2.md` (trạng thái **PROPOSAL**), `diagrams/edr-v2-architecture.md`
- `docs/decisions/0001`–`0007` và đối chiếu trạng thái từng ADR ở dòng "Trạng thái" (ADR 0007 là PROPOSED; ADR 0004 cần xác nhận liên nhóm; 0005, 0006 Accepted)
- `docs/scope/phase-1-scope.md`, `docs/scope/data_pipeline_phase_1_scope.md`, `docs/architecture/preliminary-security-architecture.md`
- `docs/research/software/w5/03-local-storage-and-pipeline-integration-design.md`, `05-integration-feasibility-and-open-issues-w05.md`
- Mã nguồn thực tế: `poc/sysmon-collector/`, `src/pipeline/`; `CLAUDE.md` mục 3 (CURRENT vs TARGET)

## Quy trình
1. **Lập bảng hiện trạng:** mỗi module trong mục 4 của kiến trúc v2 → trạng thái (đã có code + test / chỉ thiết kế / chưa có) kèm đường dẫn file. Không coi mô tả trong tài liệu là bằng chứng triển khai; xác minh bằng code và test chạy lại.
2. **Vẽ ranh giới và hợp đồng:** input, output, owner (Software / Data / Cyber), loại giao tiếp (hàm, JSONL đã niêm phong, DuckDB) giữa các module. Chỉ rõ giao diện chéo nhóm cần 3 bên review.
3. **Phân tích data flow và control flow:** data plane (collect → Bronze → validate → Silver → detect → alert → investigate), control plane (rule/config có phiên bản, policy, approval), operations (health, checkpoint/replay, audit).
4. **Đánh giá theo tiêu chí:** coupling (import tên module trần, logic nhân bản có chủ ý giữa collector và validator), độ tin cậy (crash/restart, replay idempotent), khả năng bảo trì, hiệu năng/scale **trong phạm vi 1 endpoint** (không cần Kafka, cluster, Kubernetes, cloud).
5. **Đề xuất cải tiến** theo mức ưu tiên P0/P1/P2, ước lượng nỗ lực theo tuần của kế hoạch 12 tuần, và rủi ro. Đối chiếu với P0 trong kiến trúc v2 mục 10.
6. **Migration path PoC → tích hợp:** liệt kê từng bước nhỏ có thể kiểm thử (ví dụ: sealed Bronze writer → persistent Silver replay → rule PoC → alert store), mỗi bước có tiêu chí nghiệm thu và phần phải giữ tương thích.

## Nguyên tắc không được vi phạm
- Không tự đổi kiến trúc, ADR Accepted, data contract, event identity (`CLAUDE.md` mục 8). Muốn đề xuất đổi: ghi dưới dạng "đề xuất ADR" và hỏi.
- Không coi ADR PROPOSED hoặc kiến trúc v2 là quyết định đã chốt.
- Không mô tả thành phần TARGET như đã hoàn thành. Không đề xuất XDR tập trung, SOAR, multi-tenant trong Phase 1.
- Công nghệ: chỉ nêu cái đã có trong repository hoặc ADR; công nghệ mới ghi rõ là lựa chọn cần quyết định, kèm lý do và chi phí.
- Mâu thuẫn tài liệu ↔ code ↔ issue: ghi nhận trước khi đề xuất (`CLAUDE.md` mục 8.13).

## Kiểm tra kết quả
- Mọi khẳng định "đã có" có đường dẫn file hoặc kết quả lệnh kèm thời điểm.
- Mỗi đề xuất nêu rõ: nhóm sở hữu, ảnh hưởng liên nhóm, ADR bị chạm, cách kiểm thử.
- Không có đề xuất vượt phạm vi 12 tuần mà không gắn nhãn "giai đoạn sau".

## Đầu ra
```markdown
## Hiện trạng (CURRENT) và mục tiêu (TARGET) theo module
## Ranh giới, data flow, control flow (sơ đồ văn bản hoặc Mermaid)
## Đánh giá (coupling / reliability / maintainability / phạm vi)
## Mâu thuẫn tài liệu ↔ code ↔ issue
## Đề xuất có ưu tiên + migration path + tiêu chí nghiệm thu
## Cần quyết định của con người (ADR, owner)
```

## Cần hỏi người dùng trước khi tiếp tục
Đề xuất thay đổi ADR/contract/identity; thêm công nghệ hoặc process mới; chuyển phạm vi giữa các tuần; ghi tài liệu kiến trúc vào `docs/` (chỉ làm khi được yêu cầu).
