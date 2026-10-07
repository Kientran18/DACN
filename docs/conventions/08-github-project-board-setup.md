# Thiết lập GitHub Project Board

## Cách tạo

1. Vào repo → tab **Projects** → **New project** → chọn template **Board**.
2. Đặt tên project, ví dụ: `Endpoint Security Pipeline — Đồ án Chuyên ngành`.

## Cột (Columns) đề xuất

| Cột | Ý nghĩa |
|---|---|
| **Backlog** | Việc đã xác định nhưng chưa bắt đầu |
| **To Do** | Đã lên kế hoạch làm trong sprint/tuần hiện tại |
| **In Progress** | Đang làm |
| **In Review** | Đã tạo Pull Request, chờ review |
| **Done** | Đã merge / hoàn thành |

## Tự động hóa (Automation)

Cấu hình trong **Project settings → Workflows**:

- Issue mới được tạo → tự động vào **Backlog**
- Issue được gán (assigned) → chuyển sang **To Do**
- Pull Request mở và liên kết với issue → chuyển issue sang **In Review**
- Pull Request merge → issue tự động chuyển sang **Done** và đóng issue (`Closes #<id>` trong PR description)

## Trường tùy chỉnh (Custom fields) đề xuất

| Field | Loại | Giá trị |
|---|---|---|
| `Type` | Single select | research / feature / bug / docs / infra (đồng bộ với label) |
| `Priority` | Single select | High / Medium / Low |
| `Module` | Single select | collector / bronze / silver / feature-engineering / static-analysis / rule-engine / ai-scoring / aggregator / dashboard |
| `Sprint` | Text hoặc iteration field | Tuần/sprint hiện tại |

## Liên kết với Issue Convention

- Mỗi issue tạo theo `docs/conventions/issue-convention.md` sẽ tự có label `type:*` — map đúng label này vào field `Type` trên board để lọc/nhóm dễ dàng.
- Review định kỳ (ví dụ hàng tuần): dọn cột **Backlog**, đảm bảo **In Progress** không có quá nhiều issue cùng lúc (giới hạn WIP — ví dụ tối đa 2 issue/người).

## Việc cần làm để hoàn tất

- [ ] Tạo project board với 5 cột trên
- [ ] Thiết lập automation (issue → PR → Done)
- [ ] Thêm custom field `Type`, `Priority`, `Module`
- [ ] Đưa toàn bộ issue hiện có (nếu có) vào board, phân loại vào đúng cột
