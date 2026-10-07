# Issue Convention

## Loại issue (Labels)

| Label | Dùng cho |
|---|---|
| `type:research` | Tìm hiểu công nghệ, kỹ thuật, đọc tài liệu tham khảo |
| `type:feature` | Xây dựng module/tính năng mới trong pipeline |
| `type:bug` | Lỗi cần sửa |
| `type:docs` | Viết/cập nhật tài liệu |
| `type:infra` | Môi trường, CI/CD, cấu hình repo |
| `priority:high` / `priority:medium` / `priority:low` | Mức độ ưu tiên |
| `status:blocked` | Đang bị chặn bởi việc khác |

## Cấu trúc tiêu đề

`[<module>] <mô tả ngắn gọn, dùng động từ>`

Ví dụ:
- `[collector] Đọc và parse Sysmon Event ID 1 (Process Create)`
- `[silver] Chuẩn hóa trường timestamp về UTC`
- `[research] Đánh giá Sigma rule format cho Behavior Rule Engine`

## Template nội dung issue

```markdown
### Mô tả
(Vấn đề cần giải quyết hoặc việc cần làm là gì)

### Mục tiêu / Kết quả mong đợi
- [ ] ...
- [ ] ...

### Ghi chú kỹ thuật
(Tài liệu tham khảo, thư viện dự kiến dùng, ràng buộc)

### Definition of Done
- [ ] Code/tài liệu đã hoàn thành và được review
- [ ] (nếu áp dụng) Có test hoặc ví dụ minh họa
```

## Quy tắc

- Mỗi issue nên là **một đơn vị việc làm trong 1 nhánh feature/fix** — nếu quá lớn, tách thành sub-issue hoặc checklist.
- Gán issue vào đúng cột trên **GitHub Project board** khi bắt đầu/kết thúc.
- Issue loại `research` phải kết thúc bằng một kết luận ngắn được ghi lại trong comment hoặc trong `docs/` (không để trôi mất kiến thức tìm hiểu được).
