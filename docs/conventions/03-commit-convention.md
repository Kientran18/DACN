# Commit Convention

Áp dụng theo chuẩn **Conventional Commits**:

```
<type>(<scope>): <mô tả ngắn, thì hiện tại>

[phần thân - tùy chọn, giải thích lý do/chi tiết]

[footer - tùy chọn, ví dụ: Closes #12]
```

## Các `type` sử dụng

| Type | Ý nghĩa |
|---|---|
| `feat` | Thêm tính năng/module mới |
| `fix` | Sửa lỗi |
| `docs` | Thay đổi tài liệu (README, docs/...) |
| `refactor` | Tái cấu trúc code, không đổi hành vi bên ngoài |
| `test` | Thêm/sửa test |
| `chore` | Việc phụ trợ: cấu hình CI, dependency, format code |
| `config` | Thay đổi cấu hình Sysmon/rule/config (không phải code) |
| `perf` | Cải thiện hiệu năng |

## `scope` gợi ý (tên module trong `src/`)

`collector`, `bronze`, `validation`, `silver`, `feature`, `static-analysis`, `rule-engine`, `ai-scoring`, `aggregator`, `dashboard`, `sysmon-config`

## Ví dụ

```
feat(collector): thêm collector đọc Sysmon Event ID 1 và 3

fix(silver): sửa lỗi map sai timestamp giữa Sysmon và Windows Event Log

docs(architecture): thêm sơ đồ luồng dữ liệu Bronze -> Gold

config(sysmon-config): bật thêm Event ID 11 (FileCreate)

Closes #21
```

## Quy tắc

- Mô tả ngắn viết ở **thì hiện tại**, không viết hoa chữ đầu, không có dấu `.` cuối câu.
- Một commit nên làm **một việc rõ ràng** (dễ review, dễ revert).
- Nếu commit liên quan đến issue, thêm `Closes #<id>` hoặc `Refs #<id>` ở footer.
