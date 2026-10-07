# Branch Convention

## Nhánh chính

| Nhánh | Vai trò | Ghi chú |
|---|---|---|
| `main` | Bản ổn định, luôn chạy được | Chỉ merge qua Pull Request đã review |
| `develop` | Nhánh tích hợp trước khi vào `main` | (Có thể bỏ nếu team nhỏ, merge thẳng vào `main`) |

## Nhánh làm việc

Đặt tên theo dạng: `<loại>/<mô-tả-ngắn>` hoặc `<loại>/<issue-id>-<mô-tả-ngắn>`

| Loại | Dùng khi | Ví dụ |
|---|---|---|
| `feature/` | Thêm tính năng/module mới | `feature/12-sysmon-collector` |
| `fix/` | Sửa lỗi | `fix/34-timestamp-parsing` |
| `docs/` | Chỉ thay đổi tài liệu | `docs/architecture-overview` |
| `research/` | Tìm hiểu công nghệ, thử nghiệm chưa chắc dùng | `research/isolation-forest-eval` |
| `refactor/` | Tái cấu trúc code, không đổi hành vi | `refactor/pipeline-config-loader` |
| `chore/` | Việc phụ trợ (CI, dependency, format) | `chore/setup-pre-commit` |

## Quy tắc

- Tên nhánh viết thường, dùng dấu `-` nối từ, **không dùng khoảng trắng hoặc chữ hoa**.
- Mỗi nhánh feature/fix nên gắn với **một issue cụ thể** — đưa issue ID vào tên nhánh giúp truy vết dễ hơn.
- Nhánh làm việc **luôn tạo từ `main`** (hoặc `develop` nếu dùng) và được xóa sau khi merge.
- Không commit trực tiếp lên `main`.
- Nhánh sống ngắn hạn: nếu một nhánh feature tồn tại quá 1–2 tuần mà chưa merge, nên xem xét chia nhỏ task.
