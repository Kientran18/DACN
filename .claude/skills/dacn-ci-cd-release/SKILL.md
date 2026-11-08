---
name: dacn-ci-cd-release
description: Dùng khi thiết kế quy trình kiểm thử tự động, CI, đóng gói artifact, phiên bản và phát hành của DACN - GitHub Actions nếu được duyệt, lint/type check khi đã chọn công cụ, danh sách kiểm tra release, release notes, đánh giá khả năng rollback. Chỉ đề xuất và soạn nội dung; không thêm deployment tự động hay secret khi chưa được phê duyệt.
---

# CI/CD và phát hành

## Hiện trạng (xác minh lại)
Repository không có `.github/`, không có `requirements.txt`/`pyproject.toml` gốc, không có linter hay type checker được chọn (`CLAUDE.md` mục 4); dependency cài thủ công (`pytest`, `jsonschema`, `duckdb`; `pywin32` cho live mode). Convention nhánh/commit/issue: `docs/conventions/`. Không có quy trình release hay đánh phiên bản chính thức.

## Đọc trước
`CLAUDE.md` mục 4, 5, 9–10; `docs/conventions/02-branch-convention.md`, `03-commit-convention.md`; `README.md`; `dacn-issue-workflow`; `dacn-end-to-end-acceptance`.

## Quy trình
1. **Khảo sát thực tế:** liệt kê lệnh test hiện có, điều kiện chạy (từ thư mục gốc vì import tên module trần), phụ thuộc hệ điều hành (live mode cần Windows nên **không** chạy trên CI Linux).
2. **Thiết kế pipeline kiểm thử, trung lập công cụ:** các job tách biệt: (a) `python -m pytest -q poc/sysmon-collector`, (b) `python -m pytest -q tests/`; ma trận phiên bản Python chỉ gồm phiên bản dự án đã chọn (tài liệu lab nêu Python 3.11, kiểm tra lại); ghim phiên bản dependency sau khi người dùng chọn. Hai test đang fail đã biết phải được xử lý hoặc ghi nhận có chủ đích, **không** vô hiệu hóa test để CI xanh.
3. **Lint/type check:** chỉ khi người dùng chọn công cụ; đề xuất kèm chi phí bảo trì, không bật hàng loạt quy tắc làm vỡ mã hiện có.
4. **Artifact/đóng gói:** repository chưa là package (import tên module trần); đóng gói là thay đổi cấu trúc cần quyết định riêng. Nếu cần bản chạy cho demo Windows, mô tả cách tạo thủ công trước.
5. **Phiên bản:** đề xuất SemVer cho (i) code/PoC, (ii) `schema_version` (ví dụ `bronze-event/1.0`), (iii) `rule_version`, tách nhau; thay đổi contract có quy tắc nâng version riêng và cần review liên nhóm.
6. **Release checklist:** test đã chạy lại và đính kèm đầu ra; không còn thay đổi chưa commit; tài liệu cập nhật; không có secret/PII (`dacn-security-review`); changelog; kiểm tra hướng dẫn Windows; mốc milestone khớp kế hoạch được duyệt.
7. **Release notes:** từ commit đã merge và issue đã đóng, chia mục tính năng/sửa lỗi/thay đổi contract/giới hạn đã biết; chỉ ghi điều có bằng chứng.
8. **Rollback:** với PoC local chủ yếu là quay lại tag/commit; với dữ liệu, rollback Silver bằng reprocess từ Bronze (Bronze không bị sửa).

## Nguyên tắc không được vi phạm
- Không tạo hay sửa `.github/workflows/` khi chưa được yêu cầu; nếu soạn workflow, đưa dưới dạng bản nháp trong phản hồi và chỉ ghi file khi được cho phép (nằm ngoài phạm vi `.claude/skills/`).
- Không thêm deployment tự động, secret, token, quyền ghi, hay action bên thứ ba chưa ghim commit SHA và chưa được duyệt.
- Không tag, release, push hay tạo PR khi chưa được yêu cầu. Không tự merge.
- Không báo "CI xanh" khi chưa có lần chạy thật.

## Kiểm tra kết quả
Mỗi lệnh trong pipeline đề xuất đã được chạy cục bộ thành công (hoặc ghi rõ chưa chạy); danh sách thay đổi release khớp `git log`.

## Đầu ra
Bản nháp workflow hoặc tài liệu quy trình, release checklist, bản nháp release notes, phân tích rollback.

## Cần hỏi người dùng
Mọi thay đổi trong `.github/`, chọn lint/type tool, quyết định đóng gói, đặt phiên bản đầu tiên, phát hành.
