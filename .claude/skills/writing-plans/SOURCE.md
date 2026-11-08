# Nguồn gốc: writing-plans

- **Tác giả gốc:** Jesse Vincent (dự án obra/superpowers)
- **URL gốc:** https://github.com/obra/superpowers/tree/main/skills/writing-plans
- **Commit upstream tại thời điểm tải (2026-11-08):** nhánh `main` ở `22f0b463e7a5e579904dd6211a520321035526f7` (xác nhận bằng `git ls-remote`). Commit cụ thể đã thay đổi thư mục này không lấy được (GitHub API trả 403 trong session); cần ghi lại khi có quyền đọc đầy đủ.
- **Git blob SHA của SKILL.md gốc (tiếng Anh):** `4cf0275d88d67aa4ef09f4bbca9970ed6ff74a00`
- **Giấy phép:** MIT, bản đầy đủ tại `LICENSE-upstream.txt`
- **Bản dịch và chỉnh sửa:** Claude (theo yêu cầu DACN, 2026-11-08)

## Thay đổi so với bản gốc
1. Chuyển toàn bộ nội dung sang tiếng Việt; giữ nguyên tên skill và thuật ngữ kỹ thuật.
2. **Loại bỏ** bước "Commit" (`git add`/`git commit`) khỏi mẫu task và khỏi nguyên tắc "frequent commits": mâu thuẫn với `CLAUDE.md` mục 8.6 (chỉ commit khi người dùng yêu cầu rõ ràng).
3. **Loại bỏ** đường dẫn lưu mặc định `docs/superpowers/plans/` (ngoài phạm vi và không tồn tại trong DACN); thay bằng trình bày trong phản hồi, chỉ ghi file khi người dùng yêu cầu.
4. **Loại bỏ** "Announce at start", ghi chú về `superpowers:using-git-worktrees`, và toàn bộ phần "Execution Handoff" (lựa chọn subagent-driven/native, các sub-skill `superpowers:subagent-driven-development` và `superpowers:executing-plans`): các skill đó không được cài, và việc tự dispatch subagent thực thi trái với yêu cầu chỉ thực thi khi người dùng đồng ý.
5. Thay tiêu đề kế hoạch tiếng Anh bằng mẫu tiếng Việt, thêm các mục: Hiện trạng/TARGET, Tiêu chí nghiệm thu, Ảnh hưởng liên nhóm. Đổi "Review Focus" thành "Rủi ro và điểm cần xem xét" (giữ ý, rút gọn).
6. Thêm mục "Trước khi lập kế hoạch" dựa trên `CLAUDE.md` mục 5, 8, 9; lệnh test pytest/unittest của DACN; cảnh báo không tự đổi data contract; bước tự rà soát về an toàn.
7. Không có thay đổi về quyền, hook, script hay `allowed-tools`.

## Nội dung không sao chép
Bản gốc không có file phụ thuộc trong thư mục này (đã thử tải `plan-document-reviewer-prompt.md`, trả về 404, và SKILL.md gốc không tham chiếu nó). Các tham chiếu tới skill `superpowers:*` khác không được mang theo.
