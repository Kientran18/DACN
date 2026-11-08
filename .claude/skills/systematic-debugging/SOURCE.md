# Nguồn gốc: systematic-debugging

- **Tác giả gốc:** Jesse Vincent (dự án obra/superpowers)
- **URL gốc:** https://github.com/obra/superpowers/tree/main/skills/systematic-debugging
- **Commit upstream tại thời điểm tải (2026-11-08):** nhánh `main` ở `22f0b463e7a5e579904dd6211a520321035526f7`. Commit cụ thể đã thay đổi file này không lấy được (GitHub API bị chặn trong session); cần ghi lại khi có quyền đọc đầy đủ.
- **Git blob SHA của SKILL.md gốc (tiếng Anh):** `62fc752aaef59a8bbed5d305f4cadc60f8ae07ed`
- **Giấy phép:** MIT, bản đầy đủ tại `LICENSE-upstream.txt`
- **Bản dịch và chỉnh sửa:** Claude (theo yêu cầu DACN, 2026-11-08)

## Thay đổi so với bản gốc
1. Chuyển toàn bộ nội dung sang tiếng Việt; giữ nguyên tên skill và thuật ngữ kỹ thuật.
2. **Không sao chép** ba file tham chiếu `root-cause-tracing.md`, `defense-in-depth.md`, `condition-based-waiting.md`. Các file này có trên upstream nhưng chưa được rà soát và chưa cần thiết cho quy trình DACN; phần "Supporting Techniques" của bản gốc đã được bỏ.
3. Thay các tham chiếu `superpowers:test-driven-development` và `superpowers:verification-before-completion` bằng hướng dẫn trực tiếp. Skill `verification-before-completion` được cài trong cùng đợt, nên có thể tham chiếu theo tên.
4. Thay ví dụ bash riêng cho macOS/CI (`security`, `codesign`) bằng ví dụ Python trên luồng Sysmon của DACN. Ví dụ chỉ đọc file và in kết quả, không ghi vào repository.
5. Thêm mục "Áp dụng cho DACN": không sửa mã nguồn khi đang điều tra, không dùng git để hoàn tác, cách ghi nhận lỗi đã biết.
6. Đổi "trao đổi với đối tác người" thành "trao đổi với người dùng" và tham chiếu `CLAUDE.md` mục 8.

## Nội dung không sao chép
Ba file tham chiếu nói trên.
