# Nguồn gốc: test-driven-development

- **Tác giả gốc:** Jesse Vincent (dự án obra/superpowers)
- **URL gốc:** https://github.com/obra/superpowers/tree/main/skills/test-driven-development
- **Commit upstream tại thời điểm tải (2026-11-08):** nhánh `main` ở `22f0b463e7a5e579904dd6211a520321035526f7` (xác nhận bằng `git ls-remote`). Commit cụ thể đã thay đổi thư mục này không lấy được (GitHub API trả 403 trong session); cần ghi lại khi có quyền đọc đầy đủ.
- **Git blob SHA của file gốc (tiếng Anh):**
  - `SKILL.md`: `46838cc9e893c06259e3bdad0fc2425b36242f15`
  - `writing-good-tests.md`: `d3c4482fd30b4f9084bb61545fe73939a7502c28`
- **Giấy phép:** MIT, bản đầy đủ tại `LICENSE-upstream.txt`
- **Bản dịch và chỉnh sửa:** Claude (theo yêu cầu DACN, 2026-11-08)

## Thay đổi so với bản gốc
1. Chuyển toàn bộ nội dung sang tiếng Việt; giữ nguyên tên skill, thuật ngữ, tên file, tên hàm và lệnh.
2. **Loại bỏ** "Iron Law" yêu cầu xóa code viết trước test ("Delete means delete", "Start over", "Don't keep it as reference") và các Red Flags kết luận "Delete code": mâu thuẫn với yêu cầu DACN không được tự ý xóa implementation hiện có và với quy định an toàn không thực hiện lệnh xóa/ghi đè. Thay bằng mục "Điều chỉnh cho DACN: code đã có sẵn" (characterization test, hỏi người dùng trước khi bỏ code).
3. **Loại bỏ** sơ đồ Graphviz `dot` và các ví dụ/lệnh `npm test`/TypeScript; thay bằng ví dụ pytest/unittest và lệnh thật của DACN (`CLAUDE.md` mục 4, 5).
4. Thêm: quy trình regression test cho lỗi đã xác minh; yêu cầu chạy toàn bộ `poc/sysmon-collector` và `tests/`; báo cáo mọi test fail theo tên; không sửa code ngoài phạm vi issue; không đổi schema/mapping/UUID để test pass; cảnh báo không sao chép tên máy/người dùng thật vào fixture; liên kết tới `systematic-debugging` và `verification-before-completion`.
5. `writing-good-tests.md`: dịch và rút gọn, đổi ví dụ TypeScript sang Python; bỏ tham chiếu `superpowers:writing-skills` (skill không được cài) và các trích dẫn "your human partner"; ghi rõ mutation check chỉ là kiểm tra tư duy, không sửa code thật để thử.
6. Không có thay đổi về quyền, hook, script hay `allowed-tools`.

## Nội dung không sao chép
- `testing-anti-patterns.md`: SKILL.md gốc không còn tham chiếu và URL trả về 404 tại thời điểm tải, nên không có bản để sao chép.
- Mục "Common Rationalizations" và "Red Flags" gốc được rút gọn và chỉnh theo điểm 2.
