---
name: dacn-documentation-handover
description: Tài liệu, báo cáo và bàn giao DACN bằng tiếng Việt. Tự dùng khi soạn báo cáo tuần hoặc milestone, test report, hướng dẫn cài đặt Windows, tài liệu kỹ thuật, tổng hợp trạng thái dự án, bàn giao cho AI Agent. Kết luận tiến độ phải có bằng chứng từ code, issue, test. Release notes thuộc dacn-ci-cd-release.
---

# Tài liệu và bàn giao

## Đọc trước
`CLAUDE.md` mục 3, 12, 13 (quy tắc phân biệt CURRENT/TARGET và cập nhật trạng thái), `README.md`, `docs/report/` (định dạng báo cáo tuần có sẵn), `docs/conventions/`, `docs/architecture/w5/contracts/README.md` (bảng sign-off), `docs/research/cyber/w5/05-review-handoff-and-dod.md`, issue/PR/milestone liên quan qua công cụ GitHub.

## Quy trình
1. **Thu thập bằng chứng, không dựa trí nhớ:** `git log`/`git status`, kết quả test chạy lại ngay (kèm lệnh và thời điểm), trạng thái issue/PR đọc từ GitHub, ADR hiện hành. Không chép lại số liệu từ tài liệu cũ như thể còn đúng.
2. **Xác định loại tài liệu và người đọc:** hướng dẫn nhà phát triển, hướng dẫn Windows (chỉ ghi bước người dùng tự thực hiện; phần chưa kiểm chứng trên Windows ghi rõ), báo cáo tuần/milestone, test report, bàn giao AI Agent, tổng hợp trạng thái. Release notes do `dacn-ci-cd-release` đảm nhiệm; skill này chỉ tham chiếu.
3. **Phân đoạn CURRENT / TARGET** trong mọi tài liệu trạng thái; liệt kê "chưa được chứng minh" (xem `CLAUDE.md` mục 3.1) khi liên quan.
4. **Đối chiếu yêu cầu đồ án:** bảng yêu cầu/phạm vi (`docs/scope/`) ↔ trạng thái (đã làm có bằng chứng / một phần / chưa) ↔ bằng chứng (file, test, issue).
5. **Mâu thuẫn:** nêu rõ khi tài liệu, issue và code khác nhau (ví dụ trạng thái sign-off giữa các nhóm), không tự "hòa giải".
6. **Bàn giao AI Agent:** tóm tắt quy tắc (`CLAUDE.md`), danh sách skill đang có, lệnh chạy chuẩn, việc đang dở, điểm cần quyết định của con người, cạm bẫy đã biết (import tên module trần, logic nhân bản có chủ ý, mẫu chưa khử định danh).
7. **Hướng dẫn Windows:** tiền điều kiện (VM, snapshot, Sysmon cố định phiên bản, Python, `pywin32`, quyền), từng bước kèm kết quả mong đợi và cách hoàn tác; đánh dấu bước có tác dụng phụ.
8. **Cập nhật `CLAUDE.md`/README:** chỉ đề xuất nội dung; sửa khi người dùng cho phép (`CLAUDE.md` mục 12).

## Nguyên tắc không được vi phạm
- Không hardcode điều dễ đổi (số test pass, trạng thái issue, tuần hiện tại) mà không kèm ngày và nguồn kiểm chứng.
- Không báo "hoàn thành"/"đã kiểm thử" khi chưa có bằng chứng; dùng `verification-before-completion`.
- Không đưa tên máy, người dùng, SID, secret, dữ liệu nội bộ vào tài liệu công khai, commit message hay PR.
- Không thay đổi phạm vi, milestone, kế hoạch 12 tuần trong tài liệu.
- Tài liệu bằng tiếng Việt; giữ nguyên thuật ngữ kỹ thuật, tên file/hàm/lệnh.

## Kiểm tra kết quả
Mọi số liệu có nguồn và ngày; liên kết/đường dẫn tồn tại (kiểm tra bằng `ls`); không có mô tả TARGET như đã hoàn thành.

## Đầu ra
Bản nháp tài liệu trong phản hồi (hoặc ghi file khi được yêu cầu, đúng thư mục `docs/` theo cấu trúc hiện có), kèm danh sách bằng chứng đã dùng và phần chưa xác minh.

## Cần hỏi người dùng
Trước khi ghi/sửa file trong `docs/`, `README.md`, `CLAUDE.md`; trước khi nêu kết luận tiến độ cho người ngoài nhóm; khi nguồn bằng chứng mâu thuẫn.

## Phối hợp với skill khác
- Trước đó: verification-before-completion
- Cùng lúc: -
- Sau đó: dacn-ci-cd-release (release notes)
