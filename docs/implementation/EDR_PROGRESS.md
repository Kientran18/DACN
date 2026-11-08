# EDR — Tiến độ (cập nhật sau mỗi phiên làm việc)

> Tệp này là nguồn trạng thái duy nhất giữa các phiên Claude Code. **Không dựa vào lịch sử hội thoại.** Chỉ ghi `DONE` khi có bằng chứng liên kết ở mục "Bằng chứng nghiệm thu".
> Cập nhật lần cuối: 2026-11-08 (kiểm toán Giai đoạn 0 và lập kế hoạch; **chưa có mã triển khai nào**).

## 1. Giai đoạn hiện tại

| Mục | Giá trị |
|---|---|
| Giai đoạn | **PH0 — Kiểm toán và lập kế hoạch** (trạng thái: `REVIEW`, chờ người dùng phê duyệt) |
| Task đang làm | Không có |
| Task kế tiếp (sau khi kế hoạch được duyệt) | **PH1-T01** (baseline), rồi **PH1-T02** (sửa `C-002`) |
| Branch | Nhánh tích hợp: **`claude_implement`** (tạo từ `main` ngày 2026-11-08; chứa kế hoạch và mọi hiện thực của Claude; chỉ đưa vào `main` ở bản cuối cùng theo quyết định của người dùng). `claude/great-lamport-7fps1l` đã hoàn tất (PR #43, #44, #45 đã merge) |
| PR liên quan | Không có PR nào cho `claude_implement` (đẩy trực tiếp theo chỉ định của người dùng). PR #36 (kế hoạch 12 tuần v2) vẫn mở, chưa merge |
| Issue liên quan mở | #26, #27, #28, #29 (W05), #38, #39, #40 (W06–W07) |

## 2. Baseline kiểm thử

| Lệnh (từ thư mục gốc) | Thời điểm | Kết quả | Môi trường |
|---|---|---|---|
| `python -m pytest -q poc/sysmon-collector` | 2026-11-08 ~09:55 UTC | 25 pass, 1 fail (`test_collector_errors_use_reason_codes`) | Linux, Python 3.13, pytest 9.2 |
| `python -m pytest -q tests/` | 2026-11-08 ~09:55 UTC | 5 pass, 1 fail (`test_06_time_skew_warning_and_shannon_entropy`) | như trên |

Nguyên nhân hai lỗi đã xác minh: xem [Audit mục 3](EDR_AUDIT_REPORT.md). **Chưa có kết quả nào trên Windows.**

## 3. Tổng quan task

Chi tiết trạng thái từng task: [EDR_TASK_BACKLOG.md](EDR_TASK_BACKLOG.md). Tại thời điểm này: 104 task, **tất cả `TODO`** (trừ `ML-T06`, `ML-T07` là `BLOCKED` do phụ thuộc người dùng huấn luyện mô hình).

| Trạng thái | Số task |
|---|---|
| TODO | 102 |
| IN_PROGRESS | 0 |
| BLOCKED | 2 |
| REVIEW | 0 |
| DONE | 0 |

## 4. Task đã hoàn thành

Chưa có.

## 5. Task bị chặn

| Task | Lý do | Hành động cần |
|---|---|---|
| ML-T06, ML-T07 | Chờ người dùng huấn luyện và cung cấp mô hình (ML-T05) | Người dùng làm theo [AI_TRAINING_GUIDE.md](AI_TRAINING_GUIDE.md) khi muốn bắt đầu nhánh ML |

## 6. Quyết định cần người dùng xác nhận

D-01…D-14 trong [EDR_MASTER_PLAN.md mục 10](EDR_MASTER_PLAN.md). Cần sớm nhất: **D-01 (phạm vi), D-03 (cấu trúc code), D-04 (stack API/UI), D-05 (định dạng rule), D-07 (hostname), D-13 (môi trường Windows)**.

## 7. Công việc tiếp theo

1. Người dùng xem xét và phê duyệt bộ kế hoạch (hoặc yêu cầu chỉnh sửa).
2. Người dùng trả lời D-01, D-03, D-04, D-05, D-07, D-13.
3. Claude: PH1-T01 → PH1-T02 (trên branch riêng, chưa commit khi chưa được yêu cầu).
4. Người dùng (song song, độc lập): chuẩn bị VM Windows 10 và chạy PH2-T05 (spike `pywin32`) khi Claude cung cấp script.

## 8. Bằng chứng nghiệm thu

Chưa có bằng chứng triển khai. Khi có, ghi theo mẫu:

| Task / Test | Lệnh hoặc quy trình | Môi trường (Linux/Windows, phiên bản) | Thời điểm | Kết quả | Liên kết (commit/PR/tệp đầu ra) |
|---|---|---|---|---|---|
| — | — | — | — | — | — |

## 9. Nhật ký phiên

| Ngày | Phiên | Nội dung | Kết quả |
|---|---|---|---|
| 2026-11-08 | Kiểm toán + lập kế hoạch | Chạy test, kiểm tra chuỗi Bronze→Silver, DDL, rà soát issue/PR; tạo 8 tệp trong `docs/implementation/` | Chờ phê duyệt; không sửa mã nguồn |
