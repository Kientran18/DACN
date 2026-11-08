# EDR — Tiến độ (cập nhật sau mỗi phiên làm việc)

> Tệp này là nguồn trạng thái duy nhất giữa các phiên Claude Code. **Không dựa vào lịch sử hội thoại.** Chỉ ghi `DONE` khi có bằng chứng liên kết ở mục "Bằng chứng nghiệm thu".
> Cập nhật lần cuối: 2026-11-08 ~10:40 UTC (người dùng đã duyệt đề xuất mặc định D-01…D-14; bắt đầu PH1; **thay đổi mã chưa commit**).

## 1. Giai đoạn hiện tại

| Mục | Giá trị |
|---|---|
| Giai đoạn | **PH1 (phần còn lại cần quyết định liên nhóm) + PH2 phần chạy được trên Linux — xong**; PH1 (`IN_PROGRESS`); PH0 đã được người dùng chấp nhận theo đề xuất mặc định |
| Task đang làm | PH1-T02 (`REVIEW`, chưa commit), PH2-T05 (`IN_PROGRESS`, chờ người dùng chạy trên VM) |
| Task kế tiếp | **PH1-T03** (test entropy, cần Data review), **PH1-T08** (chia sẻ code `poc/` ↔ `src/`, D-03(a) đã chọn), **PH1-T11** (marker `windows`), rồi PH1-T09 (config/log) |
| Branch | Đang làm trên nhánh con `fix/c002-collector-reason-code` (tạo từ `claude_implement`, **chỉ local**). Nhánh tích hợp: **`claude_implement`** (tạo từ `main` ngày 2026-11-08; chứa kế hoạch và mọi hiện thực của Claude; chỉ đưa vào `main` ở bản cuối cùng theo quyết định của người dùng). `claude/great-lamport-7fps1l` đã hoàn tất (PR #43, #44, #45 đã merge) |
| PR liên quan | Không có PR nào cho `claude_implement` (đẩy trực tiếp theo chỉ định của người dùng). PR #36 (kế hoạch 12 tuần v2) vẫn mở, chưa merge |
| Issue liên quan mở | #26, #27, #28, #29 (W05), #38, #39, #40 (W06–W07) |

## 2. Baseline kiểm thử

| Lệnh (từ thư mục gốc) | Thời điểm | Kết quả | Môi trường |
|---|---|---|---|
| `python -m pytest -q poc/sysmon-collector` | 2026-11-08 ~09:55 UTC | 25 pass, 1 fail (`test_collector_errors_use_reason_codes`) | Linux, Python 3.13, pytest 9.2 |
| `python -m pytest -q tests/` | 2026-11-08 ~09:55 UTC | 5 pass, 1 fail (`test_06_time_skew_warning_and_shannon_entropy`) | như trên |

| `python -m pytest -q poc/sysmon-collector` (sau PH1-T02) | 2026-11-08 ~10:37 UTC | **26 pass, 0 fail** | Linux, Python 3.13 |
| `python -m pytest -q tests/` (sau thêm test script Windows) | 2026-11-08 ~10:37 UTC | 10 pass, 1 fail (`test_06` entropy, chưa sửa: PH1-T03) | Linux, Python 3.13 |

Nguyên nhân hai lỗi đã xác minh: xem [Audit mục 3](EDR_AUDIT_REPORT.md). **Chưa có kết quả nào trên Windows.**

## 3. Tổng quan task

Chi tiết trạng thái từng task: [EDR_TASK_BACKLOG.md](EDR_TASK_BACKLOG.md). Tại thời điểm này: 104 task.

| Trạng thái | Số task |
|---|---|
| TODO | 89 |
| IN_PROGRESS | 1 (PH2-T05) |
| BLOCKED | 2 (ML-T06, ML-T07) |
| REVIEW | 1 (PH2-T06) |
| DONE | 11 (PH1-T01, T02, T03, T08, T09, T11; PH2-T01, T02, T03, T04, T07) |

## 4. Task đã hoàn thành

| Task | Bằng chứng |
|---|---|
| PH1-T01 Baseline kiểm thử | Mục 2 (đo 2026-11-08 ~09:55 UTC trước khi sửa; ~10:37 UTC sau PH1-T02) |

**Đang chờ review (chưa commit):**
- PH1-T02 — `poc/sysmon-collector/sysmon_collector_poc.py`: thêm tiền tố `C-002` vào thông báo thiếu EventID/TimeCreated (1 dòng). TDD: test `test_collector_errors_use_reason_codes` đỏ (10:36 UTC) → xanh; toàn bộ suite collector 26/26 pass; không đổi schema/contract.
- PH2-T05 — `scripts/windows/verify_windows_env.py` + `tests/test_verify_windows_env.py` (5 test pass trên Linux; các kiểm tra Windows trả SKIP). **Chưa chạy trên Windows** nên chưa tính DONE.

## 5. Task bị chặn

| Task | Lý do | Hành động cần |
|---|---|---|
| ML-T06, ML-T07 | Chờ người dùng huấn luyện và cung cấp mô hình (ML-T05) | Người dùng làm theo [AI_TRAINING_GUIDE.md](AI_TRAINING_GUIDE.md) khi muốn bắt đầu nhánh ML |

## 6. Quyết định cần người dùng xác nhận

D-01…D-14 trong [EDR_MASTER_PLAN.md mục 10](EDR_MASTER_PLAN.md). Cần sớm nhất: **D-01 (phạm vi), D-03 (cấu trúc code), D-04 (stack API/UI), D-05 (định dạng rule), D-07 (hostname), D-13 (môi trường Windows)**.

## 7. Công việc tiếp theo

1. Người dùng xem xét và phê duyệt bộ kế hoạch (hoặc yêu cầu chỉnh sửa).
2. ~~Người dùng trả lời D-01…~~ **Đã chốt theo đề xuất (2026-11-08).**
3. **Người dùng:** nâng RAM VM lên 4 GB (khuyến nghị), chụp snapshot "clean", cài Python + `pywin32` và Sysmon theo hướng dẫn, chạy `python scripts\windows\verify_windows_env.py --out verify_report.json` (một lần thường, một lần PowerShell Administrator) và gửi `verify_report.json` + đầu ra màn hình.
4. Claude: PH1-T03, PH1-T08, PH1-T11, PH1-T09 (và PH2-T01…T04 sau khi PH1-T08 xong); commit/push chỉ khi người dùng yêu cầu.

## 8. Bằng chứng nghiệm thu

Chưa có bằng chứng triển khai. Khi có, ghi theo mẫu:

| Task / Test | Lệnh hoặc quy trình | Môi trường (Linux/Windows, phiên bản) | Thời điểm | Kết quả | Liên kết (commit/PR/tệp đầu ra) |
|---|---|---|---|---|---|
| — | — | — | — | — | — |

## 9. Nhật ký phiên

| Ngày | Phiên | Nội dung | Kết quả |
|---|---|---|---|
| 2026-11-08 | Kiểm toán + lập kế hoạch | Chạy test, kiểm tra chuỗi Bronze→Silver, DDL, rà soát issue/PR; tạo 8 tệp trong `docs/implementation/` | Chờ phê duyệt; không sửa mã nguồn |
| 2026-11-08 | Bắt đầu PH1 | Người dùng duyệt D-01…D-14 theo đề xuất; cung cấp cấu hình VM; PH1-T01 DONE; PH1-T02 sửa `C-002` (REVIEW); viết script `verify_windows_env.py` (PH2-T05) | Chưa commit; chờ người dùng chạy script trên VM |
| 2026-11-08 | PH1 (đợt 2) | PH1-T03 (test entropy dùng so sánh tương đối + giá trị biết trước, lý do ghi trong test), PH1-T08/T11 (`conftest.py`, `pytest.ini`, marker `windows`, `.gitignore`), PH1-T09 (`src/common/config.py`, `log.py`). `python -m pytest -q` → 46 pass (Linux) | Đã commit vào `claude_implement`; còn PH1-T04/05/06/07/10/12 cần quyết định liên nhóm |
| 2026-11-08 | PH2 (phần Linux) | `src/agent/`: sources (base/fake/file/eventlog), `bronze_writer` (segment+manifest+verify+recover), `checkpoint`, `runner`, `__main__`. `python -m pytest -q` → 66 pass (Linux). `EventLogSource` kiểm bằng API giả; Windows thật **UNKNOWN** tới PH2-T09. Mã lỗi theo W5-01 (C-001/002/005/006); mã nội bộ mới `R-*` (phục hồi), `A-001/002` (agent) là mở rộng của mình, cần Software duyệt; log lỗi collector ghi ở `bronze/errors/` thay vì `quarantine/collector` | Đã commit vào `claude_implement`; còn PH2-T05/T09 (Windows), T08, T10 |
