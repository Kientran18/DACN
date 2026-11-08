---
name: dacn-windows-integration-test
description: Dùng khi lập kế hoạch, hướng dẫn thực hiện hoặc ghi nhận kết quả kiểm thử tích hợp trên Windows 10/11 VM thật cho DACN - Sysmon, quyền đọc Event Log, file mode và live mode, đối chiếu raw XML với bản ghi chuẩn hóa. Claude lập test plan và mẫu báo cáo; người dùng tự chạy trên VM lab và gửi kết quả.
---

# Kiểm thử tích hợp trên Windows

## Ranh giới với skill khác
`dacn-sysmon-telemetry` lo mapping và kiểm thử file mode trên mọi OS. Skill này lo phần **chỉ kiểm chứng được trên Windows**: live mode, quyền, Sysmon thật, Event Log, hành vi khi khởi động lại. Claude chạy trên Linux nên **không tự chạy được** các bước này.

## Đọc trước
`docs/research/software/w1/05-windows-lab-environment.md` (VM, snapshot sạch, Sysmon cố định phiên bản), `docs/research/software/w5/04-error-recovery-and-operational-notes.md` (kịch bản crash/restart), `docs/research/software/w5/05-integration-feasibility-and-open-issues-w05.md`, `docs/research/cyber/w4/03-detection-hunting-response-va-ke-hoach-test.md` mục 3 (quy trình Atomic Red Team an toàn), `poc/sysmon-collector/scripts/*.ps1` (chỉ đọc), `poc/sysmon-collector/configs/sysmon-config.xml`, `references/samples/raw/`.

## Quy trình
1. **Tiền điều kiện** (người dùng xác nhận bằng văn bản): VM cô lập, snapshot sạch đã tạo, build Windows, phiên bản Sysmon, phiên bản Python, `pywin32` đã cài, tài khoản và quyền (Administrator hay Event Log Readers), Sysmon dùng config của repository. Thiếu thông tin nào thì ghi "chưa rõ", không điền thay.
2. **Test plan** theo nhóm, mỗi ca có: ID, mục tiêu, bước, kết quả kỳ vọng, dữ liệu cần thu, tiêu chí đạt/không đạt:
   - Quyền: đọc channel khi có/không có quyền → kỳ vọng `PermissionError` rõ ràng (C-006).
   - File mode: `wevtutil`/`Get-WinEvent` export → collector → Bronze → adapter → validator.
   - Live mode: `--mode live` với `--max` nhỏ; so sánh với export cùng thời điểm.
   - Hoạt động vô hại tạo telemetry: process, file, registry (khóa test trong HKCU rồi xóa), network/DNS tới đích lab; dùng `run-poc-activities.ps1` chỉ sau khi người dùng đã đọc và đồng ý.
   - Đối chiếu: với mỗi sự kiện, `raw_xml` ↔ `event_data` ↔ bản ghi chuẩn hóa ↔ Silver (so field, `event_id`, `record_id`, `time_created`).
   - Bền vững (khi đã có code): kill giữa lúc ghi, restart, bản ghi trùng, bản ghi lỗi, log bị xóa/reset trên VM.
3. **Hướng dẫn chạy** gửi người dùng: lệnh chính xác, thư mục đầu ra ngoài repository, cách rollback về snapshot sau mỗi nhóm. Lệnh có tác dụng phụ (xóa log, đổi audit) phải đánh dấu rõ và chỉ đưa ra khi người dùng yêu cầu.
4. **Thu kết quả:** người dùng dán đầu ra và tệp; Claude phân tích, không suy diễn phần chưa nhận được.

## Nguyên tắc không được vi phạm
- Không chạy script PowerShell, không chạy live mode, không giả lập kết quả Windows. Kết quả "đã chạy trên Windows" chỉ ghi khi có đầu ra thật do người dùng cung cấp, kèm: build Windows, phiên bản Sysmon/Python, lệnh, thời điểm.
- Phân biệt ba nhãn trong mọi báo cáo: **synthetic**, **mẫu lab đã xuất**, **live trên Windows**. Không trộn.
- Chỉ hoạt động an toàn trên VM lab: không mã độc thật, không thay đổi cấu hình hệ thống ngoài VM, không tắt Defender hay audit trên máy dùng hằng ngày.
- Không đưa tên máy, người dùng, SID thật vào báo cáo/tài liệu (mẫu hiện chưa khử định danh).

## Kiểm tra kết quả
Mỗi ca có kết quả Đạt / Không đạt / Chưa chạy, kèm bằng chứng. Mọi lệch giữa raw và normalized được liệt kê theo field. Nếu có lỗi lạ chuyển sang `systematic-debugging`.

## Đầu ra
```markdown
# Báo cáo kiểm thử tích hợp Windows — [ngày]
## Môi trường (build, Sysmon, Python, quyền, snapshot)
## Ca kiểm thử (ID | nhãn dữ liệu | lệnh | kỳ vọng | quan sát | kết luận)
## Đối chiếu raw ↔ normalized (lệch theo field)
## Chưa chạy / chưa kiểm chứng
## Rủi ro và việc tiếp theo
```

## Cần hỏi người dùng
Trước khi đề xuất lệnh có tác dụng phụ (xóa log, bật audit, cài Sysmon), trước khi ghi báo cáo hay mẫu vào `docs/`, trước khi chạy bất kỳ kịch bản mô phỏng tấn công nào (kể cả Atomic Red Team: duyệt từng test GUID).
