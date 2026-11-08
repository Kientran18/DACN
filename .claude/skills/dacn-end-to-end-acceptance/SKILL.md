---
name: dacn-end-to-end-acceptance
description: Dùng khi lập kế hoạch và nghiệm thu kiểm thử tích hợp end-to-end của DACN - luồng Agent → Ingestion → Pipeline → Detection → Alert → Dashboard, response ở chế độ an toàn, contract verification, regression liên module, báo cáo nghiệm thu milestone. Không tuyên bố cả hệ thống hoạt động khi mới kiểm thử từng module.
---

# Nghiệm thu end-to-end

## Hiện trạng
Mới có các mắt xích rời rạc ở mức PoC (collector file mode, Bronze contract, adapter, validator). Chưa có chuỗi chạy từ XML → Silver bền vững → DetectionResult → alert → raw cho một kịch bản (mục tiêu W08 trong kiến trúc v2 mục 11). Nghiệm thu phải phản ánh đúng điều đó.

## Đọc trước
`docs/architecture/local-edr-reference-architecture-v2.md` mục 10–11 (blockers, roadmap, test matrix DATA/DET/TRC/OPS/RSP), `docs/research/cyber/w5/05-review-handoff-and-dod.md`, `docs/architecture/w5/contracts/README.md` (bảng sign-off), `docs/research/software/w5/05-integration-feasibility-and-open-issues-w05.md`, `docs/report/` (báo cáo tuần), issue/milestone liên quan qua công cụ GitHub.

## Quy trình
1. **Xác định chuỗi cần nghiệm thu** và chia thành mắt xích; với mỗi mắt xích ghi trạng thái: có code+test chạy lại được / chỉ thiết kế / chưa có. Chuỗi chỉ được gọi "end-to-end" khi **mọi** mắt xích có thật và dữ liệu đi qua cả chuỗi.
2. **Kịch bản:** chọn một kịch bản hẹp, an toàn, có nhãn (ví dụ chuỗi file→execute→delete trên VM lab theo DET-010), kèm dữ liệu vào, kết quả mong đợi tại từng mắt xích, và điều kiện thiếu telemetry.
3. **Contract verification tại từng giao diện:** Raw→Bronze (schema), Bronze→Silver (adapter, validator), Silver→Detection (trường bắt buộc), Detection→Alert (trường truy vết), Alert→UI/API. Dùng `dacn-contract-review` cho hai giao diện đầu.
4. **Truy vết hai chiều:** từ alert ra `event_id`, rồi Bronze, rồi raw XML, và ngược lại (TRC-01). Đây là tiêu chí cốt lõi.
5. **Hành vi lỗi liên module:** crash/restart, bản ghi lỗi, trùng lặp, log reset, đầy đĩa (OPS-01); ghi expected vs observed. Response chỉ ở dry-run (RSP-01).
6. **Regression liên module:** chạy toàn bộ test hiện có + ca E2E; so với lần trước bằng cùng lệnh; ghi hồi quy mới.
7. **Phân tích lỗi liên module:** tìm module gây lỗi bằng bằng chứng (`systematic-debugging`), không kết luận theo triệu chứng.
8. **Acceptance criteria:** lấy từ issue/milestone, đối chiếu từng tiêu chí Đạt/Không đạt/Chưa chạy kèm bằng chứng.

## Nguyên tắc không được vi phạm
- Không tuyên bố "hệ thống hoạt động" khi chỉ kiểm thử module độc lập; nêu rõ phạm vi (module nào, dữ liệu nào, môi trường nào).
- Mọi kết quả kèm lệnh, đầu vào (hash hoặc đường dẫn), phiên bản, thời điểm, môi trường (Linux hay Windows VM thật; synthetic hay lab).
- Không chạy mô phỏng tấn công hay response thật; phần cần Windows do người dùng thực hiện (`dacn-windows-integration-test`).
- Không sửa code hay test để cho nghiệm thu qua.

## Kiểm tra kết quả
Bảng nghiệm thu không có ô "Đạt" thiếu bằng chứng; mọi mắt xích "chưa có" xuất hiện trong phần hạn chế.

## Đầu ra
```markdown
# Kế hoạch/báo cáo nghiệm thu E2E — [milestone], [ngày]
## Phạm vi và chuỗi (mắt xích: có/thiết kế/chưa có)
## Kịch bản và dữ liệu (nhãn, nguồn)
## Kết quả theo giao diện (contract) và theo tiêu chí nghiệm thu
## Truy vết hai chiều (ví dụ cụ thể)
## Hồi quy, lỗi liên module
## Hạn chế và việc còn lại
```

## Cần hỏi người dùng
Chốt kịch bản và tiêu chí nghiệm thu, thêm fixture vào repository, ghi báo cáo vào `docs/report/`, chuyển trạng thái issue/milestone (chỉ người dùng thực hiện).
