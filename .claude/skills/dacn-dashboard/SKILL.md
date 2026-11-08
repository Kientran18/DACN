---
name: dacn-dashboard
description: Thiết kế giao diện quản lý EDR DACN. Tự dùng khi làm màn hình tổng quan endpoint, danh sách alert, telemetry explorer, process tree, timeline, quản lý rule, hàng chờ response, lọc, tìm, phân trang, trạng thái loading, lỗi, rỗng. Dữ liệu mẫu phải gắn nhãn rõ, không giả làm dữ liệu thật. Không dùng cho thiết kế API (dacn-backend-api).
---

# Dashboard EDR

## Hiện trạng
Chưa có UI. Tài liệu Software nêu UI Streamlit chỉ đọc Gold/snapshot, plotly/networkx cho cây tiến trình (`docs/research/software/w5/03-local-storage-and-pipeline-integration-design.md`, `05-integration-feasibility-and-open-issues-w05.md`); `docs/research/data/w1/requirements.txt` có `streamlit`. Chưa có ADR chốt công nghệ UI; kiểm tra lại trước khi chọn. Môi trường lab: 4 GB RAM, 2 core (`docs/research/software/w1/05-windows-lab-environment.md`).

## Đọc trước
`docs/architecture/local-edr-reference-architecture-v2.md` mục 7 (investigation, response), 8.3 (quyền, privacy); `docs/research/cyber/w5/02-alert-to-source-traceability-requirements.md` mục 3; `dacn-alert-incident-management`, `dacn-threat-hunting`, `dacn-backend-api`; `docs/scope/phase-1-scope.md` (threat hunting cơ bản).

## Quy trình
1. **Người dùng và tác vụ:** analyst (đọc), approver (response), operator (health). Liệt kê tác vụ then chốt: xem alert → mở bằng chứng → process tree → timeline → quyết định.
2. **Màn hình tối thiểu theo phạm vi:** tổng quan sức khỏe và độ phủ telemetry (kèm khoảng trống), danh sách alert (lọc: host, thời gian, severity, rule, hash, process), chi tiết alert/incident (bằng chứng, quan sát vs suy luận vs thiếu dữ liệu), telemetry explorer, process tree, rule (chỉ đọc trong production), hàng chờ response (disabled mặc định).
3. **Nguồn dữ liệu:** đọc từ API/snapshot (không giữ khóa ghi DuckDB). Mọi bảng có cột nguồn/nhãn dữ liệu.
4. **Trạng thái giao diện:** loading, rỗng (giải thích vì sao rỗng: chưa có dữ liệu hay bộ lọc), lỗi (không lộ stack), dữ liệu cũ (hiện thời điểm cập nhật). Phân trang và giới hạn dòng cho tập lớn; không tải toàn bộ Silver vào bộ nhớ.
5. **Thể hiện bằng chứng:** tách rõ ba loại (quan sát, suy luận, thiếu dữ liệu) bằng nhãn chữ, không chỉ dựa màu; liên kết `event_id` → raw XML có kiểm soát quyền và audit.
6. **Hành động nguy hiểm:** nút response ẩn/vô hiệu mặc định; mỗi lần cần xác nhận, hiển thị mục tiêu đầy đủ và hệ quả (`dacn-response-safety`).
7. **Trực quan hóa:** chọn biểu đồ theo câu hỏi cần trả lời; trục, đơn vị, múi giờ UTC ghi rõ; khả dụng (tương phản, không phụ thuộc chỉ màu). Dùng skill `dataviz` nếu có biểu đồ.
8. **Hiệu năng:** đo thời gian tải và RAM trên VM trước khi nói "mượt"; cache truy vấn có hạn.

## Nguyên tắc không được vi phạm
- Dữ liệu synthetic/mẫu luôn được gắn nhãn "DỮ LIỆU MẪU" nổi bật; không giả lập số liệu live, không trình bày số liệu bịa như đo thật.
- Không chèn dữ liệu nhạy cảm thật (tên máy, người dùng) vào ảnh chụp, demo hay tài liệu công khai.
- Không thêm thư viện front-end/CDN, build step hay service khi chưa được duyệt; không tải tài nguyên từ Internet khi chạy.
- UI không sửa Bronze/Silver, không sửa rule production.

## Kiểm tra kết quả
Chạy UI với fixture, kiểm tra từng trạng thái (rỗng, lỗi, nhiều dữ liệu), kiểm tra nhãn dữ liệu mẫu, kiểm tra không có hành động response hoạt động. Không tuyên bố "hoạt động" khi chưa chạy thật; ghi môi trường kiểm tra.

## Đầu ra
Wireframe/mô tả màn hình, bảng ánh xạ màn hình → nguồn dữ liệu → quyền, danh sách trạng thái, hoặc code theo yêu cầu cụ thể.

## Cần hỏi người dùng
Chọn công nghệ UI và thư viện, thêm trang hiển thị raw XML, bật bất kỳ thao tác response, hoặc đưa ảnh chụp màn hình vào tài liệu.

## Phối hợp với skill khác
- Trước đó: dacn-backend-api
- Cùng lúc: dacn-threat-hunting (luồng điều tra), dataviz (biểu đồ)
- Sau đó: dacn-end-to-end-acceptance
