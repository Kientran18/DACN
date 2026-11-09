# EDR — Hạn chế và rủi ro (PH12-T04)

## 1. Hạn chế đã biết

| # | Hạn chế | Tác động | Hướng xử lý |
|---|---|---|---|
| L1 | Chưa kiểm chứng trên Windows (live Event Log, `WinProcessApi`, script lab, Sysmon config, hướng dẫn cài) | Không thể tuyên bố hệ thống chạy trên Windows | Người dùng chạy `WINDOWS_ACCEPTANCE_CHECKLIST.md` |
| L2 | Rule đều `synthetic_only`; DET-010 cửa sổ 300 s chưa hiệu chỉnh; DET-101 do Claude đánh số, chờ Cyber xác nhận | Không có số liệu chất lượng phát hiện | Chạy kịch bản trên VM, hiệu chỉnh |
| L3 | Telemetry Sysmon không có file write/entropy; DET-004/007/008 bị chặn | Không phát hiện mã hóa tệp | Ngoài phạm vi MVP |
| L4 | Agent user-space dựa Sysmon, không chống giả mạo; audit hash-chain chỉ *phát hiện* sửa đổi | Kẻ có quyền admin có thể vô hiệu hóa/sửa | Ghi nhận trong báo cáo; không tuyên bố tamper-resistant |
| L5 | API chỉ loopback, không TLS; một kết nối DuckDB dùng chung bằng khóa toàn cục | Không dùng từ xa; thông lượng bị giới hạn | Đủ cho local-first |
| L6 | Response thật chưa từng chạy; *Add/Remove whitelist* mới chỉ test với tệp ioc.yaml tạm; block hash chỉ là phát hiện (mã chuyển sang `experimental/`, chưa nối vào hệ thống) | Chưa đủ 4 hành động của mục tiêu ban đầu | Cần quyết định và VM |
| L7 | VM 2 GB RAM (dưới 4 GB khuyến nghị); chưa đo CPU/RAM/độ trễ | Rủi ro hiệu năng chưa lượng hóa | PH10-T05 và đo trên VM |
| L8 | Retention chỉ có chế độ dry-run (báo cáo, không xóa); chưa có xóa thật và ngưỡng do người dùng quyết định | Bronze tăng không giới hạn nếu không dọn tay | Quyết định ngưỡng, rồi mới viết bước xóa (ADR 0003) |
| L9 | Mốc dedup alert 600 s, severity, ngưỡng là giá trị tạm | Có thể gộp/tách alert chưa tối ưu | Hiệu chỉnh trên dữ liệu thật |
| L10 | Nhánh ML: chỉ có giao diện, tắt mặc định, chưa có mô hình | Không có anomaly detection | Người dùng huấn luyện (ML-T05) |

## 2. Phụ thuộc quyết định liên nhóm (chưa được duyệt)

DDL v1.2 (hiện `SilverStore` phụ thuộc đề xuất này) · schema `DetectionResult` · chuẩn hóa hostname (D-07) · cắt µs · Event 4/16 và tên event type (Q-X3) · mã lỗi mới `R-*`/`A-*` và vị trí `bronze/errors/` · số hiệu DACN-DET-101 · hợp đồng Bronze 1.0 chưa phê duyệt chéo · ADR 0004/0007.

## 3. Rủi ro

| Rủi ro | Khả năng | Ảnh hưởng | Giảm thiểu hiện có |
|---|---|---|---|
| Lỗi chỉ lộ trên Windows (đường dẫn, quyền, ctypes) | Cao | Cao | Cách ly lớp `_Api`; checklist Windows; chưa đủ |
| Response nhầm mục tiêu hệ thống | Thấp | Rất cao | Hai khóa, allowlist bảo vệ, xác minh danh tính, thư mục lab, mặc định dry-run |
| Rò rỉ định danh trong mẫu/ảnh chụp | Trung bình | Trung bình | Log bỏ CommandLine/user; checklist che định danh; mẫu cũ trong `references/` chưa khử hoàn toàn |
| Kết luận quá mức từ kết quả synthetic | Trung bình | Cao | Nhãn mức bằng chứng L/W, PARTIAL, báo cáo nêu rõ phần không chứng minh |
| Bị tuyên bố "đã hoàn thành" khi chưa nghiệm thu W | Trung bình | Cao | Ma trận nghiệm thu nêu điều kiện sẵn sàng chưa đạt |
