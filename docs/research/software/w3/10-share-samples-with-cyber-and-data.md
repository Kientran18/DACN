# Bàn giao mẫu và review Cyber Data

## Gói đã có trên repository

- [Raw XML và manifest](../../../../references/samples/raw).
- [Bốn JSON thật](../../../../references/samples/json): Process 3, File 2, Registry 2, Network 1.
- [Báo cáo activities và config](../../../../references/samples/evidence).
- Windows 10.0.19045, Sysmon 15.22; marker EDR_POC_20261018_021142.
- sanitized=false; đây là dữ liệu lab có tên máy/tài khoản/đường dẫn. Chưa có bản sanitize được nghiệm thu.

## Review cần thực hiện

Data đối chiếu schema theo Event ID và các tên hostname/src_ip/src_port; kiểm tra missing/null, UUIDv5, timestamp, process_guid và bảo toàn raw_data. Cyber đối chiếu mẫu với [MITRE Matrix v2](../../cyber/mitre-detection-matrix-v2.md), đặc biệt DET-007/008 và mức độ bằng chứng của từng hành vi. Software xác nhận config thực dùng, đường dẫn tái lập và các giới hạn còn chưa thử.

Không tự ghi PASS hoặc thay người review. [Biểu mẫu review chung](../../../project/week-01-03-review-and-ownership.md) ghi người, ngày, link và yêu cầu thay đổi. Báo cáo Data cũ tuyên bố đồng thuận chưa đủ để chứng minh mọi người đã kiểm tra chi tiết.

## Mục còn mở

- Python live mode trên Windows.
- Kết quả E1–E10: hiện mới có một số bằng chứng sự kiện, chưa hoàn thành thí nghiệm kiểm soát.
- Xác nhận tên trường, event_type và nullability theo schema hiệu chỉnh.
- Xác nhận ma trận v2 và quyết định giới hạn detection.
