# Báo cáo tuần 3 schema và telemetry

Cập nhật 2026-10-19. Trạng thái: đã có mẫu và kết quả collector file mode; chờ review liên nhóm. Thay thế tuyên bố DoD 100% trước đây.

## Đã có bằng chứng

- references/samples/raw/export_manifest.json ghi Windows 10.0.19045, Sysmon 15.22.
- references/samples/evidence/poc_run_20261018_021142.json ghi 5 bước ok.
- Raw XML có ID 1/5/11/26/29/12/13/3/22/4/16.
- Collector tái tạo đúng bốn JSON ID 1/11/13/3 với số lượng 3/2/2/1.
- Schema, mapping và dictionary có tài liệu trong docs/architecture/w3.
- ADR về UUIDv5, process correlation và raw_data có trong docs/decisions.

## Hiệu chỉnh contract

[Schema](../architecture/w3/endpoint_event_schema_v1.md) quy định required theo Event ID: ID 5 không bắt buộc parent, ID 22 không bắt buộc socket fields. Tên JSON chuẩn là hostname/src_ip/src_port. [Mapping](../architecture/w3/sysmon_raw_to_silver_mapping_v1.md) tách payload data và adapter Silver dự kiến; File.operation là dữ liệu dẫn xuất nếu cần.

raw_data chỉ giữ EventData; XML gốc được lưu riêng. UUIDv5 chưa xử lý log reset/clone host. Chuẩn UTC không loại bỏ sai đồng hồ nguồn.

## Chưa có bằng chứng nghiệm thu

- Không tìm thấy code pipeline/Pydantic/DuckDB trong main để tái lập các tuyên bố kiểm thử hoặc ingest trong báo cáo cũ.
- Python live mode chưa có kết quả trên Windows.
- Các mẫu an toàn không chứng minh detection của cả 13 techniques.
- Cyber/Data/Software chưa có đủ xác nhận cụ thể người/ngày/link cho bản hiệu chỉnh này. Không giữ các nhãn PASS (Confirmed) thay cho review thực tế.
- Giới hạn E1–E10 còn cần kiểm chứng.

## Tuần 4

Đánh giá Wazuh, Sysmon, osquery, Velociraptor, Atomic Red Team theo cùng bộ tiêu chí; đóng góp đánh giá Data và review M1. Không coi triển khai Gold/feature store là yêu cầu tuần 4. Thiết kế pipeline thuộc tuần 5, feature/AI theo backlog kế hoạch.

Theo dõi #13–#16, #19–#22 và [review chung](../project/week-01-03-review-and-ownership.md).
