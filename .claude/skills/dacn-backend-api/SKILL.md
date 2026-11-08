---
name: dacn-backend-api
description: Thiết kế API cục bộ của DACN. Tự dùng khi cần API contract, truy vấn sự kiện, alert, rule, health, xác thực, phân quyền, validate input, xử lý lỗi, kiểm thử API. Chưa có quyết định framework nên kiểm tra stack và ADR trước. Không dùng cho giao diện (dacn-dashboard) hay thiết kế hành động response (dacn-response-safety).
---

# Backend API (local-first)

## Hiện trạng
Không có API hay backend trong repository. Tài liệu Software nhắc **REST API mỏng cục bộ trên DuckDB** như hướng "nếu sau này cần" (`docs/research/software/w4/03-tong-hop-y-tuong-kien-truc-tai-su-dung.md`) và UI Streamlit đọc Gold/snapshot (`w5/03-local-storage-and-pipeline-integration-design.md`). Chưa có ADR chọn framework; không có `requirements.txt` gốc ở thời điểm rà soát (xác minh lại).

## Đọc trước
`docs/architecture/local-edr-reference-architecture-v2.md` mục 3 (phạm vi tin cậy C), 8, 9; ADR 0005, 0007; `docs/research/software/w5/03-local-storage-and-pipeline-integration-design.md` (single-writer DuckDB, snapshot); `docs/research/software/w4/01-bao-cao-danh-gia-kien-truc-cong-cu.md`; `dacn-alert-incident-management`, `dacn-security-review`.

## Quy trình
1. **Có thật sự cần API?** So với CLI hoặc thư viện nội bộ gọi trực tiếp (modular monolith, ADR 0007 PROPOSED). Nêu lựa chọn kèm chi phí; để người dùng quyết.
2. **Xác định consumer và tài nguyên:** UI/CLI (vai trò analyst chỉ đọc, approver đặc quyền), pipeline. Tài nguyên: events (Silver), alerts/incidents (Gold), rules (read-only trong production), health/metrics, response actions (disabled mặc định).
3. **Contract trước code:** đường dẫn, phương thức, tham số lọc (host, thời gian, `process_guid`, hash, rule, severity), phân trang có giới hạn, sắp xếp, mã lỗi, ví dụ request/response. Công nghệ chưa chốt: viết dạng OpenAPI/bảng trung lập framework, ghi điều kiện để chọn (đã có trong stack? chạy tốt 4 GB RAM? Windows?).
4. **Truy cập dữ liệu:** DuckDB single-writer; API đọc snapshot hoặc read-only; truy vấn tham số hóa, không ghép chuỗi SQL; giới hạn kích thước và thời gian truy vấn.
5. **Xác thực/phân quyền:** bind `127.0.0.1`; token hoặc cơ chế cục bộ do người dùng chọn; tách quyền đọc và quyền response; không nhận rule/config từ request không xác thực; không có endpoint remote shell.
6. **Validate input và lỗi:** kiểm tra kiểu, độ dài, enum; lỗi có mã ổn định, không lộ stack hay đường dẫn; giới hạn tốc độ cho truy vấn nặng.
7. **Truy vết và audit:** mọi trả lời về alert kèm `contributing_event_ids` và cách mở raw (có audit và quyền).
8. **Kiểm thử API:** unit (validation, quyền), contract (schema response), tích hợp với DuckDB mẫu từ fixture; thử input hỏng và quá lớn.

## Nguyên tắc không được vi phạm
- Không tự thêm framework, dependency, service hay cổng mạng; không bind ra ngoài localhost.
- Không đổi schema Silver/Gold hay canonical contract; API phản ánh dữ liệu như có, không chế thêm trường.
- Không trả dữ liệu mẫu như dữ liệu thật; ghi nhãn nguồn khi cần.
- Không triển khai endpoint response thật khi chưa có `dacn-response-safety` được duyệt.

## Kiểm tra kết quả
Mỗi endpoint có ví dụ request/response khớp schema, test lỗi/quyền, và ghi rõ trường nào lấy từ cột Silver/Gold nào.

## Đầu ra
API spec (bảng hoặc OpenAPI), mô hình quyền, danh sách quyết định công nghệ cần duyệt, kế hoạch test.

## Cần hỏi người dùng
Chọn framework/transport, thêm dependency, cơ chế xác thực, mở bất kỳ cổng nào, hoặc đưa API vào repository.

## Phối hợp với skill khác
- Trước đó: dacn-alert-incident-management, dacn-data-pipeline-storage
- Cùng lúc: dacn-security-review
- Sau đó: dacn-dashboard
