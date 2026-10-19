# ADR 0003: Chiến Lược Bảo Tồn Dữ Liệu Thô (Raw Data Preservation Strategy)

* **Trạng thái:** ACCEPTED
* **Người đề xuất:** Huỳnh Hữu Nhật (Data Engineer)
* **Ngày quyết định:** 18/10/2026
* **Các bên tham gia đồng thuận:** Cyber Team, Software Team, Data Team

---

## 1. Ngữ Cảnh Kỹ Thuật (Context)
Trong kiến trúc dữ liệu EDR theo mô hình Medallion (Bronze → Silver → Gold), tầng Silver có nhiệm vụ làm sạch, chuẩn hóa kiểu dữ liệu (strongly typed) và trải phẳng (flatten) các trường quan trọng thành cột bảng trong DuckDB. 

Tuy nhiên, trong thực tế vận hành an ninh và phân tích mã độc:
* Các sự kiện từ Windows Event Log / Sysmon thường chứa nhiều trường thông tin đặc thù, ít gặp trong vận hành thường ngày (như `LogonGuid`, `LogonId`, `OriginalFileName`, `FileVersion`, `Description`, `Product`, `RuleName`). Nếu lược bỏ hoàn toàn các trường này khi chuyển từ Bronze sang Silver, hệ thống sẽ gặp tổn thất ngữ cảnh lớn khi đội ngũ Cyber cần điều tra số (Forensics Incident Response).
* Luật phát hiện (Detection rules) và các mô hình AI trong tương lai có thể cần các đặc trưng mới từ log gốc mà hiện tại ở Tuần 3 chưa khai báo thành cột trong bảng Silver. Nếu không lưu giữ dữ liệu thô, ta buộc phải chạy lại toàn bộ pipeline từ file Bronze thô (tốn kém tài nguyên I/O và tính toán).

## 2. Các Phương Án Cân Nhắc (Options Considered)

1. **Phương án A: Khai báo tất cả các trường có thể có của Sysmon thành từng cột riêng biệt trong bảng Silver**
   * *Ưu điểm:* Truy vấn SQL trực tiếp bằng tên cột mà không cần parse chuỗi.
   * *Nhược điểm:* Bảng Silver trở nên quá nhiều cột (sparse table với hàng chục cột hầu hết chứa giá trị NULL), gây phân mảnh dung lượng lưu trữ trên DuckDB và làm chậm tốc độ quét khối (vectorized scan).

2. **Phương án B: Chỉ lưu các trường cần thiết, xóa hoàn toàn dữ liệu thô sau khi chuyển sang Silver**
   * *Ưu điểm:* Bảng Silver rất nhẹ và tối ưu bộ nhớ.
   * *Nhược điểm:* Mất toàn bộ thông tin phụ trợ cho điều tra pháp y; không thể kiểm chứng tính nguyên bản (provenance/lineage audit) nếu nghi ngờ logic parse bị lỗi.

3. **Phương án C: Trải phẳng các trường cốt lõi kết hợp duy trì cột `raw_data` JSON (Lựa chọn áp dụng)**
   * Chuẩn hóa các trường cốt lõi thành các cột strongly-typed (`event_id`, `timestamp`, `process_guid`, `image_path`, `command_line`,...).
   * Đồng thời lưu toàn bộ dictionary `EventData` gốc vào cột `raw_data` dưới dạng JSON.

## 3. Quyết Định Kiến Trúc (Decision)
Hệ thống chính thức thông qua **Phương án C**:
* **Tầng Bronze:** Lưu giữ nguyên vẹn toàn bộ các bản ghi thu thập dạng JSONL / XML theo cơ chế Append-Only không thay đổi.
* **Tầng Silver:** Trong DDL của tất cả các bảng (`silver_process_events`, `silver_file_events`, `silver_registry_events`, `silver_network_events`), bổ sung bắt buộc cột `raw_data JSON NOT NULL`.
* **Logic trích xuất:** Khi pipeline xử lý, toàn bộ đối tượng `EventData` thô sẽ được serialize thành JSON string và nạp đồng thời vào cột `raw_data` song song với các cột đã parse.

## 4. Hệ Quả & Đánh Giá Tác Động (Consequences)

* **Tích cực:**
  * **Hỗ trợ truy vết & Kiểm toán (Forensic Auditing):** Khi phát hiện một alert nghi vấn, chuyên viên Cyber có thể dùng các hàm JSON có sẵn của DuckDB (ví dụ: `json_extract_string(raw_data, '$.OriginalFileName')`) để xem ngay ngữ cảnh gốc của binary mà không cần tìm ngược lại file Bronze.
  * **Tính thích ứng mở rộng (Extensibility):** Khi cần bổ sung thêm trường nghiệp vụ mới ở các tuần tiếp theo, Data team có thể trực tiếp dùng câu lệnh SQL trích xuất từ cột `raw_data` trên Silver mà không cần nạp lại từ Bronze.
* **Tiêu cực / Ràng buộc:**
  * Tăng nhẹ dung lượng file cơ sở dữ liệu `endpoint_silver.duckdb` (khoảng 20–35% tùy vào kích thước EventData). Tuy nhiên, nhờ cơ chế nén columnar tự nhiên của DuckDB, mức tăng này hoàn toàn nằm trong giới hạn tài nguyên của máy trạm (< 150MB RAM).