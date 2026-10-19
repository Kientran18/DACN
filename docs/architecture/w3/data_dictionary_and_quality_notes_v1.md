# Từ điển dữ liệu và ghi chú chất lượng v1

> Cập nhật 2026-10-19: [schema](endpoint_event_schema_v1.md) và [mapping](sysmon_raw_to_silver_mapping_v1.md) hiệu chỉnh là contract hiện hành chờ review. Mô tả Pydantic/DuckDB/dead-letter bên dưới là thiết kế dự kiến; chưa có mã pipeline tương ứng trong main để xác minh đã triển khai.


---

## 1. Từ Điển Dữ Liệu (Data Dictionary v1)

| Tên Thuộc Tính | Kiểu Lưu Trữ | Giá Trị Mẫu | Ý Nghĩa An Ninh Điểm Cuối (Cyber & Detection) |
| :--- | :--- | :--- | :--- |
| `event_id` | `VARCHAR(36)` | `5b452d31-566e-59b4-9929-cbb8377ca690` | Khóa chính xác định tính duy nhất của bản ghi; deduplicate khi nạp lại dữ liệu. |
| `process_guid` | `VARCHAR(36)` | `43f71ec6-8d5b-6ad4-2601-000000000400` | Khóa liên kết cốt lõi xuyên suốt 4 bảng sự kiện; triệt tiêu rủi ro trùng PID. |
| `parent_guid` | `VARCHAR(36)` | `43f71ec6-8d5b-6ad4-2501-000000000400` | Khóa liên kết đệ quy để dựng đồ thị cây tiến trình (Process DAG Tree). |
| `image_path` | `VARCHAR` | `C:\Windows\System32\conhost.exe` | Nhận diện binary thực thi, phát hiện chạy LOLBins từ Temp/Downloads. |
| `command_line` | `VARCHAR` | `powershell.exe -NoP -w hidden -enc...` | Đầu vào tính Shannon Entropy và Autoencoder phát hiện Obfuscation. |
| `file_sha256` | `VARCHAR(64)` | `C43CF46192DA061DD6169E55...` | Khớp kiểm tra chữ ký mã độc tĩnh (Static Threat Intelligence). |
| `file_path` | `VARCHAR` | `...\Temp\edr_poc\malware_drop.exe` | Phát hiện kỹ thuật Drop-Execute-Delete và đo đếm tần suất ghi tệp (Ransomware). |
| `target_object`| `VARCHAR` | `HKU\...\SOFTWARE\Microsoft\Windows\CurrentVersion\Run` | Phát hiện hành vi duy trì quyền truy cập bí mật (Persistence). |
| `direction` | `VARCHAR` | `OUTBOUND` | Phát hiện C2 Reverse Shell, tải stage 2 payload hoặc rò rỉ dữ liệu (Exfiltration). |
| `dest_ip` | `VARCHAR` | `172.66.147.243` | Cửa sổ trượt đếm số IP duy nhất, nhận diện port scanning hoặc C2 beaconing. |

---

## 2. Kiểm Soát & Xử Lý Rủi Ro Chất Lượng Dữ Liệu (Data Quality Notes v1)

```text
+--------------------------------------------------------------------------------------------------+
|                                  DATA QUALITY DEFENSE IN DEPTH                                   |
|                                                                                                  |
|   +-----------------------+      +--------------------------+      +-------------------------+   |
|   | Sysmon Raw Logs       | ---> | Validation & Quarantine  | ---> | Clean Silver Tables     |   |
|   | (XML / Bronze JSONL)  |      | (Pydantic Schema Check)  |      | (DuckDB Optimized OLAP) |   |
|   +-----------------------+      +--------------------------+      +-------------------------+   |
|                                                |                                                 |
|                                                v (Failed Schema / Corrupted JSON)                |
|                                  +--------------------------+                                    |
|                                  | validation_errors.jsonl  |                                    |
|                                  | (Non-blocking Isolation) |                                    |
|                                  +--------------------------+                                    |
+--------------------------------------------------------------------------------------------------+

```

### 2.1 Rủi Ro PID Reuse Trên Hệ Điều Hành Windows
* **Bản chất rủi ro:** Windows tái sử dụng Process ID (PID) trong thời gian rất ngắn. Nếu nối bảng bằng `pid`, hoạt động ghi file hoặc gọi mạng của một tiến trình hệ thống sinh sau có thể bị quy nhầm cho tiến trình độc hại đã chết trước đó.
* **Biện pháp xử lý:** Tuyệt đối cấm sử dụng `pid` làm khóa liên kết trong các câu truy vấn phân tích SQL và trích xuất đặc trưng AI. Mọi liên kết bắt buộc sử dụng `process_guid`.

### 2.2 Rủi Ro Lệch Múi Giờ & Time Drift
* **Bản chất rủi ro:** Giờ hệ thống máy trạm có thể bị sai lệch hoặc định dạng theo múi giờ địa phương, gây sai sót thứ tự trước/sau khi thực hiện Sliding Window đếm tần suất thao tác file (DET-008).
* **Biện pháp xử lý:** Chuẩn hóa múi giờ về UTC xử lý khác biệt timezone, không sửa sai đồng hồ nguồn. Cần lưu thời gian ingestion và thiết kế theo dõi clock drift riêng; collector hiện giữ chuỗi SystemTime UTC của nguồn.

### 2.3 Rủi Ro Khuyết Thiếu Trường Dữ Liệu Cố Hữu Của Sysmon (Data Gaps)
* **Bản chất rủi ro:** Sysmon Event ID 11 không trả về dung lượng file (`file_size_bytes`); Sysmon Event ID 13 trả về chuỗi text thay vì native registry type (`REG_SZ`, `REG_DWORD`).
* **Biện pháp xử lý:** 
  * Trường file_size_bytes nếu được bổ sung phải là Optional/null khi nguồn không có. Không gán 0 để tránh nhầm với file rỗng. Collector hiện không xuất trường này.
  * Trường Registry sử dụng hàm phân tích heuristic `value_type_inferred` để bóc tách kiểu giá trị an toàn.

### 2.4 Cơ Chế Phân Lập Bản Ghi Lỗi (Dead Letter Isolation)
* Khi gặp log bị hỏng cú pháp JSON hoặc vi phạm ràng buộc schema Pydantic, pipeline cô lập bản ghi sang file `data/bronze/validation_errors.jsonl` kèm mã lỗi và dòng lỗi cụ thể. Cơ chế này đảm bảo pipeline xử lý liên tục mà không bị dừng đột ngột (Non-blocking pipeline).