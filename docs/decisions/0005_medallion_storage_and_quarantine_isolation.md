# ADR 0005: Kiến Trúc Lưu Trữ Medallion Cục Bộ (JSONL + DuckDB/Parquet) Và Cơ Chế Cô Lập Lỗi Quarantine DLQ

* **Trạng thái:** Đã chấp thuận (Accepted)
* **Ngày quyết định:** 21/10/2026 (Tuần 5)
* **Người đề xuất:** Huỳnh Hữu Nhật (Data Engineer Lead)
* **Tham vấn & Đồng thuận:** Cyber Security Team (Detection Lead), Software Team (Collector Lead)
* **Liên kết Issue:** `[W05][Data] Thiết kế Bronze/Silver/Gold, schema, chất lượng và lineage dữ liệu #27`, `[W05][Team] #26`

---

## 1. Bối Cảnh & Vấn Đề Kỹ Thuật (Context and Problem Statement)

Hệ thống Giám sát và Phát hiện Xâm nhập Điểm cuối Cục bộ (Local EDR) hoạt động trực tiếp trên máy trạm Windows với ngân sách tài nguyên nghiêm ngặt (CPU trung bình $< 3\%$, RAM $< 150\text{ MB}$). Ở Tuần 5, nhóm cần chốt kiến trúc lưu trữ vật lý và cơ chế xử lý lỗi xuyên suốt từ lúc nhận dữ liệu của Software Collector cho đến khi cung cấp bảng dữ liệu sạch cho Cyber Detection Engine và mô hình AI.

Các bài toán kỹ thuật đặt ra gồm:
1. **Đảm bảo khả năng chạy lại (Replayability) và kiểm toán (`ADR 0003`):** Làm thế nào lưu trữ dữ liệu thô nguyên bản từ Sysmon mà không tốn chi phí quản trị cơ sở dữ liệu nặng nề?
2. **Truy vấn phân tích hiệu năng cao cho Detection & Feature Engineering:** Các thuật toán dựng cây phả hệ tiến trình đệ quy (`WITH RECURSIVE` trên `process_guid`) và tính toán đặc trưng cửa sổ trượt (Sliding Window $5\text{ s}$, $10\text{ s}$, $60\text{ s}$) đòi hỏi tốc độ quét cột (Columnar OLAP) rất nhanh.
3. **Chịu lỗi không chặn luồng (Non-blocking Fault Tolerance):** Khi xuất hiện bản ghi bị hỏng cú pháp JSON, thiếu trường bắt buộc (`process_guid`, `record_id`), hoặc sai định dạng thời gian, pipeline phải xử lý thế nào để vừa không làm dừng toàn bộ hệ thống, vừa không tự chế dữ liệu giả (Zero Data Fabrication) làm nhiễm bẩn tầng phân tích?
4. **Tránh xung đột đọc/ghi tệp (File Contention):** Khi tiến trình Collector (Software) vừa ghi log, tiến trình Ingestor (Data) vừa đọc log trên cùng một tệp cục bộ, làm sao tránh đọc phải dòng JSON chưa ghi xong?

---

## 2. Các Phương Án Đã Cân Nhắc (Considered Options)

### Phương án 1: Sử dụng SQLite cho toàn bộ các tầng (Bronze, Silver, Gold)
* **Ưu điểm:** Có sẵn trong thư viện chuẩn Python (`sqlite3`), gọn nhẹ, giao dịch ACID đầy đủ.
* **Nhược điểm:** SQLite lưu trữ theo hướng dòng (Row-oriented B-Tree). Khi thực hiện các câu truy vấn tổng hợp cửa sổ trượt (Window Functions) và quét hàng trăm nghìn bản ghi lịch sử để trích xuất đặc trưng AI, hiệu năng quét cột và nén dữ liệu kém xa định dạng OLAP chuyên dụng.

### Phương án 2: Triển khai Hệ quản trị Cơ sở dữ liệu Client-Server (PostgreSQL / OpenSearch)
* **Ưu điểm:** Hỗ trợ đồng thời cao, nhiều công cụ trực quan hóa có sẵn.
* **Nhược điểm:** Quá nặng cho một giải pháp Local EDR chạy ngầm trên máy trạm người dùng (OpenSearch ngốn từ $1\text{ GB} - 2\text{ GB}$ RAM), cài đặt phức tạp và trái với định hướng kiến trúc tinh gọn đã chốt ở `ADR 0004`.

### Phương án 3: Kiến trúc Medallion Cục bộ Kết hợp (Bronze JSONL + Quarantine DLQ + Silver/Gold DuckDB & Parquet)
* **Cấu trúc:**
  * **Tầng Bronze:** Ghi tệp văn bản nối đuôi bất biến (**Append-only JSON Lines**) theo lô nhỏ kèm tệp kiểm kê `manifest.json` (chứa mã băm `SHA-256`).
  * **Tầng Quarantine (Dead-Letter Queue):** Tách riêng các bản ghi không vượt qua cổng kiểm định Schema vào `data/quarantine/*.jsonl` và bảng `silver_quarantine_dlq` kèm mã lỗi chuẩn hóa (`error_code`, `raw_reference`).
  * **Tầng Silver & Gold:** Sử dụng động cơ OLAP nhúng **DuckDB** (`endpoint_silver.duckdb`) chạy in-process trong Python, kết hợp xuất kho lưu trữ lạnh ra tệp cột nén **Apache Parquet (`ZSTD`)**.

---

## 3. Quyết Định Kiến Trúc (Decision Outcome)

Nhóm quyết định lựa chọn **Phương án 3: Kiến trúc Medallion Cục bộ (Bronze JSONL $\rightarrow$ Non-blocking Quarantine DLQ $\rightarrow$ Silver/Gold DuckDB & Parquet)** kèm giao thức chuyển giao tệp nguyên tử (**Atomic File Handoff**).

```text
+---------------------------------------------------------------------------------------------------+
|                 GIAO THỨC CHUYỂN GIAO NGUYÊN TỬ & CÔ LẬP LỖI (ADR 0005)                           |
|                                                                                                   |
|  [Software Collector] ---> Ghi vào `batch_001.jsonl.tmp`                                          |
|                            Đủ 5s hoặc 500 events ---> Đổi tên nguyên tử thành `batch_001.jsonl`   |
|                                                       + Sinh `batch_001.manifest.json`            |
|                                                                     |                             |
|                                                                     v                             |
|                                                       [Data Validation & Dedup Engine]            |
|                                                                     |                             |
|                                          +--------------------------+--------------------------+  |
|                                          | (Hợp lệ 100%)                                       |  |
|                                          v                                                     v  |
|                            [DuckDB Silver Tables]                                [Quarantine DLQ] |
|                            INSERT OR IGNORE (UUIDv5)                             Ghi mã lỗi + Raw |
+---------------------------------------------------------------------------------------------------+
```

### Các quy định kỹ thuật bắt buộc kèm theo quyết định:
1. **Giao thức bàn giao tệp giữa Software và Data (Atomic File Handoff):**
   * Tiến trình Collector của nhóm Software khi đang thu thập sẽ ghi vào tệp tạm có đuôi `.jsonl.tmp`.
   * Khi đóng lô (mỗi $5\text{ giây}$ hoặc đủ $500\text{ sự kiện}$), Collector thực hiện lệnh `os.replace()` (đổi tên nguyên tử ở cấp hệ thống tệp NTFS) sang đuôi `.jsonl` và ghi tệp `.manifest.json`.
   * Tiến trình Ingestor của nhóm Data chỉ quét các tệp `.jsonl` đã có `.manifest.json` tương ứng, loại bỏ hoàn toàn lỗi đọc phải dòng JSON đang ghi dở.
2. **Chính sách Không tự chế dữ liệu (Zero Data Fabrication):**
   * Bộ kiểm định tuyệt đối không tự điền giá trị giả cho các trường khóa bắt buộc (`process_guid`, `record_id`, `timestamp`, `hostname`). Bản ghi vi phạm phải được đẩy sang Quarantine DLQ ngay lập tức để bảo vệ độ chính xác của đồ thị tiến trình và mô hình AI.

---

## 4. Hệ Quả (Consequences)

* **Tích cực:**
  * Bảo toàn 100% dữ liệu gốc tại tầng Bronze dưới dạng văn bản chuẩn, dễ dàng đọc bằng mọi công cụ hoặc nén lưu trữ dài hạn.
  * DuckDB mang lại tốc độ truy vấn phân tích cột (Vectorized Execution) nhanh gấp hàng chục lần SQLite trên các câu lệnh `WITH RECURSIVE` và `COUNT() OVER (PARTITION BY process_guid ORDER BY timestamp RANGE BETWEEN...)` mà không cần chạy tiến trình database server riêng.
  * Pipeline vận hành liên tục (Non-blocking), mọi sự kiện lỗi đều có bằng chứng kiểm toán rõ ràng trong Quarantine để phục vụ vá lỗi parser và chạy Replay.
* **Tiêu cực & Biện pháp giảm thiểu:**
  * DuckDB chỉ cho phép **1 tiến trình ghi (Single-Writer)** hoặc nhiều tiến trình chỉ đọc tại một thời điểm. *Biện pháp:* Cố định duy nhất tiến trình Data Pipeline Worker nắm quyền ghi vào `endpoint_silver.duckdb`; khi Cyber Engine hoặc CLI cần truy vấn độc lập, mở kết nối với cờ `read_only=True` hoặc đọc qua các bản chụp Parquet.