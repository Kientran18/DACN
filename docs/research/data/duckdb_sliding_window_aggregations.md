# Sliding Window Aggregations for High-Frequency Behavior

## 0. Mục đích
Nghiên cứu cách bắt Ransomware (T1486) hoặc dò quét mạng (T1071.001) dựa trên tần suất (Rate/Frequency) trong một cửa sổ thời gian (Sliding Window).

## 1. Vấn đề (Problem Statement)
Detection Rule DET-008 (Ransomware-like behavior) yêu cầu đếm số lượng file bị modify/rename bởi *cùng một process* trong *thời gian T giây*.
Nếu dùng vòng lặp Python thuần để duyệt mảng JSON sẽ cực kỳ tốn CPU, vi phạm ngân sách `< 3% CPU` của kiến trúc.

## 2. Công nghệ thử nghiệm (Technology Tested)
DuckDB Window Functions (Hàm cửa sổ).

## 3. POC Query (SQL)
Trích xuất đặc trưng `file_write_rate_per_sec` (thuộc Deliverable: AI/Feature candidate fields):

```sql
SELECT 
    process_guid,
    timestamp,
    operation,
    file_path,
    -- Đếm số lượng hành động ghi/sửa file của process này trong 60 giây qua
    COUNT(*) OVER (
        PARTITION BY process_guid 
        ORDER BY timestamp 
        RANGE BETWEEN INTERVAL 60 SECONDS PRECEDING AND CURRENT ROW
    ) as file_writes_in_last_60s
FROM silver_file_events
WHERE operation IN ('CREATE', 'MODIFY', 'RENAME', 'DELETE');
```

# 4. Đánh giá khả năng áp dụng (Conclusion)
* **Ưu điểm:** Đẩy toàn bộ tải tính toán trượt cửa sổ thời gian (Sliding Window) xuống cho DuckDB Engine (viết bằng C++), giúp Pipeline Python cực kỳ nhẹ.

* **Áp dụng Rule:** Nếu `file_writes_in_last_60s` > N (ví dụ N = 50), trigger alert DET-008.

* **Áp dụng Feature Engineering:** Ghi giá trị này ra file `feature_store.parquet` ở tầng Gold để train model Isolation Forest hoặc Autoencoder.