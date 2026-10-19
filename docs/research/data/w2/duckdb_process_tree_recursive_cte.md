# Process Tree Reconstruction using DuckDB

## 0. Mục đích
Nghiên cứu cách dựng Process Tree (Cây tiến trình) để phục vụ cho các rule phát hiện chuỗi thực thi bất thường (ví dụ: Word $\rightarrow$ CMD $\rightarrow$ PowerShell).

## 1. Vấn đề (Problem Statement)
Các hành vi tấn công như T1059 (Command and Scripting Interpreter) hoặc T1082 (System Info Discovery) yêu cầu hệ thống phải nhìn thấy ngữ cảnh cha-con (Parent-Child). 
Ví dụ: `powershell.exe` đứng một mình có thể không sao, nhưng nếu nó được spawn từ `winword.exe` thì là cảnh báo đỏ (DET-001).
Câu hỏi: Làm sao truy vấn đệ quy cây tiến trình từ bảng `silver_process_events` một cách nhanh nhất trên Local EDR?

## 2. Công nghệ thử nghiệm (Technology Tested)
DuckDB Recursive CTE (Common Table Expressions).

## 3. POC Query (SQL)
Giả sử ta phát hiện một tiến trình đáng ngờ (ví dụ: `powershell.exe` tải file), ta cần truy xuất ngược lên root để xem process nào đã gọi nó. DuckDB hỗ trợ cú pháp `WITH RECURSIVE`:

```sql
WITH RECURSIVE process_tree AS (
    -- Anchor member: Lấy tiến trình đáng ngờ tại thời điểm hiện tại
    SELECT 
        process_guid, parent_guid, image_path, command_line, timestamp, 1 as depth
    FROM silver_process_events
    WHERE image_path ILIKE '%powershell.exe%'
      AND command_line ILIKE '%-enc%'

    UNION ALL

    -- Recursive member: Join ngược lên tiến trình cha
    SELECT 
        p.process_guid, p.parent_guid, p.image_path, p.command_line, p.timestamp, pt.depth + 1
    FROM silver_process_events p
    JOIN process_tree pt ON p.process_guid = pt.parent_guid
)
SELECT * FROM process_tree ORDER BY depth DESC;
```

# 4. Đánh giá khả năng áp dụng (Conclusion)

* **Ưu điểm:** Tốc độ thực thi của DuckDB CTE trên vài trăm nghìn bản ghi (Local Phase 1) là dưới 50ms. Rất hoàn hảo cho Rule-based Detection Engine.
* **Next step:** Tích hợp câu query này vào module `pipeline/features/extractor.py` để trích xuất ra đặc trưng `process_tree_depth` cho tầng Gold.

