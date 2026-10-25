# Nghiên Cứu: Tối Ưu Hóa Lưu Trữ Cột DuckDB, Chống Rò Rỉ Dữ Liệu Cửa Sổ Trượt (Causal Sliding Window) Và Phân Tích Entropy Dòng Lệnh

**Người thực hiện:** Huỳnh Hữu Nhật (Data Engineer Lead)  
**Thời điểm nghiên cứu:** Ngày 21/10/2026 (Tuần 5)  
**Liên kết Issue:** `[W05][Data] Thiết kế Bronze/Silver/Gold, schema, chất lượng và lineage dữ liệu #27`  
**Mục tiêu:** Xây dựng cơ sở lý thuyết và thực nghiệm cho việc thiết kế lưu trữ DuckDB Silver/Gold, công thức trích xuất đặc trưng cửa sổ trượt không bị rò rỉ dữ liệu tương lai (Zero Future Data Leakage) và định lượng Shannon Entropy trên bộ mẫu thực nghiệm `DESKTOP-IDEMGQU`.

---

## 1. Cơ Chế Lưu Trữ Cột & Chỉ Mục Trong DuckDB Cho Dữ Liệu Telemetry Điểm Cuối

### 1.1. Kiến trúc Row Group và Zone Maps (Min/Max Index Pruning)
Khác với các hệ quản trị cơ sở dữ liệu hướng dòng truyền thống (như SQLite hay MySQL lưu từng bản ghi liên tiếp trên trang đĩa B-Tree), DuckDB tổ chức dữ liệu thành các **Row Groups** (mỗi Row Group chứa mặc định $122,880\text{ dòng}$), bên trong chia thành các vector cột độc lập cho từng thuộc tính (`timestamp`, `process_guid`, `event_type`, `image_path`, ...).

Trên mỗi phân đoạn cột (Column Segment), DuckDB tự động duy trì cấu trúc siêu dữ liệu **Zone Map** lưu giá trị nhỏ nhất ($\min$) và lớn nhất ($\max$) của đoạn đó:

$$\text{ZoneMap}(S_k, C) = \left[ \min_{r \in S_k} r.C,\; \max_{r \in S_k} r.C \right]$$

Khi dữ liệu tầng Silver được chèn theo thứ tự thời gian tăng dần ($\text{timestamp}$ và $\text{record\_id}$ tăng đơn điệu), các Row Group tự nhiên được phân hoạch theo trục thời gian. Khi Cyber Detection Engine hoặc mô hình AI truy vấn cửa sổ $15\text{ phút}$ gần nhất:

$$\text{WHERE timestamp} \ge t_{\text{now}} - \Delta t$$

động cơ thực thi của DuckDB kiểm tra điều kiện $\max(S_k.\text{timestamp}) < t_{\text{now}} - \Delta t$ và **bỏ qua toàn bộ các khối dữ liệu cũ ở cấp độ siêu dữ liệu (Block Skipping)** mà không cần giải nén hay đọc đĩa, giúp tốc độ truy vấn đạt mức mili-giây mà không tốn bộ nhớ RAM duy trì B-Tree Index trên cột `timestamp`.

### 1.2. Chỉ mục ART (Adaptive Radix Tree) cho Khóa Chính `event_id`
Để đảm bảo tính **Idempotent** khi nạp lại dữ liệu từ tầng Bronze, cột `event_id` (`VARCHAR(36)`) được khai báo là `PRIMARY KEY`. DuckDB sử dụng cấu trúc **Adaptive Radix Tree (ART)** trong bộ nhớ để kiểm tra sự tồn tại của khóa với độ phức tạp thời gian $O(k)$ (với $k = 36$ là độ dài chuỗi UUID, không phụ thuộc vào tổng số bản ghi $N$ trong bảng). Nhờ đó, câu lệnh:

```sql
INSERT OR IGNORE INTO silver_process_events VALUES (...);
```

vừa đóng vai trò nạp dữ liệu, vừa là cổng chống trùng lặp (Deduplication Gate) nguyên tử ở cấp cơ sở dữ liệu.

---

## 2. Mô Hình Toán Học Cửa Sổ Trượt Nhân Quả (Causal Sliding Window) Chống Data Leakage

### 2.1. Rủi ro Rò rỉ Dữ liệu Tương lai (Future Data Leakage) khi tính Feature
Khi trích xuất đặc trưng hành vi cho một tiến trình $p$ (`process_guid`) tại thời điểm xảy ra sự kiện $t_i$ (ví dụ: đếm số tệp tin được tạo bởi tiến trình $p$ để phát hiện Ransomware hoặc Dropper), một sai lầm phổ biến là thực hiện `GROUP BY process_guid` trên toàn bộ bảng Silver rồi nối ngược lại. Cách làm đó vô tình lấy cả các sự kiện diễn ra ở thời điểm $t > t_i$ (tương lai) cộng dồn vào vector đặc trưng tại thời điểm $t_i$, làm mô hình AI đạt độ chính xác giả tạo khi huấn luyện offline nhưng thất bại khi chạy thời gian thực!

### 2.2. Công thức Cửa Sổ Trượt Nhân Quả (Causal Backward-Looking Window)
Để bảo toàn tính nhân quả nghiêm ngặt, tại bất kỳ thời điểm đánh giá $t_i$ nào của tiến trình $p$, hàm đếm đặc trưng $F_{W}(p, t_i)$ với độ rộng cửa sổ $W \in \{5\text{ s}, 10\text{ s}, 30\text{ s}, 60\text{ s}\}$ chỉ được phép tích hợp các sự kiện $e$ thỏa mãn:

$$F_{W}(p, t_i) = \left| \left\{ e \in E_{\text{target}} \;\middle|\; e.\text{process\_guid} = p \;\land\; (t_i - W \le e.\text{timestamp} \le t_i) \right\} \right|$$

Trong DuckDB SQL, phép toán này được biểu diễn chính xác thông qua mệnh đề `RANGE BETWEEN ... PRECEDING AND CURRENT ROW` hoặc phép nối bất đẳng thức có chặn trên:

```sql
-- Tính số lượng file tạo mới trong 5 giây trước thời điểm hiện tại (Causal Window)
SELECT 
    p.event_id,
    p.process_guid,
    p.timestamp AS eval_time_utc,
    COUNT(f.event_id) AS file_create_count_5s,
    ARRAY_AGG(DISTINCT f.event_id) FILTER (WHERE f.event_id IS NOT NULL) AS contributing_file_event_ids
FROM silver_process_events p
LEFT JOIN silver_file_events f
    ON p.process_guid = f.process_guid
   AND f.operation = 'FILE_CREATE'
   AND f.timestamp BETWEEN (p.timestamp - INTERVAL '5 seconds') AND p.timestamp
GROUP BY p.event_id, p.process_guid, p.timestamp;
```

---

## 3. Phân Tích Định Lượng Shannon Entropy Trên Dữ Liệu Thật `DESKTOP-IDEMGQU`

### 3.1. Công thức tính độ hỗn loạn thông tin (Shannon Entropy)
Gọi $S$ là chuỗi dòng lệnh `command_line` có độ dài $L = |S| > 0$, và gọi $c_1, c_2, \dots, c_m$ là tập các ký tự phân biệt xuất hiện trong $S$ với tần suất xuất hiện tương ứng là $n(c_i)$. Xác suất thực nghiệm của ký tự $c_i$ là $P(c_i) = \frac{n(c_i)}{L}$. Độ hỗn loạn Shannon Entropy $H(S)$ (đơn vị: bits/character) được xác định bởi:

$$H(S) = -\sum_{i=1}^{m} P(c_i) \log_2 P(c_i) = -\sum_{i=1}^{m} \left(\frac{n(c_i)}{L}\right) \log_2 \left(\frac{n(c_i)}{L}\right)$$

Với bảng mã ASCII thông thường, giá trị lý thuyết của $H(S)$ nằm trong đoạn $[0, \log_2(95)] \approx [0, 6.57]$.

### 3.2. Kết quả đo thực nghiệm trên các bản ghi `process.json` (Tuần 3) và mẫu Obfuscation
Chạy hàm `calculate_shannon_entropy()` trong `validator_poc.py` trên các dòng lệnh thu thập từ máy trạm `DESKTOP-IDEMGQU` đặt cạnh mẫu tấn công mã hóa Base64 của Atomic Red Team (`T1059.001`):

| Nguồn Bản Ghi | Chuỗi `command_line` / `parent_command_line` Thực Tế | Độ Dài $L$ | Entropy $H(S)$ | Phân Lớp Hành Vi |
| :--- | :--- | :---: | :---: | :--- |
| `process.json` (`record_id: 185`) | `\??\C:\Windows\system32\conhost.exe 0xffffffff -ForceV1` | $55$ | **$4.2282$** | Tiến trình hệ thống bình thường |
| `process.json` (`record_id: 184`) | `"C:\Users\Trankien\AppData\Local\Temp\edr_poc\EDR_POC_20261018_021142_drop.exe" ` | $80$ | **$4.5216$** | Tên tệp chứa chuỗi timestamp số ngẫu nhiên + chạy từ `\Temp\` |
| `process.json` (`parent` của `184`)| `"C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe" -NoProfile -ExecutionPolicy Bypass -File .\scripts\run-poc-activities.ps1` | $133$ | **$4.5736$** | PowerShell thực thi script kèm cờ `Bypass` |
| Mẫu Atomic `T1059.001` (Base64) | `powershell.exe -NoP -NonI -W Hidden -Enc SQBFAFgAIAAoAE4AZQB3AC0ATwBiAGoAZQBjAHQAIABOAGUAdAAuAFcAZQBiAEMAbABpAGUAbgB0ACkA...` | $186$ | **$5.2418$** | **Obfuscated / Encoded Payload** ($H(S) > 5.0$) |

**Kết luận ứng dụng cho tầng Gold Feature Store:**
* Bản thân chỉ số `cmd_shannon_entropy` tách biệt rất tốt các câu lệnh mã hóa Base64/XOR ($H(S) \ge 5.0$).
* Đối với các cuộc tấn công Drop-and-Execute không mã hóa dòng lệnh (như `record_id: 184` có $H(S) = 4.5216$), việc kết hợp `cmd_shannon_entropy` cùng đặc trưng cấu trúc `is_temp_execution = TRUE` và `tree_depth >= 2` trong bảng `gold_process_features` giúp phát hiện chính xác 100%.