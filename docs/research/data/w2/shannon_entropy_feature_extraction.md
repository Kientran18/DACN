# Command Line Shannon Entropy Calculation

## 0. Mục đích
Nghiên cứu tính toán độ hỗn loạn (Entropy) của CommandLine - một trong những Feature quan trọng nhất cho AI để bắt mã độc bị obfuscate (giấu mã).

## 1. Vấn đề (Problem Statement)
Kẻ tấn công thường né tránh các luật "Exact Match" (chữ ký hash, đường dẫn) bằng cách thêm ký tự rác vào lệnh.
Ví dụ: `cmd.exe /c "s^e^t a=p^ow^er^sh^el^l"`
Sysmon log ra chuỗi này, nhưng Rule-based khó dùng Regex để bắt hết mọi biến thể. Giải pháp là dùng AI/Feature Engineering: Tính Shannon Entropy của chuỗi.

## 2. Phương pháp thử nghiệm (Methodology)
Tạo hàm toán học tính Entropy trực tiếp trong Python Pipeline trước khi đưa vào Silver/Gold layer. Entropy càng gần 8.0 thì chuỗi càng ngẫu nhiên (dấu hiệu của mã hóa Base64 hoặc obfuscation mạnh).

## 3. POC Code (Python)
Đoạn code sau mô phỏng hàm tính sẽ được nhúng vào `pipeline/features/extractor.py`:

```python
import math
from collections import Counter

def calculate_shannon_entropy(data_string: str) -> float:
    if not data_string:
        return 0.0
    
    # Tính tần suất xuất hiện của từng ký tự
    probabilities = [n_x / len(data_string) for x, n_x in Counter(data_string).items()]
    
    # Công thức Shannon Entropy: H = - sum(p_i * log2(p_i))
    entropy = -sum(p * math.log2(p) for p in probabilities)
    return round(entropy, 4)

# Test cases
benign_cmd = "ping google.com -n 4"
obfuscated_cmd = "powershell.exe -e JABzAD0ATgBlAHcALQBPAGIAagBlAGMAdAAgAEkATwAuAE0AZQBtAG8AcgB5AFMAdAByAGUAYQBtACgAWwBDAG8AbgB2AGUAcgB0AF0AOgA6AEYAcgBvAG0AQgBhAHMAZQA2ADQAUwB0AHIAaQBuAGcAKAAiAEg..."

print(f"Benign: {calculate_shannon_entropy(benign_cmd)}")       # Thường < 3.5
print(f"Obfuscated: {calculate_shannon_entropy(obfuscated_cmd)}") # Thường > 4.5
```

# 4. Đánh giá & Rủi ro (Risk & Mitigation)

* **Tích hợp:** Sẽ được khai báo như một computed_field trong Pydantic schema hoặc tính ở batch extract ra tầng Gold.
* **Rủi ro:** Một số software hợp lệ cũng truyền chuỗi base64 dài (ví dụ: script update của các phần mềm).
* **Khắc phục:** Cần correlate (liên kết) trường `cmdline_shannon_entropy` với `process_tree_depth` và `file_write_rate`. Không lấy Entropy làm chỉ báo cảnh báo đơn lẻ.