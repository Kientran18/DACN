# Nghiên Cứu: Cơ Chế Suy Diễn Kiểu Dữ Liệu Registry (Registry Type Inference Heuristics)

**Người thực hiện:** Huỳnh Hữu Nhật (Data Engineer)  
**Thời điểm:** Tuần 3 (10/2026)  
**Mục tiêu:** Giải quyết hạn chế mất thông tin kiểu dữ liệu (data gaps) trong Sysmon Event ID 13 phục vụ luật phát hiện Persistence.

---

## 1. Giới Hạn Của Sysmon Đối Với Registry Telemetry
Trong kiến trúc Windows Registry gốc, mỗi giá trị (Value) được lưu trữ với một kiểu dữ liệu tường minh như `REG_SZ` (chuỗi ký tự), `REG_DWORD` (số nguyên 32-bit), `REG_QWORD` (số nguyên 64-bit), hoặc `REG_BINARY` (mảng byte).

Tuy nhiên, Microsoft Sysmon (Event ID 13 - `SetValue`) chuyển đổi toàn bộ trường dữ liệu thành chuỗi văn bản thuần túy trong thuộc tính `Details`:
* Giá trị DWORD số `1` được hiển thị thành chuỗi: `"DWORD (0x00000001)"`.
* Giá trị QWORD được hiển thị thành chuỗi: `"QWORD (0x0000000000000001)"`.
* Mảng nhị phân hiển thị dạng nhãn: `"Binary Data"`.
* Giá trị chuỗi thực thi (ví dụ: đường dẫn file mã độc) hiển thị dạng chuỗi gốc: `"C:\Users\...\malware.exe"`.

**Vấn đề:** Nếu lưu trữ `Details` thành text mà không phân loại kiểu, luật phát hiện của Cyber (Rule-based detection) sẽ rất khó kiểm tra nhanh các giá trị cờ nhị phân (ví dụ: cờ vô hiệu hóa Defender thường là DWORD = 1) mà buộc phải dùng biểu thức chính quy (Regex) làm chậm tốc độ quét.

---

## 2. Giải Thuật Suy Diễn Heuristic (Inference Logic)
Dựa trên phân tích mẫu dữ liệu thực nghiệm PoC thu thập được (`registry.json`), thuật toán suy diễn được tối ưu hóa như sau:

```python
def infer_registry_value_type(details: str | None) -> str:
    """
    Suy diễn kiểu dữ liệu Registry nguyên bản dựa trên định dạng text của Sysmon.
    """
    if not details:
        return "UNKNOWN"
    
    # 1. Nhận diện DWORD (32-bit integer)
    if details.startswith("DWORD ("):
        return "REG_DWORD"
    
    # 2. Nhận diện QWORD (64-bit integer)
    if details.startswith("QWORD ("):
        return "REG_QWORD"
    
    # 3. Nhận diện Dữ liệu nhị phân
    if details.startswith("Binary Data"):
        return "REG_BINARY"
    
    # 4. Trường hợp còn lại là chuỗi (REG_SZ / REG_EXPAND_SZ)
    return "STRING_UNSPECIFIED"
```

## 3. Phân Tách Đường Dẫn Khóa Registry (Path Normalization)

Trường `TargetObject` của Sysmon ghi nhận toàn bộ đường dẫn:
`HKU\S-1-5-21-...\SOFTWARE\EDR_PoC\TestDword`

Để phục vụ truy vấn tối ưu trong DuckDB Silver, ta áp dụng thuật toán tách chuỗi thành 3 thành phần:

1. `hive`: Lấy phần tử đầu tiên (`parts[0]`) $\rightarrow$ Phân lớp nhánh cấp cao (`HKLM`, `HKCU`, `HKU`).
2. `value_name`: Lấy phần tử cuối cùng (`parts[-1]`) khi thao tác là `SetValue` hoặc `DeleteValue`.
3. `key_path`: Nối các phần tử ở giữa lại $\rightarrow$ Nhánh khóa phục vụ khớp mẫu các khóa Run/RunOnce hay IFEO.  

---

## 4. Kết Quả Kiểm Thử (Unit Test Verification)
Các trường hợp kiểm thử sau đã pass 100% trong `test_sysmon_collector_poc.py`:

* `DWORD (0x00000001)` $\rightarrow$ `REG_DWORD`
* `QWORD (0x0000000000000001)` $\rightarrow$ `REG_QWORD`
* `Binary Data` $\rightarrow$ `REG_BINARY`
* `C:\Users\Trankien\...\EDR_POC.exe` $\rightarrow$ `STRING_UNSPECIFIED`

Giải pháp này hoàn toàn bù đắp được khoảng trống dữ liệu (Data Gaps) của Sysmon mà không gây quá tải bộ xử lý của máy trạm.