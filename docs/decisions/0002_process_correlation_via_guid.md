# ADR 0002: Chuẩn Hóa Khóa Phả Hệ Tiến Trình Qua Process GUID

* **Trạng thái:** ACCEPTED
* **Người đề xuất:** Huỳnh Hữu Nhật (Data Engineer)
* **Ngày quyết định:** 18/10/2026
* **Các bên tham gia đồng thuận:** Cyber Team, Software Team, Data Team

---

## 1. Ngữ Cảnh Kỹ Thuật (Context)
Trên hệ điều hành Windows, mã định danh tiến trình (`ProcessId` hay PID) là một số nguyên trong dải giới hạn (thường từ 4 đến khoảng 65,535). Khi một tiến trình kết thúc, Windows sẽ nhanh chóng tái cấp phát PID này cho một tiến trình mới được sinh ra ngay sau đó (hiện tượng **PID Reuse**).

Nếu hệ thống EDR dùng PID để liên kết các hành vi:
* Một sự kiện ghi file hoặc mở kết nối socket độc hại của tiến trình malware có thể bị gán nhầm cho một tiến trình hệ thống vô hại sinh sau trùng PID.
* Dựng cây tiến trình (Process Tree / DAG) sẽ bị vòng lặp logic (cycles) hoặc gãy nhánh phả hệ.

## 2. Quyết Định Kiến Trúc (Decision)
1. **Triệt tiêu vai trò của PID trong quan hệ dữ liệu:**
   * Cột `pid` và `ppid` vẫn được lưu trữ trong bảng `silver_process_events` nhưng chỉ mang ý nghĩa tham khảo ngữ cảnh tức thời tại thời điểm thực thi.
   * **Tuyệt đối cấm** sử dụng `pid` làm khóa ngoại (Foreign Key) hoặc điều kiện JOIN trong các câu truy vấn phân tích, Rule-based Detection và mô hình AI.
2. **Bắt buộc sử dụng `process_guid` làm khóa định danh duy nhất:**
   * Mọi sự kiện điểm cuối (Process, File, Registry, Network) bắt buộc phải có trường `process_guid` liên kết về đúng thực thể tiến trình khởi tạo.
   * Trường `parent_guid` trong sự kiện Process được sử dụng làm khóa đệ quy để dựng cây quan hệ cha - con.
3. **Quy chuẩn định dạng chuỗi GUID:**
   * Sysmon xuất log thô có dạng ngoặc nhọn `{UUID}`. Pipeline chuẩn hóa tại Silver Layer bắt buộc phải strip sạch ngoặc nhọn về dạng chuỗi UUID chuẩn 36 ký tự:
     `{43f71ec6-8d5b-6ad4-2601-000000000400}` $\rightarrow$ `43f71ec6-8d5b-6ad4-2601-000000000400`.

## 3. Hệ Quả & Đánh Giá Tác Động (Consequences)
* **Tích cực:** 
  * Loại bỏ 100% hiện tượng nhận diện sai lệch do tái sử dụng PID.
  * Cho phép câu lệnh `WITH RECURSIVE` trên DuckDB dựng chính xác cây tiến trình nhiều cấp độ mà không sợ bị lặp vô tận.
* **Tiêu cực/Ràng buộc:** 
  * Cần sự phối hợp từ Software Team để đảm bảo cấu hình Sysmon sinh đầy đủ trường `ProcessGuid` và `ParentProcessGuid` trên mọi sự kiện (đã kiểm chứng thành công trong Tuần 2 và Tuần 3).