# ADR 0001: Chiến Lược Sinh Event ID Xác Định (Deterministic UUIDv5)

* **Trạng thái:** ACCEPTED
* **Người đề xuất:** Huỳnh Hữu Nhật (Data Engineer)
* **Ngày quyết định:** 18/10/2026
* **Các bên tham gia đồng thuận:** Cyber Team, Software Team, Data Team

---

## 1. Ngữ Cảnh Kỹ Thuật (Context)
Trong phiên bản thử nghiệm Tuần 1, pipeline sử dụng hàm sinh ngẫu nhiên `uuid.uuid4()` để cấp phát `event_id` cho mỗi sự kiện tại thời điểm parse dữ liệu vào Silver Layer.

Tuy nhiên, trong môi trường vận hành EDR thực tế:
* Khi pipeline gặp sự cố cần chạy lại (re-process) một file log Bronze, hàm `uuid4()` lại sinh ra một bộ `event_id` hoàn toàn mới cho cùng một sự kiện vật lý.
* Điều này dẫn đến nguy cơ nhân đôi dữ liệu (duplicate records) trong DuckDB nếu không có khóa tự nhiên, hoặc làm đứt gãy mối liên kết giữa các bảng khi kiểm toán điều tra số (Forensics Audit).

## 2. Các Phương Án Cân Nhắc (Options Considered)
1. **Phương án A: Sử dụng Windows `EventRecordID` thuần túy**
   * *Ưu điểm:* Là số nguyên tăng dần tự nhiên do Windows cấp phát.
   * *Nhược điểm:* `EventRecordID` chỉ là số cục bộ cho từng kênh log (Channel) và bị reset khi xóa log hoặc trên các máy trạm khác nhau; không đảm bảo tính toàn cục (Global Uniqueness).
2. **Phương án B: Giữ nguyên `UUIDv4` ngẫu nhiên**
   * *Ưu điểm:* Đơn giản, không phụ thuộc vào trường dữ liệu đầu vào.
   * *Nhược điểm:* Mất tính bất biến khi chạy lại dữ liệu (Non-idempotent).
3. **Phương án C: Sinh mã băm xác định `UUIDv5` (Lựa chọn áp dụng)**
   * Sinh `UUIDv5` dựa trên một Namespace DNS cố định kết hợp với chuỗi định danh tự nhiên duy nhất của sự kiện:
     $$\text{key} = \text{Computer} + "\vert{}" + \text{Channel} + "\vert{}" + \text{EventRecordID}$$

## 3. Quyết Định Kiến Trúc (Decision)
Thống nhất áp dụng **Phương án C (Deterministic UUIDv5)** cho toàn bộ hệ thống:
* Sử dụng không gian tên cố định: `EVENT_ID_NAMESPACE = uuid.UUID("6f1d3c52-8a0e-4b7a-9c1e-3d5a7b9e2f10")`.
* Khóa sinh mã băm: `key = f"{Computer}|{Channel}|{EventRecordID}"`.
* Quy tắc: `event_id = str(uuid.uuid5(EVENT_ID_NAMESPACE, key))`.

## 4. Hệ Quả & Đánh Giá Tác Động (Consequences)
* **Tích cực:** 
  * Đảm bảo tính duy nhất tuyệt đối trên toàn bộ điểm cuối và các kênh log.
  * Pipeline đạt chuẩn **Idempotent**: Dù nạp lại file Bronze bao nhiêu lần thì bản ghi tạo ra trong DuckDB vẫn giữ nguyên `event_id`, cho phép cơ chế `INSERT OR IGNORE` hoạt động hoàn hảo.
* **Tiêu cực/Ràng buộc:** 
  * Cần đảm bảo collector luôn đọc được trường `EventRecordID` từ Windows System Header (đã được kiểm chứng sẵn có 100% trong Sysmon EventLog).