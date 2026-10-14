# Collection Feasibility Notes

Bối cảnh: Phase 1, 1 endpoint Windows, collector bằng Python (`pywin32`, `psutil`), ngân sách theo `phase_1_local_data_architecture_mapping.md` (RAM < 150 MB).

## 1. Đánh giá khả thi theo nguồn

| Nguồn | Khả thi | Quyền | Cấu hình bắt buộc | Độ trễ | Rủi ro chính |
|---|---|---|---|---|---|
| **Sysmon 15+** | **Cao** | Admin để cài; admin (hoặc quyền đọc channel) để đọc | `sysmon-config.xml` (event nào, `HashAlgorithms`, rule registry/file) | Gần real-time | Config sai → thiếu dữ liệu im lặng; channel đầy → ghi đè sự kiện cũ |
| **Security 4688/4689** | Cao (khi bật policy) | Admin | Audit Process Creation + GPO command line | Gần real-time | Trùng dữ liệu với Sysmon 1; chỉ dùng để lấp token elevation / exit code |
| **Security 5156/5157** | Thấp–Trung bình | Admin | Audit Filtering Platform Connection | Gần real-time | Volume rất lớn; chỉ dùng để đối chiếu khi debug |
| **Security 4663/4657 (SACL)** | Thấp | Admin | SACL từng file/key | Gần real-time | Không bật diện rộng được; không đưa vào MVP |
| **ETW** | Thấp cho Phase 1 | Admin | Trace session + parse manifest | Real-time | Công sức lớn, mất sự kiện khi buffer đầy → chỉ làm spike |
| **psutil / Win32 enrichment** | Cao | Phần lớn không cần admin; xem process của user khác cần admin | Không | Tại thời điểm poll | Race condition (process/file đã mất), PID reuse |
| **WMI subscription** | Không khuyến nghị | Admin | — | Có trễ | Mất sự kiện, là kỹ thuật persistence của attacker |

## 2. Sysmon: cấu hình cần bật

| Event | Bật? | Ghi chú về volume / rủi ro |
|---|---|---|
| 1, 5 | Bật toàn bộ | Volume vừa; loại trừ service ồn ào bằng exclude |
| 3 | Bật, **include có chọn lọc** (vd. loại trừ loopback, process hệ thống đã biết) | Volume cao nhất trong nhóm "thường dùng" |
| 22 | Bật | Volume cao; exclude domain nội bộ/Windows Update |
| 11 | Bật theo path nhạy cảm (`\Temp\`, `\Downloads\`, `\AppData\`, `\ProgramData\`, Desktop/Documents cho ransomware) | **Không bật toàn ổ đĩa** |
| 23 **hoặc** 26 | Chọn 1 (xem mục 4) | 23 lưu bản file xóa vào thư mục archive → tốn đĩa |
| 12, 13, 14 | Bật theo danh sách key Cyber chốt | Volume thấp nếu lọc đúng |
| 15, 29 | Bật | Volume thấp; hỗ trợ T1204.002 |
| 4, 16 | Bật | Volume rất thấp; phục vụ T1562.001 |
| 7 (Image load) | **Chưa bật** | Rất ồn; chỉ xem xét khi Cyber yêu cầu cho T1218 |

`HashAlgorithms`: tối thiểu `SHA256`; thêm `IMPHASH` nếu muốn dùng cho phân tích tĩnh.

## 3. Thiết kế collector: các điểm cần chốt để đảm bảo độ tin cậy

1. **Push thay vì poll:** dùng `EvtSubscribe` với callback; poll chỉ làm cơ chế dự phòng khi mất subscription.
2. **Bookmark:** lưu bookmark ra đĩa sau mỗi batch → khởi động lại không mất/lặp sự kiện.
3. **Khóa chống trùng:** dùng `(Channel, EventRecordID)` để dedupe trước khi sinh `event_id`.
4. **Kích thước channel:** tăng kích thước log của Sysmon/Operational (`wevtutil sl … /ms:<bytes>`); nếu collector dừng lâu hơn thời gian ghi đầy channel thì sẽ mất dữ liệu — cần ghi cảnh báo khi bookmark trỏ vào bản ghi đã bị ghi đè.
5. **Thời gian:** lấy `TimeCreated/@SystemTime` (UTC, độ phân giải 100 ns) làm nguồn thời gian; `UtcTime` của Sysmon chỉ tới mili-giây. Sliding window của Data dùng đúng trường này.
6. **Bronze append-only:** ghi JSONL **trước** khi validate; lỗi chuyển sang `validation_errors.jsonl` (đã có).
7. **Enrichment tách khỏi luồng chính:** các bước dùng `os.stat`/`GetTokenInformation` chạy ở pipeline Silver, chấp nhận NULL khi object đã biến mất, và ghi cờ `enrichment_status` để Data biết trường nào là "không lấy được" thay vì "bằng 0".
8. **Heartbeat/tamper:** collector ghi định kỳ một bản ghi sức khỏe; Sysmon Event 4/16 và Security 1102 được lấy làm tín hiệu "nguồn dữ liệu bị tác động".

## 4. Quyết định cần chốt: Event 23 hay 26

| | 23 (FileDelete) | 26 (FileDeleteDetected) |
|---|---|---|
| Lưu bản sao file bị xóa | Có (thư mục archive) | Không |
| Cho phép tính `chunk_entropy` của file đã xóa an toàn (không race) | **Có** | Không |
| Chi phí đĩa | Cao (có thể đầy ổ nếu ransomware xóa hàng loạt) | Thấp |
| Rủi ro | Cần giới hạn path/kích thước | Mất khả năng lấy nội dung |

**Đề xuất:** dùng **26** cho diện rộng (rẻ), và **23 chỉ cho thư mục nhạy cảm** nếu Data thật sự cần entropy file bị xóa. Cần Data xác nhận.

## 5. Ngân sách tài nguyên

- Chưa có số đo thực. Cần đo trên lab: CPU/RAM của (a) Sysmon service, (b) collector Python, (c) pipeline Silver — rồi so với ngưỡng RAM < 150 MB / CPU < 3% (Data cần làm rõ ngưỡng này **có tính cả Sysmon hay không**, câu hỏi Q-D5).
- Đề xuất đo 3 kịch bản: nhàn rỗi 30 phút, duyệt web + mở Office, chạy bộ kịch bản mô phỏng của Cyber.

## 6. Kế hoạch xác nhận khả thi (acceptance test)

Với mỗi kỹ thuật trong 13 kỹ thuật, chạy một kịch bản vô hại trên VM lab (ví dụ Atomic Red Team) và kiểm tra: (1) sự kiện Sysmon xuất hiện, (2) đi qua Bronze → Silver không lỗi, (3) các field Required trong bảng 02 có giá trị hoặc NULL đúng như đã ghi. Kết quả điền vào cột "Độ phủ" của bảng E (file 02). Đây là bằng chứng cho mục *Candidate source exists* trong Definition of Done.
