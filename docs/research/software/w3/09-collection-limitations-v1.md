# Collection Limitations v1

Kế thừa từ `04-technical-limitations-open-questions.md` (Week 2). Các mục dưới là **giả thuyết cần xác minh bằng thí nghiệm** trên VM; sau khi có kết quả, cập nhật cột "Kết quả" và sửa file Week 2 nếu giả thuyết sai.

## 1. Quyền cần thiết (Required Permissions)

| Tác vụ | Quyền dự kiến | Đã xác minh trên VM? |
|---|---|---|
| Cài, gỡ, cập nhật Sysmon | Administrator (cài driver) | ☐ |
| Đọc kênh `Sysmon/Operational` (Get-WinEvent, wevtutil, `EvtQuery`) | Thường cần Administrator; có thể cấp quyền đọc channel cho tài khoản khác (nhóm Event Log Readers hoặc `wevtutil sl /ca`) | ☐ (thí nghiệm E10) |
| Đổi kích thước channel (`wevtutil sl /ms`) | Administrator | ☐ |
| Đọc Security log (4688, 4689, 1102) | Administrator / quyền `SeSecurityPrivilege` | ☐ |
| Bật Audit Policy, GPO command line | Administrator | ☐ |
| Chạy `run-poc-activities.ps1` | Người dùng thường (ghi `%TEMP%`, `HKCU`) | ☐ |
| `psutil` snapshot (net_connections, process_iter) | Phần lớn user thường; xem tiến trình của user khác cần Administrator | ☐ |
| Chạy `export-samples.ps1` | Administrator (có `#Requires`) | ☐ |

## 2. Giới hạn đã biết

| # | Giới hạn | Ảnh hưởng | Cách xử lý Phase 1 | Thí nghiệm |
|---|---|---|---|---|
| L1 | Không có sự kiện write / rename / read file | DET-008 chỉ phủ một phần | Đếm Event 11 + 26 theo cửa sổ; Q-C1 | E1, E2, E3 |
| L2 | Event 11 không có hash và kích thước | Hash/size phải lấy từ Event 29/15 hoặc tính lại (có race) | Event 29, enrichment ở Silver | E8 |
| L3 | Registry: không có giá trị cũ, nội dung binary, mã trạng thái | DET-003 không biết giá trị trước đó | `previous_data_*` = NULL | E5, E6 |
| L4 | Network: không có TCP state, bytes, duration, SNI, LISTEN | DET-006 chỉ theo tần suất | Correlate DNS ↔ Event 3 | E7 |
| L5 | Thiếu `token_elevation_type`, `exit_code`, `is_wow64`, `user_sid` | Một số field Required của Data để NULL | Security 4688/4689 hoặc enrichment | Mẫu file 03 |
| L6 | Process có từ trước Sysmon không có Event 1 | Process tree cụt | Lưu `parent_image`, cờ `tree_truncated` | Mẫu file 03 |
| L7 | Volume cao (Event 1, 5, 3, 22 đang ghi tất cả) | Có thể nghẽn pipeline, đầy channel | Đo và thêm exclude; channel 256 MB | E9 |
| L8 | Collector user-space có thể bị kill; Sysmon 15+ khó kill hơn nhưng không miễn nhiễm với Admin | DET-007 | Watchdog là process riêng (TR-05) | — |
| L9 | Chỉ phát hiện, không chặn trước khi chạy | EPP "block execution" không có | Terminate/Quarantine sau khi chạy (Q-C8) | — |

## 3. Thí nghiệm xác minh

Lệnh đếm sự kiện: `Get-WinEvent -LogName 'Microsoft-Windows-Sysmon/Operational' | Group-Object Id | Sort-Object Count -Descending`.

| Mã | Câu hỏi | Cách làm | Giả thuyết | **Kết quả** (điền) | Ảnh hưởng |
|---|---|---|---|---|---|
| E1 | Ghi đè file có sinh Event 11? | Bước 3 (`Set-Content` lên file có sẵn) | Có (truncate) | | Q-C1, DET-008 |
| E2 | Nối thêm vào file có sinh Event 11? | Bước 3 (`Add-Content`) | Không | | Q-C1 |
| E3 | Đổi tên file có sinh sự kiện? | Bước 3 (`Rename-Item`) | Không | | Q-C1 |
| E4 | Event 26 ghi những trường nào (có Hashes)? | Xóa file trong Temp | Có Hashes, IsExecutable | | Q-C2 |
| E5 | Xóa value / xóa key cho `EventType` nào? | Bước 4 | `DeleteValue`, `DeleteKey` | | Ánh xạ operation |
| E6 | `TargetObject` của HKCU có dạng `HKU\<SID>\...`? | Bước 4 | Có | | Rule Sysmon, regex Cyber |
| E7 | `DestinationIp` (Event 3) nằm trong `QueryResults` (Event 22)? | Bước 5 | Có | | Correlate DNS |
| E8 | Copy PE vào Temp có sinh Event 29? Event 11 có cho cả `.txt` và `.exe`? | Bước 3 | Có | | Hash lúc tạo file |
| E9 | Bao nhiêu sự kiện/giờ khi máy nhàn rỗi và khi dùng bình thường? | Đếm theo ID trong 30 phút | Event 1, 5, 3, 22 chiếm đa số | | TR-07, exclude |
| E10 | Người dùng thường có đọc được kênh Sysmon không? | Chạy `Get-WinEvent` không có quyền Admin | Bị từ chối | | Bảng quyền ở mục 1 |

## 4. Việc cần làm sau khi có kết quả
- [ ] Cập nhật cột "Kết quả" và bảng quyền.
- [ ] Sửa `04-technical-limitations-open-questions.md` (Week 2) nếu giả thuyết sai.
- [ ] Cập nhật `sysmon-config.xml` và CHANGELOG (file 02).
