# MITRE Detection Matrix v2 đối chiếu mẫu tuần 3

Bản đề xuất 2026-10-19, chờ Cyber/Data/Software review. Phân loại này đánh giá telemetry và khả năng thiết kế detection, không phải kết quả detection hay kiểm thử tấn công. 13 techniques giữ từ tuần 2; DET là mã ý tưởng detection nội bộ.

## Quy ước bằng chứng

- P: raw_process_create_event1.xml; F: raw_file_create_event11.xml; R: raw_registry_setvalue_event13.xml.
- N: raw_network_connect_event3.xml; D: raw_dns_query_event22.xml; X: raw_file_delete_event26.xml; E: raw_file_executable_event29.xml; T: raw_process_terminate_event5.xml.
- Các file ở references/samples/raw. Lần chạy EDR_POC_20261018_021142, Windows 10.0.19045, Sysmon 15.22. Báo cáo hoạt động ghi 5 bước ok.
- Mẫu vô hại chỉ xác minh event/field. Không kết luận hành vi độc hại, độ chính xác rule hoặc technique đã được tái hiện đầy đủ.

## Ma trận

| Technique | Hành vi và DET | Nguồn/field cần | Bằng chứng hiện có | Độ phủ và phần chưa xác minh |
|---|---|---|---|---|
| T1204.002 | File được người dùng mở/chạy; DET-010 hỗ trợ chuỗi thực thi | 11/1; file_path, Image, parent, timestamp | F/P/E: drop.exe từ Temp được tạo và chạy | Một phần; không chứng minh user click, download origin hoặc malicious intent |
| T1059.001 | PowerShell bất thường; DET-001 | 1; Image, ParentImage, CommandLine | P có ngữ cảnh cha; N/D có PowerShell | Field khả dụng; chưa thử Office spawn/encoded command và chưa đánh giá rule |
| T1059.003 | CMD từ cha bất thường; DET-002 | 1; parent/command line | Báo cáo hoạt động chạy cmd; T có cmd kết thúc | Có cơ sở nguồn; cần chọn thêm mẫu ID 1 cmd và kịch bản cha bất thường |
| T1218 | Binary hệ thống proxy execution | 1, có thể 7; Image/CommandLine/module | P chỉ là binary vô hại được copy | Chưa kiểm chứng proxy execution; ImageLoad chưa bật trong config hiện tại |
| T1547.001 | Run key/Startup persistence; DET-003 | 12/13, 11; TargetObject, Details, Image | R là khóa EDR_PoC | Registry source đã xác minh; chưa có mẫu Run/Startup persistence |
| T1053.005 | Scheduled task persistence; DET-004 | 1 schtasks; TaskScheduler/Security hoặc TaskCache | Chưa có mẫu task | Một phần theo thiết kế; chưa xác minh tạo task qua CLI/COM |
| T1562.001 | Disable tools; DET-007 | 5, service/config, heartbeat | T; 4/16 là service/config của Sysmon | Một phần; process exit không cho biết bị kill bởi ai; chưa có watchdog hay thử tamper |
| T1082 | System information discovery; DET-009 | 1; command line/parent | Script gọi whoami/hostname, mẫu chọn hiện tại chưa đủ chuỗi | Cần chọn thêm event để đối chiếu; chưa xác minh toàn bộ discovery |
| T1083 | File/directory discovery; DET-009 | 1 CLI; nguồn API bổ sung | Không có mẫu enumeration | Một phần; API enumeration không được chứng minh bởi ProcessCreate |
| T1105 | Kết nối rồi tải/ghi công cụ; DET-005 | 3/22/11/1/29; GUID/path/time/hash | N/D và F/E có các loại cần | Chưa chứng minh cùng luồng download; script copy hostname nội bộ và request example.com riêng |
| T1071.001 | Web communication/C2; DET-006 | 3/22; GUID, IP/port/domain, timestamp | N/D cùng ProcessGuid, HTTPS 443/example.com | Metadata đã xác minh; một request không chứng minh C2/beaconing, không có nội dung TLS |
| T1070.004 | File deletion; DET-010 | 11/1/26; path/hash/time | F/P/X có mẫu tạo/chạy/xóa drop.exe | Có mẫu chuỗi vô hại; chưa triển khai rule/đánh giá intent; dùng Event 26 trong lab |
| T1486 | Encryption/ransomware-like activity; DET-008 | 11/26 + nguồn write/rename/entropy bổ sung | F/X chỉ tạo/xóa mẫu | Yếu/một phần; không có bằng chứng mã hóa, đầy đủ write-in-place/rename hoặc file entropy |

## Quyết định đề xuất để review

1. Dùng Event 26 cho mẫu xóa file của lab hiện tại; không ngầm yêu cầu Event 23/archive nếu chưa có nhu cầu.
2. DET-008 chỉ dùng tần suất create/delete như proxy có giới hạn; không đặt tên file_write_rate cho bộ đếm Event 11 hoặc coi entropy command line là entropy nội dung file.
3. DET-007 cần mô hình service/watchdog riêng; Event 4/16 chỉ phản ánh Sysmon, không mọi service.
4. Chốt event_type theo schema tuần 3; giữ tên detection tách biệt tên sự kiện.
5. Chưa yêu cầu chạy đủ 13 kỹ thuật ngay tuần 3; phải ghi rõ từng phần đã/ chưa kiểm chứng. Kịch bản kiểm thử đầy đủ thuộc tuần 10.

## Review

Chưa có xác nhận nghiệm thu của cả ba bên. Ghi người, ngày và link review tại [hồ sơ chung](../../project/week-01-03-review-and-ownership.md). Các phát biểu Full trong mapping tuần 2 chỉ là khả năng nguồn theo tài liệu, không thay bảng bằng chứng này.
