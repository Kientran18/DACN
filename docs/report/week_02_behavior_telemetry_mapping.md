# Week 2: Behavior-to-Telemetry Mapping & Data Requirements v1

> **Cập nhật 2026-10-19:** Đây là mapping/đề xuất tuần 2. Ma trận bằng chứng hiện hành: [v2](../research/cyber/mitre-detection-matrix-v2.md). Event 11/23/26 không chứng minh đầy đủ write-in-place/rename; lab chọn Event 26. Các mục Full là khả năng nguồn theo khảo sát, không phải xác nhận detection đã chạy. Tên JSON và required theo Event ID được chốt trong schema tuần 3 hiệu chỉnh; quyết định cuối cùng vẫn chờ review.


## Deliverable 1: Behavior-to-Telemetry Mapping v1
Ma trận ánh xạ từ 13 kỹ thuật MITRE ATT&CK của Cyber sang Telemetry Type, Sysmon Event ID của Software, và bảng dữ liệu Silver Layer của Data.

| # | MITRE Technique | Observable Behavior | Telemetry Type | Sysmon Event ID | Silver Table (DuckDB) | Critical Correlation Key |
|---|---|---|---|---|---|---|
| 1 | **T1204.002** (Malicious File) | File rơi vào Temp/Downloads rồi thực thi | File Create, Process Create | Event ID 11, 1 | `silver_file_events`, `silver_process_events` | `image_path` == `file_path` |
| 2 | **T1059.001** (PowerShell) | Chạy `powershell.exe` với cờ ẩn, tải payload | Process Create, Network Connect | Event ID 1, 3 | `silver_process_events`, `silver_network_events` | `process_guid`, `parent_guid` |
| 3 | **T1059.003** (Command Shell) | Shell thực thi từ tiến trình cha bất thường (Word, Excel) | Process Create | Event ID 1 | `silver_process_events` | `parent_guid` -> `process_guid` |
| 4 | **T1218** (System Binary Proxy) | LOLBin (`rundll32`, `regsvr32`) chạy payload từ path lạ | Process Create | Event ID 1 | `silver_process_events` | `process_guid`, `command_line` |
| 5 | **T1547.001** (Registry Run Keys) | Sửa khóa AutoRun trỏ tới file thực thi lạ | Registry Event | Event ID 12, 13 | `silver_registry_events` | `process_guid`, `target_object` |
| 6 | **T1053.005** (Scheduled Task) | `schtasks.exe` tạo task trỏ vào Temp/AppData | Process Create | Event ID 1 | `silver_process_events` | `process_guid`, `command_line` |
| 7 | **T1562.001** (Disable Tools) | Tiến trình agent bị kill, tắt service | Process Terminate | Event ID 5 | `silver_process_events` | Target PID / ImageName |
| 8 | **T1082** (System Info Discovery)| Chạy liên tiếp `systeminfo`, `whoami` | Process Create | Event ID 1 | `silver_process_events` | `parent_guid` |
| 9 | **T1083** (File/Dir Discovery) | Liệt kê cây thư mục hàng loạt | Process Create | Event ID 1 | `silver_process_events` | `parent_guid`, `command_line` |
| 10 | **T1105** (Ingress Tool Transfer)| Ghi file nhị phân mới sau khi kết nối mạng | Network Connect, File Create | Event ID 3, 11 | `silver_network_events`, `silver_file_events` | `process_guid` |
| 11 | **T1071.001** (Web Protocols) | Kết nối lặp lại ra IP ngoài qua cổng 80/443 | Network Connect, DNS Query | Event ID 3, 22 | `silver_network_events` | `process_guid`, `dest_ip` |
| 12 | **T1070.004** (File Deletion) | Drop-Execute-Delete sequence | File Create, Process, File Delete | Event ID 11, 1, 23 | `silver_file_events`, `process`| `file_path`, `file_sha256` |
| 13 | **T1486** (Data Encrypted) | Ghi/đổi tên file hàng loạt | File Write, Rename, Delete | Event ID 11, 23 | `silver_file_events` | `process_guid`, time delta |

## Deliverable 2: Telemetry Requirements v1 (Rule-Based vs AI/Feature Candidates)

### 1. Nhóm trường phục vụ Rule-Based Detection (Deterministic Rules)
Yêu cầu tính xác định cao (Exact Match, Regex, Static Logic):
* **`image_path` & `parent_image`:** Phục vụ DET-001, DET-002 (Phát hiện tiến trình cha là Word/Excel spawn shells).
* **`command_line`:** Dùng Regex bắt các cờ PowerShell (`-enc`, `-w hidden`).
* **`file_path`:** Kiểm tra thực thi từ các vùng nhạy cảm (`\AppData\Local\Temp`, `\Downloads`).
* **`target_object` (Registry):** Bắt cứng các khóa Run/RunOnce (`\CurrentVersion\Run`).
* **`file_sha256`:** Tra cứu IOCs / Blacklist / Whitelist.
* **`dest_port`:** Lọc các port lạ không qua HTTP/HTTPS.

### 2. Nhóm trường ứng viên cho AI & Feature Engineering (Gold Layer)
* **`cmdline_shannon_entropy`:** Entropy của chuỗi lệnh ($0.0 \rightarrow 8.0$), dùng để phát hiện payload bị obfuscate.
* **`cmdline_length` & `cmdline_special_char_ratio`:** Đặc trưng cho Autoencoder phát hiện chuỗi thực thi bất thường.
* **`file_write_rate_per_sec` & `file_extension_diversity`:** Đặc trưng cốt lõi để train mô hình bắt Ransomware (DET-008).
* **`network_unique_dest_ip_count`:** Phát hiện quét mạng hoặc C2 beaconing qua cửa sổ 5 phút.
* **`process_tree_depth` & `process_dag_out_degree`:** Đếm độ sâu của Process Tree (Recursive CTE) để tìm Living-off-the-Land attacks.

## Deliverable 3: Initial Event Field List
*(Đã được định nghĩa chi tiết tại file `edr_data_requirements_architecture_2.md`)*.

## Deliverable 4: Initial Data Requirements Notes (Ghi chú Kỹ thuật & Rủi ro)
1. **Rủi ro PID Reuse:** Windows tái sử dụng PID rất nhanh. Bắt buộc dùng `process_guid` sinh từ Sysmon làm khóa chính liên kết giữa tất cả các sự kiện thay cho `pid`.
2. **Đồng bộ thời gian (Time Drift):** Mọi logic trượt cửa sổ thời gian (Sliding Window) phải dựa trên `timestamp` UTC của Sysmon event, không được tính dựa trên thời điểm insert vào DB.
3. **Cấu hình Sysmon:** Team Software cần đảm bảo file `sysmon-config.xml` bật đủ các Event ID 1, 3, 5, 11, 12, 13, 14, 22, 23.
