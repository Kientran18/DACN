# Báo Cáo Tiến Độ Tuần 2: Behavior-to-Telemetry Mapping & Data Requirements

**Dự án:** Hệ thống Giám sát & Phát hiện Xâm nhập Điểm cuối Cục bộ (Local EDR)  
**Vai trò phụ trách:** Data Engineer / Pipeline & Storage  
**Thời gian hoàn thành:** Tuần 2 (Kế hoạch 12 tuần ĐACN)  
**Trạng thái:** REVIEW (Sẵn sàng họp chéo với Cyber & Software)

---

## 1. Mục Tiêu & Phạm Vi Công Việc Tuần 2
Tiếp nối tầng lưu trữ Silver Layer (DuckDB) đã xây dựng ở Tuần 1, mục tiêu của Tuần 2 là kết nối logic giữa 3 bộ phận (Cyber, Software, Data). Cụ thể: ánh xạ 13 hành vi tấn công MITRE ATT&CK đã chốt của Cyber thành các Telemetry type, đối chiếu với Event ID của Sysmon (Software), và định nghĩa rõ schema/trường dữ liệu nào phục vụ cho Rule-based, trường nào cho AI/Feature Engineering.

**Definition of Done (DoD) đạt 100%:** Đã hoàn tất mọi tài liệu ánh xạ, định nghĩa trường dữ liệu và hoàn thành POC nghiên cứu trích xuất đặc trưng.

---

## 2. Cấu Trúc Tài Liệu Đã Bổ Sung (Architecture & Scope)
Để tương thích với thiết kế "Local EDR" (không dùng server trung tâm) của Phase 1, các tài liệu sau đã được thêm vào hệ thống:

```text
ĐACN/
├── architecture/
│   ├── phase_1_local_data_architecture_mapping.md   # Down-scale từ Lakehouse xuống DuckDB
│   └── sysmon_to_silver_schema_mapping.md           # Ánh xạ Sysmon Event ID sang Pydantic Schema
├── scope/
│   └── data_pipeline_phase_1_scope.md               # Giới hạn in-scope/out-of-scope của Data Phase 1
└── research/                                        # Các POC truy vấn & thuật toán cho tầng Gold
    ├── duckdb_process_tree_recursive_cte.md         
    ├── duckdb_sliding_window_aggregations.md        
    └── shannon_entropy_feature_extraction.md
```

---

## 3. Các Thành Phần Đã Hoàn Thiện (Deliverables)
### 3.1. Deliverable 1: Behavior-to-Telemetry Mapping v1
Bảng ma trận liên kết giữa Kịch bản tấn công (Cyber) $\rightarrow$ Năng lực thu thập (Software) $\rightarrow$ Bảng lưu trữ (Data):

| MITRE Technique | Observable Behavior | Telemetry Type (Sysmon) | Silver Table (DuckDB) | Correlation Key |
|---|---|---|---|---|
| **T1204.002 (Malicious File)** | File rơi vào Temp rồi thực thi | File Create (11), Process (1) | `file_events`, `process_events` | `image_path` == `file_path` |
| **T1059.001 (PowerShell)** | Chạy `powershell` với cờ ẩn, tải payload | Process (1), Network (3) | `process_events`, `network_events` | `process_guid` |
| **T1059.003 (CMD)** | Word/Excel spawn `cmd.exe` | Process Create (1) | `process_events` | `parent_guid` $\rightarrow$ `process_guid` |
| **T1547.001 (Run Keys)** | Sửa khóa AutoRun trỏ tới mã độc | Registry (12, 13) | `registry_events` | `process_guid`, `target_object` |
| **T1105 (Ingress Tool)** | Socket ra ngoài rồi ghi file nhị phân | Network (3), File Create (11) | `network_events`, `file_events` | `process_guid`, time delta |
| **T1486 (Ransomware)** | Đổi tên/ghi file hàng loạt trong thời gian ngắn | File Write/Rename/Delete (11, 23) | `file_events` | `process_guid`, rate/sec |

*(Lưu ý: Bảng chi tiết 13 kỹ thuật đã được lưu trong hồ sơ hệ thống).*

### 3.2 Deliverable 2: Initial Event Field List (Chuẩn hóa Schema)

* **Common Fields (Mọi event đều phải có):** `event_id` (UUIDv4), `timestamp` (UTC chuẩn hóa, không dùng local time để tính sliding window), `event_type`, `host_id` và đặc biệt là `process_guid` (Thay thế hoàn toàn PID để chống rủi ro PID Reuse trên Windows).
* **Process Events:** `parent_guid`, `image_path`, `command_line`, `user_name`, `file_sha256`.
* **File/Registry/Network:** `file_path`, `operation`, `target_object`, `dest_ip`, `dest_port`.

### 3.3 Deliverable 3: Telemetry Requirements (Phân lớp Detection vs AI)
* **Rule-Based Fields (Yêu cầu độ chính xác cao / Exact Match):**
    * `image_path` & `parent_image`: Bắt các chuỗi bất thường (Word sinh PowerShell).
    * `command_line`: Regex bắt cờ mã hóa (`-enc`, `-w hidden`).
    * `target_object`: Khớp regex các khóa Registry nhạy cảm (`\Run`, `Winlogon`).
    * `file_sha256`: Phục vụ check hash tĩnh.
* **AI & Feature Engineering Fields (Yêu cầu tính toán logic / Gold Layer):**
    * Tốc độ/Tần suất (`file_write_rate_per_sec`): Dùng cho Isolation Forest bắt Ransomware.
    * Độ hỗn loạn (`cmdline_shannon_entropy`): Nhận diện payload bị obfuscate.
    * Cấu trúc đồ thị (`process_tree_depth`): Tìm Living-off-the-Land (LotL) qua độ sâu của DAG.

---

## 4. Kết Quả Nghiên Cứu POC (Research for Gold Layer)
Để chuẩn bị cho việc xây dựng Feature Store ở Tuần 3, các thử nghiệm công nghệ sau đã thành công:
1. **Process Tree Reconstruction:** Đã viết thành công câu truy vấn `WITH RECURSIVE` trên DuckDB (thời gian phản hồi < 50ms) để dựng ngược cây tiến trình từ `process_guid` về `parent_guid`.
2. **Sliding Window Aggregations:** Tận dụng DuckDB Window Functions (`OVER PARTITION BY`) để đếm tần suất ghi file trong cửa sổ 60s/300s mà không làm ngốn CPU của Python pipeline.
3. **Shannon Entropy:** Đã thiết kế module Python tính độ hỗn loạn của `command_line` (thang điểm 0.0 - 8.0) để nhận diện lệnh Base64/Obfuscated.

---

## 5. Bàn Giao & Kế Hoạch Tiếp Theo (Tuần 3)

1. **Giao tiếp liên team (Đóng Tuần 2):**
    * Đưa Báo cáo và Ma trận này cho Cyber review chốt quy tắc.
    * Yêu cầu Software cấu hình Sysmon (`sysmon-config.xml`) đảm bảo bật đủ các Event ID: **1, 3, 5, 11, 12, 13, 14, 22, 23/26**.
2. **Nhiệm vụ trọng tâm Tuần 3 (Data):**
    * Code logic trích xuất (module `pipeline/features/extractor.py`) dựa trên 3 POC đã nghiên cứu.
    * Chạy thử nghiệm trên dữ liệu log (Bronze/Silver) hiện tại và xuất thành công ra định dạng `data/gold/feature_store.parquet`.