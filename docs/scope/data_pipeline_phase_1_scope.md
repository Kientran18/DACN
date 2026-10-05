# Phase 1 Scope: Data Engineering & Pipeline

## 1. Mục tiêu (Objective)
Định nghĩa rõ giới hạn, trách nhiệm và cấu hình kiến trúc của phân hệ Dữ liệu (Data Pipeline) trong Giai đoạn 1 (Local EDR Prototype). Phân hệ dữ liệu chịu trách nhiệm thu thập, chuẩn hóa, lưu trữ và trích xuất đặc trưng phục vụ cho Rule-based Detection và AI/ML models.

## 2. Trong phạm vi (In-Scope)
- **Nguồn dữ liệu (Ingestion):** Giới hạn ở việc đọc log cục bộ từ Microsoft Sysmon (v15+) qua Windows Event Log (kênh `Microsoft-Windows-System/Operational`).
- **Telemetry hỗ trợ:** Giới hạn thu thập và xử lý các Sysmon Event ID: 1, 3, 5, 11, 12, 13, 14, 22, 23/26 (tương ứng với Process, File, Registry, Network, DNS).
- **Kiến trúc lưu trữ (Local Medallion Architecture):**
  - **Bronze:** Lưu trữ log thô dạng JSONL.
  - **Silver:** Validate bằng Pydantic và lưu trữ bằng DuckDB (embedded OLAP) cho 4 bảng chuẩn: Process, File, Registry, Network.
  - **Gold:** Trích xuất đặc trưng ra định dạng `.parquet` (Feature Store cục bộ).
- **Feature Engineering:** Tính toán các đặc trưng cơ bản như: Cây tiến trình (Process Tree Depth), Tính toán tần suất cửa sổ trượt (Sliding Windows), và độ hỗn loạn chuỗi lệnh (Shannon Entropy).
- **Hỗ trợ Detection:** Cung cấp cơ sở dữ liệu DuckDB với tốc độ truy vấn `< 100ms` để Cyber team đối chiếu với 10 Detection Rules (DET-001 đến DET-010).

## 3. Ngoài phạm vi (Out-of-Scope cho Phase 1)
Để đảm bảo tiến độ và phù hợp với giới hạn của Prototype (1 máy Windows VM), các tính năng sau sẽ được **hoãn lại sang Phase 2 hoặc bản Enterprise**:
- **Không thu thập từ Kernel:** Không lập trình Minifilter driver, eBPF, hay gọi API `PsSetCreateProcessNotifyRoutineEx`. Bàn giao toàn bộ việc móc nối OS cho Sysmon.
- **Không dùng Big Data Streaming:** Bỏ qua Microsoft Fabric, Apache Kafka, Apache Flink. Dữ liệu chạy hoàn toàn theo luồng xử lý cục bộ bằng Python/DuckDB.
- **Không lưu trữ Cloud Lakehouse:** Bỏ qua OneLake, Delta Lake, AWS S3. Tất cả dữ liệu nằm trên ổ cứng của VM lab.
- **Không dùng Graph Neural Networks (GNN):** Trong Phase 1, việc phát hiện bất thường trên Process Tree sẽ dùng SQL đệ quy (Recursive CTE) và các rule tĩnh thay vì train mạng GNN phức tạp.

## 4. Ràng buộc Kỹ thuật (Technical Constraints)
- **Môi trường:** Chạy trên Python 3.11 trong Windows 10/11 VM chung của team.
- **Tài nguyên (Hardware Budget):** Vì Python nặng hơn C/Rust, Pipeline cần tối ưu hóa batch-insert (dùng `executemany` của DuckDB) để giữ mức tiêu thụ RAM `< 200MB` và không gây nghẽn CPU (spike) quá 5% trên máy lab.
- **Tính toàn vẹn (Integrity):** Bắt buộc sử dụng `process_guid` làm khóa chính liên kết giữa tất cả các sự kiện thay cho PID để chống tái sử dụng PID của Windows.