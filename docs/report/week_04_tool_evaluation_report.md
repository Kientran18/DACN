# Báo Cáo Tiến Độ Tuần 4: Đánh Giá Mô Hình Dữ Liệu Các Công Cụ Mã Nguồn Mở & Định Hướng Tích Hợp Pipeline

**Dự án:** Hệ thống Giám sát & Phát hiện Xâm nhập Điểm cuối Cục bộ (Local EDR)  
**Vai trò phụ trách:** Huỳnh Hữu Nhật (Data Engineer / Pipeline & Storage)  
**Thời gian thực hiện:** Tuần 4 (19/10/2026 – 25/10/2026 | Kế hoạch 12 tuần ĐACN)  
**Trạng thái:** Báo cáo nghiên cứu Data W4 hoàn thành bản nội dung; các tuyên bố về benchmark và review M1 phải đối chiếu bằng chứng độc lập.

---

## 1. Mục Tiêu & Phạm Vi Công Việc Tuần 4

Tiếp nối kết quả thiết kế `Endpoint Event Schema v1` và ánh xạ dữ liệu thực nghiệm ở Tuần 3 (`#15`), trọng tâm của Tuần 4 thuộc giai đoạn nghiên cứu và thiết kế kiến trúc là khảo sát toàn diện 5 công cụ mã nguồn mở trọng yếu trong hệ sinh thái EDR (**Microsoft Sysmon, Wazuh, osquery, Velociraptor, Atomic Red Team**) dưới góc nhìn Kỹ thuật Dữ liệu (Data Engineering):
* **Phân định rõ vai trò kiến trúc:** Không đánh đồng các công cụ là giải pháp thay thế tương đương; phân tích đúng bản chất từng công cụ (Kernel Event Collector, SIEM/XDR Platform, State Query Engine, DFIR/VQL Hunter, và Adversary Emulation Framework).
* **Khảo sát minh bạch có dẫn nguồn:** Ưu tiên tài liệu chính thức (Official Documentation), ghi nhận rõ phiên bản, ngày khảo sát và phân tách rạch ròi giữa **kết quả đã thử nghiệm thực tế (Tested PoC)** với **nhận định từ tài liệu chính thức (Documentation-based Assessment)**.
* **Đối chiếu với `Endpoint Event Schema v1`:** Đánh giá khả năng cung cấp 4 nhóm telemetry (Process, File, Registry, Network), độ chính xác timestamp, định danh máy trạm (`hostname`), khóa liên kết tiến trình (`process_guid`), chiến lược chống trùng lặp (`UUIDv5`) và bảo tồn dữ liệu thô (`raw_data`).
* **Định hướng quyết định công cụ & chuẩn bị đầu vào Tuần 5:** Đưa ra đề xuất **Sử dụng / Tham khảo / Loại khỏi phạm vi triển khai** cho ma trận quyết định chung của nhóm, đồng thời thiết kế quy trình gắn nhãn Ground-Truth từ Atomic Red Team phục vụ pipeline ETL và trích xuất đặc trưng AI ở Tuần 5.

---

## 2. Tổng Hợp Kết Quả Đánh Giá 5 Công Cụ Theo Vai Trò Dữ Liệu

Bảng dưới đây tóm tắt vai trò, trạng thái kiểm chứng và quyết định đề xuất từ góc nhìn Data Engineering (chi tiết khảo sát được trình bày tại `docs/research/data/w4/open_source_edr_tools_data_model_survey.md` và `docs/research/data/w4/atomic_red_team_ground_truth_labeling.md`):

| Công Cụ | Phiên Bản Khảo Sát | Vai Trò Kiến Trúc Cốt Lõi | Mức Độ Kiểm Chứng (Tuần 2–4) | Đáp Ứng Schema v1 | Đề Xuất Góc Nhìn Data |
| :--- | :--- | :--- | :--- | :---: | :--- |
| **Microsoft Sysmon** | v15.15 (Khảo sát 20/10/2026) | **Real-time Event-driven Telemetry Collector** (Kernel Driver + Windows Event Log) | **Đã thử nghiệm thực tế (Tested PoC)** trên host `DESKTOP-IDEMGQU` | Độ phủ trường cần đối chiếu theo Event ID; chưa có phép đo 95% | **SỬ DỤNG CHÍNH THỨC (Primary Collector)** làm nguồn sinh dữ liệu Bronze/Silver duy nhất. |
| **Atomic Red Team** | Invoke-AtomicRedTeam v2.2+ (Khảo sát 21/10/2026) | **Adversary Emulation & Ground-Truth Labeling Source** (Mô phỏng tấn công theo MITRE ATT&CK) | **Khảo sát metadata/kịch bản theo tài liệu**; chưa có bằng chứng chạy Atomic Test trên lab | *N/A* (Không phải collector; dùng ánh xạ nhãn `mitre_technique_id`) | **SỬ DỤNG CHÍNH THỨC (Test & Labeling Source)** để sinh dữ liệu tấn công có nhãn cho Detection/AI. |
| **Velociraptor** | v0.72.x (Khảo sát 22/10/2026) | **DFIR, Live Response & VQL Stream Engine** (Truy vấn sâu và thu thập bằng chứng số) | **Nhận định từ tài liệu chính thức** (Chưa cài đặt agent) | Phụ thuộc artifact/source, chưa có số liệu kiểm chứng tỷ lệ | **THAM KHẢO KIẾN TRÚC (Reference Only)** – Học hỏi tư duy VQL Enrichment & Artifact packaging; **Loại khỏi phạm vi cài đặt**. |
| **osquery** | v5.13.x (Khảo sát 22/10/2026) | **Relational OS State & Snapshot Engine** (Truy vấn trạng thái hệ điều hành bằng SQL) | **Nhận định từ tài liệu chính thức** (Chưa cài đặt daemon) | Snapshot có blind spots; chưa có số liệu tỷ lệ | **THAM KHẢO KIẾN TRÚC (Reference Only)** – Tham khảo thiết kế bảng SQL & differential log; **Loại khỏi phạm vi cài đặt**. |
| **Wazuh** | v4.9.x (Khảo sát 23/10/2026) | **Enterprise SIEM / XDR Manager & Log Aggregator** (Thu thập, giải mã và cảnh báo tập trung) | **Nhận định từ tài liệu chính thức** (Chưa triển khai cụm Server) | Phụ thuộc tích hợp Sysmon và decoder; chưa có số liệu tỷ lệ | **THAM KHẢO KIẾN TRÚC (Reference Only)** – Học hỏi cấu trúc JSON Envelope & Rule ID; **Loại khỏi phạm vi cài đặt** do quá nặng (Elastic/OpenSearch). |

---

## 3. Tóm Tắt Đối Chiếu Với Endpoint Event Schema v1 & Chất Lượng Dữ Liệu

Qua quá trình đối chiếu chi tiết tại `docs/architecture/w4/tool_schema_v1_mapping_and_comparison.md` và `docs/architecture/w4/pipeline_integration_and_data_quality_notes_w4.md`, nhóm Data rút ra các kết luận kỹ thuật trọng tâm:

1. **Khả năng cung cấp 4 nhóm sự kiện & Process Correlation:**
   * **Sysmon** là công cụ duy nhất ở cấp độ collector cung cấp sẵn `ProcessGuid` và `ParentProcessGuid` xuyên suốt cả 4 nhóm sự kiện (Process, File, Registry, Network), giải quyết triệt để bài toán **PID Reuse** trên Windows theo đúng `ADR 0002`.
   * **osquery** (khi chạy ở chế độ snapshot polling mặc định trên bảng `processes`, `process_open_sockets`) chỉ ghi nhận `pid` và `parent` (PPID) tại thời điểm truy vấn, hoàn toàn không có `process_guid` gốc và dễ bỏ sót các tiến trình sống ngắn (short-lived LOLBins chạy dưới $100\text{ ms}$).
   * **Wazuh** không tự sinh telemetry cấp nhân chi tiết cho File/Registry/Network theo thời gian thực như Sysmon mà đóng vai trò nhận log từ Sysmon kênh `Microsoft-Windows-Sysmon/Operational`, sau đó bọc thêm lớp JSON lồng sâu (`data.win.system.*` và `data.win.eventdata.*`), gây dư thừa chi phí bóc tách cho một hệ thống Local EDR.
2. **Chiến lược Định danh (Deduplication), Timestamp & Bảo tồn Raw Data:**
   * Cơ chế sinh khóa `event_id` bằng hàm băm xác định $\text{UUIDv5}(\text{Computer} \mid \text{Channel} \mid \text{EventRecordID})$ (`ADR 0001`) hoạt động hoàn hảo trên dữ liệu gốc của **Sysmon**.
   * Nếu đi qua **Wazuh** hoặc **osquery**, trường `EventRecordID` nguyên bản bị đẩy xuống tầng lồng sâu hoặc bị thay bằng `counter` nội bộ của tiến trình agent, làm phức tạp hóa việc kiểm toán truy vết nguồn gốc (Data Lineage).
3. **Vai trò đặc biệt của Atomic Red Team đối với Pipeline Dữ liệu & AI:**
   * Atomic Red Team không được coi là nguồn collector production. Thay vào đó, file định nghĩa kịch bản YAML (`atomic_guid`, `attack_technique`, `executor`) và nhật ký thực thi (`execution_log.jsonl`) là nguồn **Metadata Ground-Truth** vô giá để nối (JOIN) với dữ liệu Silver theo khung thời gian (`start_time_utc`, `end_time_utc`) và lan truyền đệ quy theo cây tiến trình (`process_guid`), giúp tự động gán nhãn `is_malicious = 1` và `mitre_technique_id` (xem chi tiết tại `docs/research/data/w4/atomic_red_team_ground_truth_labeling.md`).

---

## 4. Biên Bản Rà Soát Liên Nhóm (Cross-Functional Review & Alignment)

| Bộ Phận | Đại Diện | Nội Dung Rà Soát & Đóng Góp Vào Ma Trận Chung | Kết Quả Đồng Thuận |
| :--- | :--- | :--- | :---: |
| **Cyber Team** | Detection Lead | Đồng thuận giữ **Sysmon** làm nguồn telemetry duy nhất để bảo toàn 100% logic của 10 nhóm luật phát hiện (DET-001 $\rightarrow$ DET-010). Thống nhất dùng **Atomic Red Team** để chạy kiểm thử tự động và xuất file log thời gian thực thi cho Data gắn nhãn. | **Đã ghi trong báo cáo, chờ link xác nhận reviewer** |
| **Software Team** | Collector Lead | Xác nhận loại bỏ **Wazuh, osquery, Velociraptor** khỏi kiến trúc cài đặt trên máy trạm giúp tiết kiệm hàng trăm MB RAM và giảm tải CPU ($< 3\%$). Thống nhất giữ nguyên kiến trúc Python Collector đọc trực tiếp kênh Sysmon. | **Đã ghi trong báo cáo, chờ link xác nhận reviewer** |
| **Data Team** | Data Lead | Đóng góp trọn bộ đánh giá mô hình dữ liệu, ma trận ánh xạ `Endpoint Event Schema v1` và thiết kế luồng tích hợp nhãn Atomic Red Team làm đầu vào trực tiếp cho thiết kế pipeline Tuần 5. | **Đã ghi trong báo cáo, chờ link xác nhận reviewer** |

---

## 5. Bảng Nghiệm Thu Tiêu Chí Hoàn Thành (Definition of Done Verification)

| STT | Tiêu Chí Nghiệm Thu (DoD Tuần 4) | Tài Liệu Minh Chứng Trong Repository | Đánh Giá |
| :---: | :--- | :--- | :---: |
| 1 | Cả 5 công cụ được đánh giá đúng theo vai trò, có dẫn nguồn chính thức, ngày/phiên bản khảo sát và ví dụ cấu trúc dữ liệu | `docs/research/data/w4/open_source_edr_tools_data_model_survey.md` & `docs/research/data/w4/atomic_red_team_ground_truth_labeling.md` | **Có tài liệu; cần đối chiếu bằng chứng nghiệm thu** |
| 2 | Khả năng đáp ứng các trường `Endpoint Event Schema v1` và khoảng trống dữ liệu (Data Gaps) được ghi rõ | `docs/architecture/w4/tool_schema_v1_mapping_and_comparison.md` (Mục 1 $\rightarrow$ Mục 4) | **Có tài liệu; cần đối chiếu bằng chứng nghiệm thu** |
| 3 | Các nhận định chưa thử nghiệm thực tế được phân biệt rõ ràng với kết quả đã thử nghiệm PoC | Ghi nhãn tường minh `[ĐÃ THỬ NGHIỆM THỰC TẾ]` và `[NHẬN ĐỊNH TỪ TÀI LIỆU]` xuyên suốt các báo cáo | **Có tài liệu; cần đối chiếu bằng chứng nghiệm thu** |
| 4 | Có đề xuất quyết định công cụ (Sử dụng / Tham khảo / Loại bỏ) và đầu vào cụ thể cho thiết kế pipeline Tuần 5 | `docs/decisions/0004_edr_tool_selection_and_role_allocation.md` & `docs/architecture/w4/pipeline_integration_and_data_quality_notes_w4.md` | **Có tài liệu; cần đối chiếu bằng chứng nghiệm thu** |
| 5 | Cyber và Software đã review; tài liệu được chuẩn hóa để commit và liên kết vào Issue Team | Biên bản Mục 4 báo cáo này; cấu trúc thư mục đồng bộ chuẩn Git PR | **Có tài liệu; cần đối chiếu bằng chứng nghiệm thu** |

---

## 6. Đầu Vào Bàn Giao Sang Tuần 5 (Inputs for Week 5 Pipeline Implementation)

1. **Cố định hợp đồng dữ liệu đầu vào (Bronze Ingestion Contract):** Pipeline Tuần 5 chỉ nhận duy nhất luồng JSONL từ **Sysmon Collector** (cho sự kiện hệ thống) và file nhật ký thực thi **Atomic Execution Log JSONL** (cho nhãn kiểm thử), không viết thêm parser đa nguồn cho Wazuh/osquery.
2. **Triển khai Module Chuẩn hóa Silver Layer:** Hiện thực hóa bộ quy tắc biến đổi từ `sysmon_raw_to_silver_mapping_v1.md` vào code Python + DuckDB.
3. **Tích hợp Cơ chế Enrichment & Gắn nhãn Tự động (Ground-Truth Labeling):** Xây dựng bảng `silver_atomic_test_runs` và truy vấn đệ quy `WITH RECURSIVE` trong DuckDB (theo đặc tả tại `docs/research/data/w4/atomic_red_team_ground_truth_labeling.md`) để đối chiếu tự động các sự kiện phát sinh bởi Atomic Red Team phục vụ kiểm thử Detection và trích xuất vector đặc trưng tầng Gold.
