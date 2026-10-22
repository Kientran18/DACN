# Ghi Chú Kiến Trúc Tuần 4: Tích Hợp Pipeline, Đánh Giá Chất Lượng Dữ Liệu & Các Ý Tưởng Tái Sử Dụng

**Dự án:** Hệ thống Giám sát & Phát hiện Xâm nhập Điểm cuối Cục bộ (Local EDR)  
**Người thực hiện:** Huỳnh Hữu Nhật (Data Engineer)  
**Thời điểm:** Tuần 4 (10/2026)  
**Mục tiêu:** Đánh giá khả năng tích hợp dữ liệu vào pipeline dự kiến ở Tuần 5, phân tích chất lượng dữ liệu/lineage của các công cụ và trích lọc các ý tưởng thiết kế xuất sắc từ Wazuh, osquery, Velociraptor, Atomic Red Team để nâng cấp kiến trúc Local EDR.

---

## 1. Đánh Giá Chất Lượng Dữ Liệu, Deduplication & Lineage Theo Từng Công Cụ

Dựa trên các nguyên tắc kiến trúc đã chốt ở Tuần 3 (`ADR 0001`, `ADR 0002`, `ADR 0003`), bảng dưới đây đánh giá chất lượng dữ liệu nội tại của 5 công cụ:

| Khía Cạnh Kỹ Thuật Dữ Liệu | Microsoft Sysmon `[TESTED POC]` | Wazuh `[DOCS ASSESSMENT]` | osquery `[DOCS ASSESSMENT]` | Velociraptor `[DOCS ASSESSMENT]` | Atomic Red Team `[TESTED/DOCS]` |
| :--- | :--- | :--- | :--- | :--- | :--- |
| **1. Bảo tồn dữ liệu thô (Raw Data Preservation)** | **Xuất sắc:** Giữ nguyên 100% dictionary `EventData` gốc trong cột `raw_data` mà không bị biến đổi kiểu. | **Tốt nhưng cồng kềnh:** Có tùy chọn `full_log` nhưng mặc định bọc qua nhiều lớp JSON và ép mọi giá trị thành kiểu `string`. | **Trung bình:** Chỉ xuất các cột được liệt kê trong câu lệnh `SELECT` của query; các trường OS không được `SELECT` sẽ mất vĩnh viễn. | **Tốt:** Phụ thuộc vào câu lệnh VQL; có thể giữ nguyên đối tượng `EventData` nếu `SELECT *`. | Lưu đầy đủ thông số đầu vào và lệnh thực thi trong nhật ký `execution_log`. |
| **2. Định danh & Chống trùng lặp (Deduplication)** | **Chuẩn xác 100%:** Có khóa tự nhiên `(Computer, Channel, EventRecordID)` tăng đơn điệu, tương thích hoàn hảo với `UUIDv5`. | **Phức tạp:** Có `id` riêng của Wazuh Manager (`timestamp.counter`), nhưng nếu nạp lại log từ Agent sẽ sinh `id` mới trên Manager. | **Rủi ro cao:** Dùng `(hostIdentifier, name, unixTime, counter)`, trong đó `counter` bị reset về `0` mỗi khi khởi động lại dịch vụ `osqueryd`. | **Tốt:** Mỗi luồng thu thập có `ClientId` và `FlowId` riêng biệt kết hợp với `EventRecordID` nếu đọc từ EVTX. | Định danh kịch bản tĩnh qua `auto_generated_guid` và lần chạy qua `execution_id`. |
| **3. Chất lượng thời gian & Thứ tự nhân quả (Temporal Quality)** | **Rất cao:** Độ phân giải $100\text{ ns}$ (`SystemTime` UTC), bảo toàn đúng thứ tự trước-sau của chuỗi hành vi tạo Process $\rightarrow$ tạo File $\rightarrow$ xóa File. | **Cao:** Giữ được `systemTime` gốc của Windows nếu lấy đúng đường dẫn `data.win.system.systemTime`. | **Kém cho EDR Real-time:** `unixTime` tính bằng **giây (seconds)**; 20 sự kiện diễn ra trong $500\text{ ms}$ sẽ có cùng một mốc thời gian! | **Rất cao:** Hỗ trợ timestamp độ phân giải cao từ ETW/EVTX và NTFS `$MFT` (`SI` / `FN` timestamps). | **Cao:** Ghi nhận mốc bắt đầu và kết thúc bài test ở độ phân giải mili-giây UTC. |
| **4. Truy vết nguồn gốc & Phả hệ (Data Lineage)** | **Trực tiếp (Zero-hop):** Đọc thẳng từ Kernel $\rightarrow$ Windows EventChannel $\rightarrow$ Python Collector, kèm `RuleName` của `sysmon-config.xml`. | **Gián tiếp (Multi-hop):** Kernel $\rightarrow$ EventChannel $\rightarrow$ Wazuh Agent $\rightarrow$ Queue $\rightarrow$ Wazuh Analysisd $\rightarrow$ File JSON. | **Mất ngữ cảnh nhân quả:** Chỉ thấy trạng thái bảng tại thời điểm poll, không biết sự kiện trung gian. | **Truy vết Forensics mạnh:** Biết rõ dữ liệu đến từ Artifact VQL nào và cho phép làm giàu ngữ cảnh ngay trên Client. | Cung cấp siêu dữ liệu gốc: `attack_technique` $\rightarrow$ `atomic_guid` $\rightarrow$ `runner_pid`. |

---

## 2. Đánh Giá Khả Năng Đưa Đầu Ra Vào Pipeline Dự Kiến (Tuần 5) & Phục Vụ Feature / Detection / AI

### 2.1. Khả năng đáp ứng cho Cyber Detection Rules (DET-001 $\rightarrow$ DET-010)
* **Với nguồn Sysmon:** Đáp ứng **100%** yêu cầu trường dữ liệu cho cả 10 nhóm luật phát hiện đã thống nhất với Cyber Team ở Tuần 2 và Tuần 3 (từ phát hiện LOLBins qua `image_path` + `command_line`, Office spawn Shell qua `parent_image`, Persistence qua `target_object` Registry, cho tới C2 Beaconing qua `dest_ip` + `dns_query_name`).
* **Nếu thay bằng osquery hoặc Wazuh FIM:** Sẽ làm **vỡ ít nhất 6/10 nhóm luật phát hiện** do thiếu `process_guid` xuyên suốt giữa Process – File – Registry – Network và độ trễ/bỏ lọt sự kiện của cơ chế polling.

### 2.2. Khả năng phục vụ AI Feature Engineering (Gold Layer)
Ở tầng Gold, mô hình phát hiện bất thường (Anomaly Detection / Autoencoder / Isolation Forest) cần trích xuất 3 nhóm đặc trưng chính từ tầng Silver:
1. **Đặc trưng Cấu trúc Đồ thị Tiến trình (Process Tree DAG Features):** Độ sâu cây tiến trình (`tree_depth`), số lượng tiến trình con sinh ra trong $10\text{ giây}$ (`child_process_count_10s`).
   * *Yêu cầu dữ liệu:* Bắt buộc phải có cặp khóa `(process_guid, parent_guid)` không bị vòng lặp PID Reuse. $\rightarrow$ **Chỉ Sysmon đáp ứng trực tiếp.**
2. **Đặc trưng Tần suất Cửa sổ Trượt (Sliding Window Behavioral Counters):** Tốc độ ghi/xóa file trong $5\text{ giây}$ của cùng một tiến trình (`file_write_rate_5s` để bắt Ransomware), số lượng khóa Registry bị sửa đổi (`reg_mod_count_10s`), số cổng đích duy nhất kết nối (`unique_dest_ports_30s`).
   * *Yêu cầu dữ liệu:* Cần timestamp độ chính xác mili-giây và khóa ngoại `process_guid` trên bảng File, Registry, Network. $\rightarrow$ **Sysmon đáp ứng 100%; osquery thất bại do độ phân giải giây và thiếu khóa liên kết.**
3. **Đặc trưng Ngôn ngữ & Độ hỗn loạn Dòng lệnh (Command-line Lexical & Entropy Features):** Độ dài chuỗi lệnh (`cmd_length`), điểm số **Shannon Entropy**:
   $$H(X) = -\sum_{i=1}^{n} P(x_i) \log_2 P(x_i)$$
   tỷ lệ ký tự Base64/Obfuscation.
   * *Yêu cầu dữ liệu:* Chuỗi `command_line` nguyên bản không bị cắt cụt. $\rightarrow$ **Sysmon đáp ứng hoàn hảo.**

---

## 3. Các Ý Tưởng Thiết Kế Xuất Sắc Có Thể Tái Sử Dụng Cho Pipeline (Reusable Design Patterns)

Mặc dù nhóm quyết định **không cài đặt Wazuh, osquery và Velociraptor** vào sản phẩm Local EDR để giữ hệ thống tinh gọn, quá trình nghiên cứu mô hình dữ liệu của 4 công cụ ngoài Sysmon mang lại **4 ý tưởng thiết kế đắt giá** có thể áp dụng ngay vào kiến trúc Pipeline Tuần 5:

```text
+---------------------------------------------------------------------------------------------------+
|                   4 Ý TƯỞNG TÁI SỬ DỤNG TỪ CÁC CÔNG CỤ MÃ NGUỒN MỞ CHO PIPELINE                   |
|                                                                                                   |
|  1. Từ Sysmon Config + Wazuh Rule  --->  Trích xuất "RuleName" (technique_id, technique_name)     |
|                                          làm Pre-tagging Hints ngay tại tầng Silver.              |
|                                                                                                   |
|  2. Từ Velociraptor ProcessTracker --->  Dựng bảng bộ nhớ đệm `silver_process_context_cache`      |
|                                          trong DuckDB để tra cứu nhanh tổ tiên tiến trình.        |
|                                                                                                   |
|  3. Từ osquery SQL Virtual Tables  --->  Thiết kế các SQL Views chuẩn hóa trên DuckDB             |
|                                          (`v_enriched_file_events`, `v_enriched_network_events`). |
|                                                                                                   |
|  4. Từ Atomic Red Team YAML/Log    --->  Pipeline tự động nối Ground-Truth (`silver_atomic_runs`) |
|                                          để chấm điểm Precision/Recall cho Detection & AI.        |
+---------------------------------------------------------------------------------------------------+
```

### 3.1. Ý tưởng 1 (Từ Sysmon + Wazuh): Tận dụng trường `RuleName` của Sysmon làm Pre-tagging Metadata
* **Quan sát:** Trong cấu hình `sysmon-config.xml` (như bộ mẫu SwiftOnSecurity / Modular Sysmon), trường `EventData.RuleName` thường chứa chuỗi định danh kỹ thuật MITRE, ví dụ: `"technique_id=T1059.001,technique_name=PowerShell"`. Wazuh tận dụng rất tốt trường này trong các decoder của mình.
* **Áp dụng vào Pipeline Tuần 5:** Dù cột này hiện nằm trong `raw_data`, ở bước ETL sang Silver hoặc qua SQL View trên DuckDB, ta có thể viết hàm trích xuất nhẹ từ `raw_data->>'$.RuleName'` để lấy gợi ý kỹ thuật ban đầu (`sysmon_rule_hint`), hỗ trợ đắc lực cho Cyber Team khi đối chiếu chéo với Detection Engine.

### 3.2. Ý tưởng 2 (Từ Velociraptor): Cơ chế `ProcessTracker` làm giàu ngữ cảnh cho File/Registry/Network
* **Quan sát:** Trong Sysmon, các sự kiện File (ID 11), Registry (ID 13) và Network (ID 3) chỉ chứa `ProcessGuid` và `Image` của tiến trình hiện tại, **không chứa `CommandLine` hay `ParentImage`**. Velociraptor giải quyết việc này bằng một bộ nhớ đệm `ProcessTracker` để mỗi khi có sự kiện phụ xảy ra, nó lập tức gắn kèm thông tin tiến trình cha và dòng lệnh gốc.
* **Áp dụng vào Pipeline Tuần 5:** Trong DuckDB Silver Layer, chúng ta thiết kế sẵn các **Enriched SQL Views** (ví dụ `v_silver_file_enriched`, `v_silver_network_enriched`) thực hiện `LEFT JOIN` với `silver_process_events` thông qua `process_guid`. Nhờ đó, cả Cyber Rule Engine và AI Feature Extractor đều có ngay `command_line`, `parent_image`, `user_name` và `integrity_level` trên mọi sự kiện File/Registry/Network mà không làm phình dung lượng lưu trữ vật lý!

### 3.3. Ý tưởng 3 (Từ osquery): Trừu tượng hóa truy vấn bằng giao diện SQL thống nhất
* **Quan sát:** Sức mạnh lớn nhất của osquery là cho phép chuyên viên an ninh viết câu lệnh SQL chuẩn để hỏi thông tin thay vì phải học cú pháp riêng.
* **Áp dụng vào Pipeline Tuần 5:** Sử dụng **DuckDB** làm động cơ lưu trữ và truy vấn tại tầng Silver/Gold giúp Local EDR của nhóm đạt được đúng trải nghiệm SQL mạnh mẽ như osquery, nhưng vượt trội hơn ở chỗ truy vấn trên **luồng dữ liệu lịch sử hướng sự kiện (Event-driven Historical Stream)** thay vì chỉ truy vấn trạng thái tức thời.

### 3.4. Ý tưởng 4 (Từ Atomic Red Team): Chuẩn hóa Pipeline Kiểm thử & Gắn nhãn Tự động (Automated Labeling Loop)
* **Áp dụng vào Pipeline Tuần 5:** Xây dựng quy trình khép kín khi chạy kiểm thử:
  $$\text{Invoke-AtomicTest} \longrightarrow \text{Sysmon Bronze JSONL} + \text{Atomic Execution Log} \longrightarrow \text{DuckDB Silver Join} \longrightarrow \text{Labeled Gold Features}$$
  Quy trình này giúp nhóm tự động hóa hoàn toàn việc tạo tập dữ liệu có nhãn (`Ground-Truth Dataset`) để đo lường tỷ lệ phát hiện đúng (True Positive Rate) và báo động giả (False Positive Rate) ở các tuần tiếp theo.

---

## 4. Kiến Trúc Luồng Dữ Liệu Đầu Vào Bàn Giao Cho Tuần 5 (Week 5 Pipeline Preview)

Sơ đồ dưới đây tổng hợp toàn bộ thiết kế đầu vào bàn giao cho giai đoạn hiện thực hóa Pipeline ở Tuần 5:

```text
+----------------------------------------------------------------------------------------------------+
|                      KIẾN TRÚC PIPELINE DỮ LIỆU ĐẦU VÀO TUẦN 5 (DATA BLUEPRINT)                    |
|                                                                                                    |
|  [NGUỒN THU THẬP PRODUCTION]                         [NGUỒN KÍCH HOẠT & GẮN NHÃN LAB/POC]          |
|   Microsoft Sysmon v15.15                             Atomic Red Team (Invoke-AtomicTest)          |
|   (Kênh Operational EVTX)                             (Kịch bản Txxxx.yaml + Runner PID)           |
|              |                                                        |                            |
|              v (Python Collector)                                     v (Execution Logger)         |
|  +-----------------------------------+               +------------------------------------------+  |
|  | TẦNG BRONZE (Append-Only JSONL)   |               | TẦNG BRONZE LAB (Execution Log JSONL)    |  |
|  | - data/bronze/sysmon_raw.jsonl    |               | - data/bronze/atomic_runs.jsonl          |  |
|  | - data/bronze/validation_err.jsonl|               +------------------------------------------+  |
|  +-----------------------------------+                                |                            |
|              |                                                        |                            |
|              v (Pydantic Validation + Deterministic UUIDv5 + Strip GUID + Registry Inference)      |
|  +----------------------------------------------------------------------------------------------+  |
|  | TẦNG SILVER (DuckDB OLAP: endpoint_silver.duckdb)                                            |  |
|  | - 4 Bảng Chuẩn Hóa Schema v1:                                                                |  |
|  |   + silver_process_events (ID 1, 5)          + silver_file_events (ID 11, 23, 26)            |  |
|  |   + silver_registry_events (ID 12, 13, 14)   + silver_network_events (ID 3, 22)              |  |
|  | - 1 Bảng Nhãn Thực Nghiệm:                   - Các Enriched SQL Views (Học từ Velociraptor): |  |
|  |   + silver_atomic_test_runs                    + v_process_tree_lineage, v_enriched_events   |  |
|  +----------------------------------------------------------------------------------------------+  |
|              |                                                                                     |
|              v (Recursive Process Lineage Join + Sliding Window Aggregations + Shannon Entropy)    |
|  +----------------------------------------------------------------------------------------------+  |
|  | TẦNG GOLD (Feature Store & Detection Input)                                                  |  |
|  | - Vector đặc trưng hành vi theo `process_guid` kèm nhãn `mitre_technique_id` (nếu có)        |  |
|  +----------------------------------------------------------------------------------------------+  |
+----------------------------------------------------------------------------------------------------+
```