# ADR 0004: Quyết Định Lựa Chọn Công Cụ Thu Thập, Sinh Nhãn Và Tham Khảo Kiến Trúc (Góc Nhìn Dữ Liệu)

* **Trạng thái:** ACCEPTED
* **Người đề xuất:** Huỳnh Hữu Nhật (Data Engineer)
* **Ngày quyết định:** 24/10/2026 (Tuần 4)
* **Các bên tham gia đồng thuận:** Cyber Security Team, Software Team, Data Engineering Team
* **Phụ thuộc:** `ADR 0001` (Deterministic UUIDv5), `ADR 0002` (Process Correlation via GUID), `ADR 0003` (Raw Data Preservation), `Endpoint Event Schema v1` (`#15`)

---

## 1. Ngữ Cảnh Kỹ Thuật (Context)

Trong Tuần 4 của kế hoạch 12 tuần phát triển Hệ thống Giám sát & Phát hiện Xâm nhập Điểm cuối Cục bộ (Local EDR), toàn nhóm cần đưa ra quyết định kiến trúc cuối cùng về việc lựa chọn hoặc loại bỏ 5 công cụ mã nguồn mở phổ biến: **Microsoft Sysmon, Wazuh, osquery, Velociraptor và Atomic Red Team**.

Dưới góc nhìn của nhóm Kỹ thuật Dữ liệu (Data Engineering), công cụ được lựa chọn đưa vào pipeline thực thi bắt buộc phải thỏa mãn 4 ràng buộc cứng sau đây:
1. **Đáp ứng `Endpoint Event Schema v1`:** Cung cấp đầy đủ 4 nhóm sự kiện (Process, File, Registry, Network) theo thời gian thực với độ phân giải thời gian sub-second.
2. **Tuân thủ `ADR 0001` & `ADR 0002`:** Cung cấp khóa tự nhiên tuần tự để sinh `event_id` xác định (`UUIDv5`) và cung cấp mã định danh `process_guid` xuyên suốt mọi loại sự kiện nhằm chống lại hiện tượng tái sử dụng PID (PID Reuse) trên Windows.
3. **Giới hạn tài nguyên máy trạm (Local EDR Footprint):** Toàn bộ quá trình thu thập và lưu trữ cục bộ phải chiếm dưới $3\%$ CPU và dưới $150\text{ MB}$ RAM, không phụ thuộc vào cụm máy chủ tập trung nặng nề (như Elasticsearch/OpenSearch).
4. **Hỗ trợ kiểm thử và huấn luyện AI có nhãn:** Có cơ chế sinh dữ liệu tấn công thực tế kèm metadata Ground-Truth (`mitre_technique_id`) để đánh giá độ chính xác của luật phát hiện và mô hình học máy.

---

## 2. Phân Tích Các Công Cụ Khảo Sát (Evaluation Summary)

1. **Microsoft Sysmon (v15.15):**
   * *Đánh giá:* Hoạt động ở cấp Kernel Minifilter + ETW, cung cấp `ProcessGuid`, `ParentProcessGuid` và `EventRecordID` trên cả 4 nhóm sự kiện với chi phí tài nguyên cực thấp. Đã được kiểm chứng thực nghiệm thành công 100% trong PoC Tuần 2 và Tuần 3.
2. **Atomic Red Team (`Invoke-AtomicRedTeam` v2.2+):**
   * *Đánh giá:* Không phải là công cụ thu thập (Collector), mà là framework mô phỏng hành vi kẻ tấn công theo chuẩn MITRE ATT&CK. Cung cấp metadata kịch bản (`auto_generated_guid`, `attack_technique`) và nhật ký thực thi (`runner_pid`, `start_time_utc`, `end_time_utc`) lý tưởng để làm nguồn gắn nhãn Ground-Truth.
3. **Wazuh (v4.9.x):**
   * *Đánh giá:* Là nền tảng SIEM/XDR tập trung. Bản thân Wazuh Agent trên Windows vẫn phải đọc lại kênh log của Sysmon để có telemetry tiến trình/mạng chi tiết, đồng thời bọc dữ liệu vào JSON lồng sâu và yêu cầu cụm Wazuh Server + OpenSearch tiêu tốn nhiều GB RAM.
4. **osquery (v5.13.x):**
   * *Đánh giá:* Là công cụ truy vấn trạng thái hệ điều hành bằng SQL theo chu kỳ (polling/snapshot). Thiếu trường `process_guid`, chỉ có độ phân giải thời gian tính bằng giây (`unixTime`), không gắn được sự kiện tạo file/registry với tiến trình thực hiện và dễ bỏ lọt các tiến trình độc hại chạy nhanh (short-lived processes).
5. **Velociraptor (v0.72.x):**
   * *Đánh giá:* Rất mạnh cho điều tra số (DFIR) và săn tìm mối đe dọa theo yêu cầu bằng ngôn ngữ VQL. Tuy nhiên, việc duy trì thêm một Velociraptor Client/Server song song với Python Collector + DuckDB gây chồng chéo chức năng truy vấn và dư thừa tài nguyên.

---

## 3. Quyết Định Kiến Trúc (Decision)

Nhóm chính thức thống nhất phân bổ vai trò cho 5 công cụ như sau:

| Công Cụ | Quyết Định | Vai Trò Cụ Thể Trong Dự Án Local EDR |
| :--- | :---: | :--- |
| **1. Microsoft Sysmon** | **SỬ DỤNG CHÍNH THỨC (Adopt – Primary Collector)** | Nguồn thu thập sự kiện điểm cuối thời gian thực duy nhất ở môi trường vận hành; cấp dữ liệu trực tiếp cho tầng Bronze JSONL và Silver DuckDB. |
| **2. Atomic Red Team** | **SỬ DỤNG CHÍNH THỨC (Adopt – Labeling & Test Source)** | Công cụ mô phỏng tấn công trong môi trường Lab/PoC để sinh bộ dữ liệu thực nghiệm và cung cấp metadata gắn nhãn (`silver_atomic_test_runs`) cho Detection & AI. **Không cài đặt làm collector trên máy trạm production.** |
| **3. Velociraptor** | **THAM KHẢO & LOẠI KHỎI PHẠM VI CÀI ĐẶT (Reference Only)** | Không cài đặt phần mềm. **Tái sử dụng ý tưởng `ProcessTracker`** để thiết kế các SQL Enriched Views nối ngữ cảnh tiến trình trong DuckDB. |
| **4. osquery** | **THAM KHẢO & LOẠI KHỎI PHẠM VI CÀI ĐẶT (Reference Only)** | Không cài đặt phần mềm. **Tái sử dụng tư duy truy vấn SQL trên dữ liệu điểm cuối** thông qua engine DuckDB tại tầng Silver/Gold. |
| **5. Wazuh** | **THAM KHẢO & LOẠI KHỎI PHẠM VI CÀI ĐẶT (Reference Only)** | Không cài đặt phần mềm. **Tái sử dụng ý tưởng trích xuất nhãn kỹ thuật từ trường `RuleName`** và cấu trúc phân loại cảnh báo MITRE. |

---

## 4. Hệ Quả & Đánh Giá Tác Động (Consequences)

### Tích cực (Positive)
* **Bảo toàn 100% thiết kế Tuần 3:** Không phải thay đổi bất kỳ trường nào trong `Endpoint Event Schema v1` hay viết lại logic chuẩn hóa `UUIDv5` và `process_guid`.
* **Pipeline Tuần 5 đơn giản, tốc độ cao:** Nhóm Data chỉ cần tập trung xây dựng một luồng ETL vững chắc từ Sysmon JSONL sang DuckDB Silver/Gold mà không bị phân tán nguồn lực vào việc duy trì nhiều bộ parser phức tạp.
* **Giải quyết bài toán thiếu dữ liệu có nhãn cho AI:** Sự kết hợp giữa **Sysmon (Telemetry)** và **Atomic Red Team (Ground-Truth Metadata)** tạo ra bộ dữ liệu có nhãn chất lượng cao, truy vết chính xác theo cây tiến trình.

### Ràng buộc & Biện pháp giảm thiểu (Constraints & Mitigations)
* Việc chỉ dùng Sysmon đòi hỏi tệp cấu hình `sysmon-config.xml` của Software/Cyber Team phải được thiết lập đầy đủ các luật lọc cho Event ID `1, 3, 5, 11, 12, 13, 14, 22, 23` (đã được kiểm chứng và khóa cấu hình ở Tuần 2–3).