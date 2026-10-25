# DACN — Windows Endpoint Security

**Đề tài:** Tìm hiểu và hiện thực một hệ thống bảo mật cho thiết bị đầu cuối (Endpoint Security)

**Trạng thái dự án:** Đang thực hiện Giai đoạn 1 — Đồ án chuyên ngành  
**Nền tảng mục tiêu:** Microsoft Windows 10/11  
**Định hướng:** Endpoint Protection Platform (EPP) & Endpoint Detection and Response (EDR)

---

## 1. Giới thiệu dự án

**DACN — Windows Endpoint Security** là dự án nghiên cứu, thiết kế và phát triển một hệ thống bảo mật dành cho thiết bị đầu cuối chạy hệ điều hành Microsoft Windows.

Các giải pháp bảo mật truyền thống thường tập trung vào việc phát hiện mã độc thông qua chữ ký hoặc mẫu nhận diện đã biết. Tuy nhiên, nhiều cuộc tấn công hiện đại có thể sử dụng công cụ hợp pháp của hệ điều hành, kỹ thuật thực thi script, cơ chế duy trì quyền truy cập và các hành vi bất thường để tránh bị phát hiện.

Dự án hướng đến việc kết hợp các cơ chế bảo mật thuộc EPP và EDR, bao gồm:

- Giám sát hoạt động của tiến trình, tệp tin, Registry và kết nối mạng.
- Thu thập, chuẩn hóa và lưu trữ dữ liệu sự kiện bảo mật.
- Phát hiện dấu hiệu nguy hiểm bằng chữ ký, luật phát hiện và phân tích hành vi.
- Nghiên cứu ứng dụng AI/ML để hỗ trợ phát hiện bất thường và đánh giá mức độ rủi ro.
- Cung cấp cảnh báo, thông tin điều tra và khả năng phản ứng cơ bản đối với các mối đe dọa.

**Mục tiêu cuối cùng** là phát triển một ứng dụng Endpoint Security có thể cài đặt và vận hành trên máy tính Windows, cung cấp các chức năng bảo vệ, giám sát, phát hiện và xử lý mối đe dọa ở mức cơ bản.

Dự án được triển khai theo hai giai đoạn: nghiên cứu và thiết kế trong Đồ án chuyên ngành, sau đó hiện thực và thử nghiệm hệ thống trong Luận văn tốt nghiệp.

## 2. Mục tiêu

### 2.1. Mục tiêu tổng quát

Nghiên cứu và xây dựng một hệ thống bảo mật endpoint theo hướng module hóa, có khả năng giám sát các hoạt động quan trọng trên Windows, phát hiện hành vi đáng ngờ và hỗ trợ người dùng điều tra, phản ứng với các sự kiện bảo mật.

### 2.2. Mục tiêu cụ thể

1. Tìm hiểu kiến trúc và cơ chế hoạt động của EPP, EDR và các phương pháp phát hiện mã độc.
2. Nghiên cứu các kỹ thuật tấn công trên Windows dựa trên MITRE ATT&CK.
3. Tìm hiểu cơ chế thu thập dữ liệu từ Windows Event Log, Sysmon và các nguồn telemetry liên quan.
4. Thiết kế Data Pipeline xử lý dữ liệu từ sự kiện thô đến dữ liệu chuẩn hóa và cảnh báo.
5. Xây dựng mô hình phát hiện dựa trên rule, signature, whitelist và phân tích hành vi.
6. Nghiên cứu AI/ML phục vụ anomaly detection và risk scoring.
7. Thiết kế giao diện giám sát, quản lý cảnh báo, điều tra sự kiện và phản ứng cơ bản.
8. Tiến tới tích hợp các thành phần thành một ứng dụng có thể chạy và sử dụng thực tế.

## 3. Các chức năng dự kiến của hệ thống hoàn chỉnh

Đây là các chức năng **hướng tới ở Giai đoạn 2**, không phải danh sách những tính năng đã được triển khai đầy đủ.

| Nhóm chức năng | Mô tả |
|---|---|
| Endpoint Monitoring | Theo dõi hoạt động của tiến trình, tệp tin, Registry và kết nối mạng trên Windows |
| Data Collection | Thu thập các sự kiện hệ thống từ Sysmon, Windows Event Log và các nguồn phù hợp |
| Data Processing | Chuẩn hóa, kiểm định, lưu trữ và truy vấn dữ liệu bảo mật |
| Signature & Whitelist | Kiểm tra hash, danh sách tin cậy và các mẫu nhận diện mối đe dọa |
| Rule-based Detection | Phát hiện các hành vi đáng ngờ thông qua tập luật bảo mật |
| Behavioral Detection | Phân tích chuỗi sự kiện và mối quan hệ giữa các tiến trình |
| AI-assisted Detection | Hỗ trợ đánh giá bất thường và tính điểm rủi ro khi có dữ liệu, mô hình phù hợp |
| Alert Management | Sinh, lưu trữ và hiển thị cảnh báo theo mức độ nghiêm trọng |
| Investigation | Xem process tree, incident timeline và bằng chứng liên quan đến cảnh báo |
| Threat Hunting | Tìm kiếm và lọc sự kiện theo tiến trình, thời gian, hash, rule và mức độ rủi ro |
| Basic Response | Hỗ trợ kết thúc tiến trình, cách ly tệp tin, chặn hash và cập nhật whitelist theo cơ chế an toàn |
| Dashboard | Giao diện tổng quan trạng thái giám sát, sự kiện và cảnh báo |

Phạm vi tính năng, mức độ tự động hóa và cơ chế phản ứng sẽ được chốt trong quá trình thiết kế, hiện thực và kiểm thử.

## 4. Kiến trúc hệ thống dự kiến

Hệ thống được định hướng xây dựng theo kiến trúc module, cho phép phát triển, kiểm thử, thay thế và mở rộng từng thành phần độc lập.

**Luồng xử lý tổng quát:**

**Windows Endpoint → Event Collector → Raw/Bronze Storage → Validation & Normalization → Silver Storage → Detection & AI → Alert → Investigation / Response → Dashboard**

Các thành phần chính:

| Module | Trách nhiệm |
|---|---|
| Endpoint Agent / Collector | Thu thập dữ liệu hoạt động từ máy Windows |
| Data Pipeline | Kiểm định, chuẩn hóa, loại trùng và xử lý dữ liệu |
| Local Storage | Lưu trữ sự kiện thô, dữ liệu chuẩn hóa và dữ liệu phục vụ phân tích |
| Detection Engine | Thực thi signature/rule và phát hiện hành vi đáng ngờ |
| AI / Risk Scoring | Phân tích đặc trưng, hỗ trợ phát hiện bất thường và đánh giá rủi ro |
| Alert & Incident Manager | Tổng hợp cảnh báo, quản lý mức độ nghiêm trọng và bằng chứng |
| Investigation & Hunting | Truy vấn và tái dựng bối cảnh sự kiện bảo mật |
| Response Manager | Thực thi các thao tác phản ứng có kiểm soát |
| Dashboard / User Interface | Cung cấp giao diện sử dụng và quản lý hệ thống |

**Nguyên tắc thiết kế:** Ưu tiên hệ thống cục bộ trên Windows, dễ triển khai, có thể mở rộng và không phụ thuộc vào hạ tầng SIEM tập trung trong phiên bản đầu tiên.

## 5. Lộ trình phát triển

Dự án được chia thành hai giai đoạn.

### Giai đoạn 1 — Đồ án chuyên ngành

**Trạng thái: Đang thực hiện**

**Thời gian dự kiến:** 12 tuần.

Trọng tâm là nghiên cứu các công nghệ bảo mật endpoint, đánh giá công cụ mã nguồn mở, xác minh telemetry trên Windows, thiết kế các module và xây dựng kiến trúc tổng thể.

| Thời gian | Nội dung trọng tâm | Kết quả dự kiến |
|---|---|---|
| Tuần 1–4 | Nghiên cứu EPP/EDR, MITRE ATT&CK, Threat Model, Windows telemetry và công cụ mã nguồn mở | Nền tảng nghiên cứu, dữ liệu mẫu, collector PoC, báo cáo đánh giá công cụ |
| Tuần 5–8 | Thiết kế Data Pipeline, Detection Engine, Static Analysis, Whitelist, Signature và AI | Kiến trúc xử lý dữ liệu, mô hình phát hiện, danh sách rule và thiết kế AI |
| Tuần 9–10 | Thiết kế EDR Investigation, Threat Hunting, Response và kịch bản kiểm thử | Thiết kế điều tra/phản ứng, test scenarios và dashboard wireframe |
| Tuần 11–12 | Tích hợp thiết kế kiến trúc, rà soát yêu cầu và hoàn thiện tài liệu | Architecture Final Package, báo cáo, slide và backlog Giai đoạn 2 |

**Sản phẩm trọng tâm của Giai đoạn 1:**

- Tài liệu nghiên cứu EPP/EDR và các kỹ thuật tấn công.
- Threat Model và MITRE ATT&CK Detection Matrix.
- Windows Telemetry Catalogue và dữ liệu sự kiện thực nghiệm.
- Endpoint Event Schema và Raw-to-Normalized Mapping.
- Báo cáo đánh giá Sysmon, Wazuh, osquery, Velociraptor và Atomic Red Team.
- Thiết kế Data Pipeline, Detection Engine, Static Analysis và AI.
- Thiết kế Investigation, Threat Hunting, Response và Dashboard.
- Kiến trúc hệ thống tổng thể và kế hoạch hiện thực cho Giai đoạn 2.

Các PoC được thực hiện trong giai đoạn này nhằm kiểm chứng tính khả thi của thiết kế, chưa phải ứng dụng bảo mật hoàn chỉnh.

### Giai đoạn 2 — Luận văn tốt nghiệp

**Trạng thái: Chưa bắt đầu**

Giai đoạn này tập trung vào việc hiện thực, tích hợp và triển khai thử nghiệm kiến trúc đã xây dựng ở Giai đoạn 1.

Các mục tiêu dự kiến:

1. Hoàn thiện Endpoint Agent / Event Collector.
2. Triển khai Data Pipeline và hệ thống lưu trữ dữ liệu.
3. Xây dựng Detection Engine với các luật phát hiện cơ bản.
4. Tích hợp signature, whitelist và các chức năng phân tích tĩnh phù hợp.
5. Nghiên cứu và tích hợp AI/ML khi đáp ứng yêu cầu dữ liệu và kiểm thử.
6. Phát triển dashboard quản lý sự kiện, cảnh báo và điều tra.
7. Triển khai các chức năng response an toàn.
8. Tích hợp các module thành một ứng dụng có thể cài đặt và vận hành trên Windows.
9. Kiểm thử, đánh giá hiệu năng, độ chính xác phát hiện và khả năng sử dụng thực tế.

**Kết quả hướng tới:** Một ứng dụng Endpoint Security hoạt động được, có các chức năng cơ bản của EPP/EDR, phù hợp với phạm vi và nguồn lực của đồ án. Đây không phải mục tiêu thay thế toàn bộ các sản phẩm EDR thương mại.

## 6. Công nghệ và công cụ nghiên cứu

| Công nghệ / Công cụ | Vai trò trong dự án |
|---|---|
| Python | Xây dựng collector PoC, xử lý dữ liệu, detection và các thành phần hỗ trợ |
| Microsoft Sysmon | Cung cấp dữ liệu sự kiện bảo mật trên Windows |
| Windows Event Log | Nguồn truy xuất sự kiện hệ thống |
| Pydantic | Định hướng kiểm định và chuẩn hóa schema |
| DuckDB | Định hướng lưu trữ và truy vấn dữ liệu cục bộ |
| JSON / JSONL / Parquet | Biểu diễn và lưu trữ dữ liệu ở các tầng xử lý |
| MITRE ATT&CK | Phân loại kỹ thuật tấn công và hỗ trợ xây dựng rule |
| Atomic Red Team | Nghiên cứu kịch bản mô phỏng tấn công trong môi trường lab |
| Wazuh | Tham khảo kiến trúc rule engine, alert và response |
| osquery | Tham khảo phương pháp truy vấn dữ liệu hệ điều hành |
| Velociraptor | Tham khảo threat hunting, investigation và digital forensics |
| Git & GitHub | Quản lý mã nguồn, issue, pull request và tiến độ dự án |

Danh sách trên gồm cả công nghệ đã sử dụng trong PoC lẫn công nghệ đang được nghiên cứu hoặc dự kiến tích hợp. Không phải tất cả đều được triển khai vào ứng dụng cuối cùng.

## 7. Trạng thái hiện tại

Dự án đang ở **Giai đoạn 1 — Nghiên cứu và thiết kế**.

Các nội dung đã có trong repository bao gồm:

- Tài liệu khảo sát EPP/EDR và mô hình bảo mật endpoint.
- Danh sách 13 kỹ thuật MITRE ATT&CK được lựa chọn.
- Threat Model và các tài liệu Behavior-to-Telemetry Mapping.
- Mẫu XML/JSON Sysmon cho Process, File, Registry và Network.
- Minimal Sysmon Collector PoC phục vụ phân tích sự kiện.
- Tài liệu Endpoint Event Schema và các quy tắc chuẩn hóa dữ liệu.
- Các tài liệu thiết kế Data Pipeline và kiểm tra dữ liệu.
- Báo cáo nghiên cứu, đánh giá năm công cụ mã nguồn mở ở tuần 4.

**Những chức năng chưa được xem là hoàn chỉnh:** detection engine chạy liên tục, AI detection, hệ thống cảnh báo/incident tích hợp, response tự động và dashboard của sản phẩm cuối cùng.

Tiến độ chi tiết được quản lý tại [GitHub Issues](https://github.com/Kientran18/DACN/issues) và [Pull Requests](https://github.com/Kientran18/DACN/pulls).

## 8. Cấu trúc repository

Cấu trúc chính của dự án:

- `docs/` — Tài liệu nghiên cứu, yêu cầu, thiết kế, báo cáo và quyết định kiến trúc.
  - `architecture/` — Mô hình kiến trúc, schema, data mapping và pipeline design.
  - `research/cyber/` — Nghiên cứu EPP/EDR, ATT&CK, telemetry và detection.
  - `research/data/` — Nghiên cứu Data Engineering, schema, feature và AI.
  - `research/software/` — Nghiên cứu Windows telemetry, collector và system architecture.
  - `decisions/` — Architecture Decision Records (ADR).
  - `report/` — Các báo cáo tiến độ theo tuần.
  - `scope/` — Phạm vi, giả định và giới hạn hệ thống.
- `poc/sysmon-collector/` — Mã nguồn và cấu hình Collector PoC.
- `references/samples/` — Bộ mẫu Sysmon XML/JSON và bằng chứng thực nghiệm.
- `src/pipeline/` — Các thành phần PoC, schema và kiểm định dữ liệu.
- `tests/` — Các bài kiểm thử hiện có.
- `diagrams/` — Thư mục dành cho sơ đồ kiến trúc.

Cấu trúc có thể được mở rộng và tổ chức lại khi hệ thống chuyển sang giai đoạn hiện thực.

## 9. Thử nghiệm Collector PoC

Repository hiện có một collector PoC hỗ trợ đọc dữ liệu sự kiện Sysmon đã xuất ra XML và chuyển đổi thành JSON.

Ví dụ chạy từ thư mục gốc repository:

```powershell
python poc/sysmon-collector/sysmon_collector_poc.py --mode file --input references/samples/raw/raw_process_create_event1.xml --output process_output.json
```

Chạy bài kiểm thử collector (sau khi cài đặt các dependency cần thiết):

```powershell
python -m pytest -q poc/sysmon-collector/test_sysmon_collector_poc.py
```

Đây là chức năng thử nghiệm dành cho nghiên cứu và phát triển, **không phải phần mềm Endpoint Protection chạy nền hoàn chỉnh**. Chế độ đọc trực tiếp Windows Event Log có thể cần Windows, Sysmon, `pywin32` và quyền truy cập phù hợp; không mặc định đã được kiểm chứng trong mọi môi trường.

**Lưu ý:** Một số dữ liệu mẫu thực nghiệm hiện chưa được khử định danh hoàn toàn. Cần kiểm tra thông tin host, người dùng và đường dẫn trước khi chia sẻ hoặc tái sử dụng công khai.

## 10. Thành viên và phân công

Dự án được thực hiện bởi nhóm ba thành viên với các vai trò chính:

| Vai trò | Trách nhiệm |
|---|---|
| Cyber Security | Nghiên cứu EPP/EDR, MITRE ATT&CK, Threat Model, detection rules, static analysis, threat hunting, investigation và response |
| Data Engineering / AI | Thiết kế Data Pipeline, schema, validation, storage, feature engineering, AI/ML và risk scoring |
| Software Engineering / System Architecture | Thiết kế hệ thống, Endpoint Agent/Collector, module interfaces, PoC, tích hợp và dashboard |

Các thành viên phối hợp thông qua GitHub Issues, Pull Requests và tài liệu kỹ thuật trong repository.

## 11. Tài liệu tham khảo

- [MITRE ATT&CK](https://attack.mitre.org/)
- [Microsoft Sysmon](https://learn.microsoft.com/en-us/sysinternals/downloads/sysmon)
- [Windows Event Log](https://learn.microsoft.com/en-us/windows/win32/wes/windows-event-log)
- [Wazuh Documentation](https://documentation.wazuh.com/)
- [osquery Documentation](https://osquery.readthedocs.io/)
- [Velociraptor Documentation](https://docs.velociraptor.app/)
- [Atomic Red Team](https://github.com/redcanaryco/atomic-red-team)

---

**DACN — Windows Endpoint Security**

*Giai đoạn 1: Nghiên cứu, xác minh tính khả thi và thiết kế kiến trúc.*  
*Giai đoạn 2: Hiện thực, tích hợp và đánh giá ứng dụng Endpoint Security.*
