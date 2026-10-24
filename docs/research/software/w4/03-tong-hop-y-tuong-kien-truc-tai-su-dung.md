# Tổng hợp ý tưởng kiến trúc có thể tái sử dụng

Đây là **ý tưởng thiết kế**, không phải mã để sao chép. Nhãn: **[T]** từ tài liệu (nguồn ở file 01 mục 9), **[N]** nhận định chưa kiểm chứng. **Chưa có ý tưởng nào được thử nghiệm.** Cột "Giai đoạn": P1 nếu nằm trong phạm vi Phase 1, P2 nếu để sau.

## 1. Agent / Collector

| # | Ý tưởng | Nguồn | Áp dụng cho dự án | GĐ |
|---|---|---|---|---|
| A1 | Khai báo kênh cần đọc và định dạng trong cấu hình thay vì viết cứng: `<localfile>` + `eventchannel` cho kênh Sysmon | Wazuh [T:W6] | Collector đọc danh sách `channels` từ file YAML (kênh, query, định dạng) | P1 |
| A2 | Phân biệt **luồng sự kiện** và **snapshot trạng thái**; snapshot đọc theo chu kỳ và chỉ ghi phần thay đổi (differential) | osquery [T:O3] | Bronze có hai loại bản ghi `event` và `snapshot`; snapshot `psutil` (kết nối, process list) kèm `snapshot_id`, phần so sánh làm ở Silver | P1 |
| A3 | Duy trì **bảng process trong bộ nhớ** từ sự kiện tạo/kết thúc để tra cứu cha-con | Velociraptor: tài liệu có mục "Process Tracker" [T:V1]; chi tiết [?] | Collector giữ bảng `process_guid` → thông tin cha, giảm lỗi cây tiến trình bị cụt (Q-D9) | P1 (ý tưởng) |
| A4 | **Nạp lại cấu hình nóng** mà không ngắt kết nối | Wazuh 4.14.0 [T:W8]; Sysmon tự nạp lại cấu hình khi registry đổi [T:S1] | Collector đọc lại file cấu hình khi đổi; không cần khởi động lại | P2 |
| A5 | **Giới hạn tài nguyên** khi thu thập (giới hạn CPU, kiểm soát tốc độ) | Velociraptor [T:V1] | Giới hạn tốc độ ghi, kích thước batch, backpressure khi hàng đợi đầy; ghi sự kiện `telemetry_dropped_events_total` | P1 |
| A6 | **Gói thu thập offline**: đóng gói kết quả thành ZIP để review | Velociraptor offline collector [T:V1] | Lệnh xuất "triage bundle" từ Bronze/Silver cho Cyber/Data review | P2 |

## 2. Configuration

| # | Ý tưởng | Nguồn | Áp dụng cho dự án | GĐ |
|---|---|---|---|---|
| C1 | **Đặt tên luật** để sự kiện mang `RuleName` ngay từ nguồn | Sysmon: thuộc tính `name` [T:S1] | Gắn mã kỹ thuật/DET vào tên luật Sysmon (quy ước do nhóm đặt); Silver lưu `rule_name` | P1 |
| C2 | Ngữ nghĩa luật rõ ràng: include/exclude, **exclude thắng include**, cùng trường là OR, khác trường là AND, `RuleGroup` đặt AND/OR | Sysmon [T:S1] | Rule engine YAML của nhóm dùng cùng ngữ nghĩa để Cyber đã quen | P1 |
| C3 | Tách **decoder** (chuẩn hóa trường) khỏi **rule** (luật phát hiện) | Wazuh [T:W2] | Silver = decoder, Detection = rule; thêm nguồn mới chỉ cần thêm bộ ánh xạ | P1 |
| C4 | **Định nghĩa artifact bằng YAML**: tham số, điều kiện tiên quyết (precondition), nguồn truy vấn | Velociraptor [T:V1, mục Artifacts] | Schema file rule: `id`, `description`, `os`, `parameters`, `sql`, `severity`, `technique` | P1 |
| C5 | Nhóm luật theo chủ đề (pack) kèm tần suất chạy | osquery packs [T:O1] | Gói luật theo 13 kỹ thuật (execution, persistence...), mỗi gói có `interval` | P1 |
| C6 | **Sigma** làm định dạng luật di động | Velociraptor dùng Sigma [T:V1] | Đánh giá chuyển Sigma sang SQL DuckDB; công cụ chuyển đổi chưa xác minh [?] | P2 |

## 3. Query

| # | Ý tưởng | Nguồn | Áp dụng cho dự án | GĐ |
|---|---|---|---|---|
| Q1 | Dùng **SQL** làm ngôn ngữ truy vấn chung | osquery [T:O1]; DuckDB (stack hiện có) | Luật phát hiện là SQL có tên, chạy trên DuckDB (đã có POC Recursive CTE và sliding window) | P1 |
| Q2 | Truy vấn **theo lịch với kết quả differential**: chỉ báo phần mới xuất hiện | osquery [T:O2, O3] | Detection chạy theo cửa sổ trượt và chỉ phát alert cho hàng mới (giữ trạng thái để khử trùng alert) | P1 |
| Q3 | **Lọc tại nguồn**: đẩy truy vấn/bộ lọc xuống endpoint thay vì gom hết dữ liệu | Velociraptor [T:V1] | Dồn bộ lọc vào Sysmon config và bộ lọc của collector; không ghi mọi thứ vào Bronze | P1 |
| Q4 | Phân biệt truy vấn **sự kiện liên tục** và truy vấn **thu thập một lần** | Velociraptor (Event queries) [T:V1] | Collector có hai chế độ rõ ràng: theo dõi (follow) và xuất một lần | P1 |

## 4. Storage / Interface

| # | Ý tưởng | Nguồn | Áp dụng cho dự án | GĐ |
|---|---|---|---|---|
| S1 | Tách **dữ liệu thô đầy đủ** khỏi **alert** (server phân tích, indexer lưu alert) | Wazuh [T:W2] | Bronze giữ nguyên bản; bảng alert ở Gold; reprocess được khi đổi luật | P1 |
| S2 | **REST API** mỏng cho trạng thái và dữ liệu | Wazuh (cổng 55000) [T:W1] | API cục bộ trên DuckDB nếu sau này cần; Phase 1 Streamlit đọc DuckDB trực tiếp | P2 |
| S3 | **Notebook**: truy vấn đã lưu kèm kết quả để điều tra | Velociraptor [T:V1] | Trang "Investigation" trong Streamlit: danh sách truy vấn đã lưu (hunt định sẵn như Suspicious PowerShell, Unusual process tree) | P1 |
| S4 | **Xuất dữ liệu** sang định dạng công cụ ngoài đọc được | Velociraptor xuất Splunk/Elastic/Timesketch [T:V1] | Module báo cáo xuất CSV/JSON có cột thời gian chuẩn để nhập vào công cụ timeline | P1 |
| S5 | **Logger dạng plugin**: file là mặc định, có thể thay bằng đích khác | osquery [T:O1] | Lớp ghi Bronze/Silver có giao diện chung (JSONL, DuckDB, sau này Kafka) | P2 |

## 5. Test tooling

| # | Ý tưởng | Nguồn | Áp dụng cho dự án | GĐ |
|---|---|---|---|---|
| T1 | Mỗi kỹ thuật ATT&CK có test **mô tả bằng YAML** | Atomic Red Team [T:A1] | File `test-manifest.yaml`: kỹ thuật → atomic test → sự kiện Sysmon kỳ vọng → DET kỳ vọng | P1 |
| T2 | **Cleanup** đi kèm mỗi test để chạy lại được | Atomic Red Team [T:A3] | Mọi script mô phỏng của nhóm có phần dọn dẹp; quay về snapshot sau mỗi phiên | P1 |
| T3 | **Kiểm tra điều kiện tiên quyết** trước khi chạy | Atomic Red Team [T:A2] | Test harness kiểm tra Sysmon đang chạy, hash config khớp, channel còn chỗ trước khi chạy test | P1 |
| T4 | **Chạy liên tục theo lịch** để hồi quy | Atomic Red Team [T:A4] | Sau mỗi thay đổi rule/config, chạy lại bộ test; Phase 2 mới tự động hóa | P2 |
| T5 | Quy trình an toàn: máy test giống thật, đã có thu thập, có phép | Atomic Red Team [T:A2] | Văn bản "Test protocol" gắn với VM lab và snapshot | P1 |

## 6. Không nên tái sử dụng

| Việc | Lý do |
|---|---|
| Sao chép mã/rule/decoder của Wazuh vào repo | GPLv2 (copyleft) [T:W3] |
| Sao chép mã Velociraptor hoặc artifact vào repo | AGPL-3.0 [T:V4] |
| Đưa binary Sysmon vào repo hoặc phát hành kèm | Điều khoản Sysinternals [T:S2] |
| Chạy toàn bộ atomics | Nhiều test có thể gây hại hoặc bị Defender can thiệp; cần Cyber duyệt tập con [T:A2, N] |
| Cài Wazuh server trên cùng máy endpoint | Lệch kiến trúc Phase 1; cần máy Linux riêng [T:W3] |

## 7. Cập nhật sau W5: ý tưởng nào đã đi vào thiết kế

Chỉ ghi những ý tưởng được thiết kế ở W5 (file 01 đến 06 của W5). **Chưa ý tưởng nào được cài đặt hay chạy trên Windows.**

| Ý tưởng | Đã áp dụng ở W5 thế nào | Trạng thái |
|---|---|---|
| A1 Khai báo kênh trong cấu hình | Danh sách `channels` trong `edr.yaml` (W5 file 01 mục 9) | Thiết kế |
| A2 Luồng sự kiện và snapshot | `source` có `PSUTIL_SNAPSHOT`; Bronze phân biệt hai loại (W5 file 01 mục 3). Cơ chế snapshot chưa thiết kế chi tiết | Một phần |
| A3 Bảng process trong bộ nhớ | Chưa dùng; thay bằng `parent_image` lưu trên dòng con và cờ `tree_truncated` (Q-D9) | Chờ Data |
| A5 Giới hạn tốc độ, backpressure | Mô hình kéo, hàng đợi có giới hạn, quarantine và chỉ số `lag_seconds` (W5 file 04 mục 4, 5) | Thiết kế |
| C1 Đặt tên luật (`RuleName`) | `RuleName` còn nằm trong `event_data` của Bronze; cột Silver chưa chốt | Chờ Data |
| C3 Tách decoder và rule | D-02: Silver transform là nơi duy nhất ánh xạ ngữ nghĩa (W5 file 05 mục 4) | Đề xuất |
| Q2 Kết quả differential | Nạp idempotent bằng `INSERT OR IGNORE` và `_ingest_ledger` (W5 file 03 mục 4); phát alert chỉ cho dòng mới chưa thiết kế | Một phần |
| S1 Tách dữ liệu thô khỏi alert | Bronze bất biến, Gold chứa alert (W5 file 03 mục 1) | Thiết kế |
| A4, A6, C6, S2, S5, T4 | Vẫn để Phase 2 | Không đổi |
| T1 đến T3, T5 | Chưa thay đổi; tập con atomic test chưa chốt (U4) | Không đổi |
