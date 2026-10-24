# Bảng khả năng tích hợp và ràng buộc triển khai

**Ngày khảo sát:** 2026-10-19 · **Nguồn:** mã nguồn trích dẫn nằm ở file 01 mục 9 (ví dụ [T:S1]). Nhãn: **[T]** từ tài liệu, **[N]** nhận định chưa kiểm chứng, **[?]** chưa xác minh. **Không có mục nào đã thử nghiệm.** Không có số đo tài nguyên.

## A. Triển khai và môi trường

| Tiêu chí | Sysmon | Wazuh | osquery | Velociraptor | Atomic Red Team |
|---|---|---|---|---|---|
| Phiên bản khảo sát | v15.22 (2026-09-10) [T:S1] | 4.14.9 (2026-10-14) [T:W4]; có tài liệu 5.0-beta [T:W7] | 5.23.1 [T:O4] | 0.77.3 [T:V1] | Không có số phiên bản chính thức xác minh được; Invoke-AtomicRedTeam 2.1.0 theo nguồn thứ cấp [T:A6] |
| Loại / mô hình | Sensor standalone, không cần server [T:S1] | Agent + server + indexer + dashboard [T:W1] | Agent độc lập (daemon + shell) [T:O1] | Client–server, offline collector, chế độ `gui` cục bộ [T:V1, V3] | Thư viện test + module PowerShell chạy cục bộ hoặc từ xa [T:A1, A2] |
| Windows hỗ trợ | Windows 11+ và Server 2019+ theo trang chính thức [T:S1] | Agent: XP đến Windows 11, Server 2022 [T:W5]. **Server/indexer/dashboard: Linux 64-bit** [T:W3] | Gói MSI và ZIP x86_64, arm64 [T:O4]; danh sách phiên bản Windows hỗ trợ [?] | Client Windows qua MSI; Windows 7 không còn hỗ trợ cho bản build hiện đại [T:V2] | Module PowerShell [T:A1]; danh sách phiên bản Windows [?] |
| Cách triển khai | `sysmon64 -i <config>`; cập nhật `-c`; gỡ `-u`; không cần khởi động lại [T:S1]. Tùy chọn: tính năng tích hợp của Windows 11 [T:S3] | MSI agent (`WAZUH_MANAGER=...`); server cài bằng script (all-in-one) hoặc tách máy [T:W5, W1, W3] | MSI hoặc ZIP; osqueryd chạy lịch truy vấn [T:O4, O1] | MSI đã repack với client config; hoặc `service install`; hoặc offline collector [T:V2, V1] | `Install-AtomicRedTeam` và thư mục atomics; đường dẫn mặc định `C:\AtomicRedTeam` [T:A4] |
| Quyền cần thiết | Quản trị để cài driver/service [N] | Admin để cài agent [T:W5] | [?] | Cài MSI cần quyền nâng cao; service chạy bằng Local System [T:V2] | [?]; nhiều test có thể cần admin và bị Defender can thiệp [N] |
| Cấu hình | XML có `schemaversion`, luật include/exclude [T:S1] | `ossec.conf` cho agent; decoder/rule trên server [T:W5, W2] | `osquery.conf` (lịch truy vấn, pack) [T:O2] | File client config (khóa, địa chỉ server); artifact YAML + VQL [T:V2, V1] | YAML cho từng atomic; `config.ps1` cho runner [T:A1, A4] |
| Phụ thuộc chính | Driver Windows [T:S1] | Máy Linux; indexer; dashboard; Filebeat [T:W1, W3] | [?] | Một binary cho mỗi hệ điều hành/kiến trúc [T:V2] | PowerShell; module `powershell-yaml` [T:A6] |
| Ghi chú vận hành | Phiên bản tích hợp và standalone không cùng tồn tại [T:S5] | Yêu cầu phần cứng phụ thuộc số endpoint [T:W3] | Cần dùng bản mới: 5.23.1 vá lỗi tràn bộ đệm trong bảng `processes` Windows [T:O4] | Cần ≥ 0.77.3 do nhiều CVE [T:V1] | Tài liệu: chạy test có thể để lại trạng thái không mong muốn; chỉ chạy khi có phép [T:A2] |

## B. Interface, output và tích hợp với collector/pipeline dự kiến

| Tiêu chí | Sysmon | Wazuh | osquery | Velociraptor | Atomic Red Team |
|---|---|---|---|---|---|
| Interface | Windows Event Log API; Event Collection [T:S1] | REST API server (cổng 55000), REST API indexer, dashboard web [T:W1] | Shell SQL; Thrift API cho ứng dụng tùy chỉnh; plugin logger [T:O5, O1] | GUI; API gRPC (mTLS); CLI; notebook [T:V1, V5] | Cmdlet PowerShell (`Invoke-AtomicTest`) [T:A1, A3] |
| Định dạng output | XML sự kiện trong channel Sysmon/Operational [T:S1] | Alert lưu ở indexer; định dạng chi tiết [?] | Log JSON: `osqueryd.results.log` (differential) và `osqueryd.snapshots.log` [T:O3] | Dữ liệu thu thập (artifact); có xuất sang Splunk, Elastic, Timesketch [T:V1]; định dạng file [?] | Console; không sinh dữ liệu cho pipeline [N] |
| Tích hợp với collector Python | **Đã dùng**: đọc channel qua `pywin32`; PoC Week 3 (chưa chạy live) | Không trực tiếp. Muốn dùng phải đọc từ indexer/API, lệch với mô hình cục bộ [N] | JSON log đưa thẳng vào Bronze là dễ [N]; nhưng thêm một daemon cần quản lý | API gRPC có client Python [T:V5]; cần có server đang chạy [N] | Không cần tích hợp dữ liệu; tích hợp ở quy trình kiểm thử |
| Điểm chạm với Silver/DuckDB | Qua Bronze JSONL → Pydantic → Silver | Cần connector riêng [N] | Differential JSON có thể ánh xạ thành bảng sự kiện [N] | Qua API/xuất file [N] | Không |
| Khoảng trống Week 2/3 có thể bù | (là nguồn chính, các khoảng trống đã ghi ở file 04 Week 2) | FIM cho file và registry (registry quét định kỳ; thư mục realtime; whodata) [T:W7]; mức bù cho write/rename chưa xác minh [?] | `ntfs_journal_events` (write/rename file), `process_etw_events`, `registry` snapshot [T:O6]; độ chi tiết [?] | Nguồn sự kiện ETW và nhật ký sự kiện Windows, luật Sigma [T:V1]; chi tiết [?] | Không bù dữ liệu; kiểm chứng độ phủ của dữ liệu hiện có |

## C. License, độ phức tạp, ràng buộc tài nguyên và khuyến nghị

| Tiêu chí | Sysmon | Wazuh | osquery | Velociraptor | Atomic Red Team |
|---|---|---|---|---|---|
| License | Sysinternals Software License Terms [T:S2] | GPLv2 và Apache 2.0 tùy thành phần [T:W3] | `Apache-2.0 OR GPL-2.0-only`, người dùng chọn [T:O5] | AGPL-3.0 [T:V4] | Invoke-AtomicRedTeam: MIT [T:A1]; atomics: MIT theo nguồn thứ cấp [T:A6] |
| Điều kiện tái sử dụng | **Không phân phối lại binary**; dẫn link tải chính thức. Config do nhóm viết thì tự do. Cấu hình cộng đồng ghi CC BY 4.0 cần ghi công nếu dùng [T:S2, S4] | Copyleft: **không sao chép mã/rule vào repo**; chỉ lấy ý tưởng [N] | Chọn Apache-2.0 nếu cần dùng mã; giữ thông báo bản quyền [N] | Copyleft mạnh: **không sao chép mã**; dùng như công cụ ngoài [N] | MIT: dùng và sửa được, giữ thông báo bản quyền; cần đối chiếu LICENSE trong repo atomics [?] |
| Độ phức tạp tích hợp (định tính) | Thấp (đã làm) | Cao | Trung bình | Cao (client–server); thấp–trung bình (offline/`gui` cục bộ) [N] | Thấp–trung bình |
| Độ phức tạp vận hành (định tính) | Trung bình: tinh chỉnh bộ lọc, kiểm soát volume [T:S1, N] | Cao: 4 thành phần, rule/decoder XML [N] | Trung bình: thêm daemon, quản lý lịch truy vấn và log [N] | Cao nếu có server: chứng chỉ, cấu hình, đóng gói MSI [T:V2, N] | Thấp–trung bình; rủi ro nằm ở chọn test an toàn [N] |
| Ràng buộc tài nguyên | **Chưa đo.** Tài liệu cảnh báo Event 7, 10, 23 sinh lượng log/đĩa lớn [T:S1] | **Chưa đo.** Yêu cầu phụ thuộc số endpoint [T:W3] | **Chưa đo** [?] | **Chưa đo** [?] | Không áp dụng (chạy khi test) |
| Rủi ro chính | Windows 10 có được hỗ trợ không [T:S1]; volume | Lệch kiến trúc Phase 1; 5.0 sắp thay đổi [N] | Event table Windows hạn chế, chưa rõ gán tiến trình [?] | AGPL; CVE; lệch mô hình không-server | Test chạy thật có thể bị Defender chặn hoặc để lại trạng thái |
| **Khuyến nghị** | **Sử dụng** (nguồn telemetry chính) | **Tham khảo**; loại khỏi pipeline Phase 1 | **Tham khảo**; spike tùy chọn ở Phase 2 | **Tham khảo**; loại khỏi pipeline Phase 1 | **Sử dụng** (test tooling, tập con an toàn) |

## D. Đối chiếu với ràng buộc Phase 1

**✔** khớp · **✖** không khớp · **?** chưa rõ

| Ràng buộc | Sysmon | Wazuh | osquery | Velociraptor | Atomic Red Team |
|---|---|---|---|---|---|
| 1 endpoint, không có central server | ✔ | ✖ (cần server Linux) | ✔ | ✖ (client–server) / ✔ (offline, `gui` cục bộ) | ✔ |
| Stack Python 3.11, DuckDB, Pydantic | ✔ (đọc event log bằng `pywin32`) | ✖ | ✔ (JSON → Bronze) | ? (qua gRPC cần server) | ✔ (độc lập) |
| Giám sát user-space, không viết driver | ✔ (Sysmon đã có driver, nhóm không viết) | ✔ (agent) | ✔ | ✔ | ✔ |
| Ngân sách tài nguyên | ? (chưa đo) | ? | ? | ? | không áp dụng |
| Mô phỏng vô hại, không malware thật | không áp dụng | không áp dụng | không áp dụng | không áp dụng | ✔ có điều kiện (chọn tập con) |
| Tái sử dụng license không ràng buộc repo | ✔ (không phân phối binary) | ✖ (GPLv2) | ✔ (Apache-2.0) | ✖ (AGPL-3.0) | ✔ (MIT) |
