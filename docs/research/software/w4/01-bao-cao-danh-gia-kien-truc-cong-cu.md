# Báo cáo đánh giá kiến trúc công cụ (Tuần 4, vai trò Software)

**Ngày khảo sát:** 2026-10-19 · **Phạm vi:** Wazuh, Sysmon, osquery, Velociraptor, Atomic Red Team · **Trạng thái:** DRAFT, chờ review của Cyber và Data (M1)

## 0. Quy ước độ tin cậy

| Nhãn | Ý nghĩa |
|---|---|
| **[T:id]** | Nhận định lấy từ tài liệu/nguồn có dẫn ở mục 9 |
| **[N]** | Nhận định của người đánh giá, suy luận từ tài liệu, chưa kiểm chứng |
| **[?]** | Chưa xác minh được trong đợt khảo sát này |
| **[X]** | Đã thử nghiệm trên máy lab |

**Không có mục nào trong báo cáo này mang nhãn [X].** Nhóm chưa cài đặt hay chạy thử công cụ nào trong 5 công cụ; mọi đánh giá dựa trên tài liệu. Báo cáo cũng **không có số đo** CPU/RAM/độ trễ vì chưa thử nghiệm.

## 1. Đầu vào đã đọc

**Ràng buộc hệ thống Phase 1** (từ `phase-1-scope.md`, `week-1-decisions.md`, `data_pipeline_phase_1_scope.md`, `threat_model_v1.md`):
- 1 endpoint Windows (VM lab), không có central server; giám sát chủ yếu ở user-space; không viết driver/kernel hook, việc móc nối OS giao cho Sysmon.
- Stack: Python 3.11, Pydantic, DuckDB, Parquet, Streamlit (`requirements.txt`). Bronze JSONL → Silver DuckDB → Gold Parquet.
- Ngân sách tài nguyên ghi không nhất quán giữa các tài liệu (RAM < 150 MB hoặc < 200 MB; CPU < 3% hoặc spike ≤ 5%), chưa có số đo (Q-D5).
- Chỉ dùng mô phỏng vô hại; 13 kỹ thuật MITRE và DET-001 đến DET-010 của Cyber.

**Kết quả collector PoC Tuần 3:** có mã PoC và 13 unit test đạt **trên sự kiện giả lập**; **chưa có mẫu sự kiện thật**, chưa chạy live, chưa chạy script/config trên Windows. Vì vậy báo cáo này **không dựa vào số liệu thực nghiệm nào từ PoC**.

## 2. Phân biệt vai trò: năm công cụ không thay thế nhau

| Công cụ | Loại | Trả lời câu hỏi | Vị trí trong pipeline của nhóm |
|---|---|---|---|
| **Sysmon** | Sensor telemetry (driver + service) | "Điều gì vừa xảy ra trên host?" | Nguồn dữ liệu đầu vào (Bronze) |
| **Wazuh** | Nền tảng XDR/SIEM: agent + server + indexer + dashboard | "Thu gom, phân tích theo luật, lưu trữ, hiển thị" | Chồng lấn với **toàn bộ phần phía sau collector** mà nhóm đang tự xây (Silver, Detection, UI) |
| **osquery** | Framework truy vấn trạng thái endpoint bằng SQL | "Trạng thái hệ thống hiện tại / thay đổi theo thời gian?" | Nguồn bổ sung dạng snapshot và event table |
| **Velociraptor** | Nền tảng DFIR/hunting client–server dùng VQL | "Thu thập bằng chứng, săn mối đe dọa theo yêu cầu" | Công cụ điều tra; nguồn ý tưởng |
| **Atomic Red Team** | Thư viện test mô phỏng kỹ thuật ATT&CK + framework chạy | "Phát hiện của mình có bắt được kỹ thuật X không?" | Công cụ kiểm thử/nghiệm thu |

```text
  Atomic Red Team ──(sinh hành vi)──► Windows endpoint
                                          │
                       Sysmon ──(ghi event log)──► [Collector (Python)] ──► Bronze ► Silver ► Gold ► Detection ► UI
                                          │
          (tham khảo / bổ sung)   osquery, Velociraptor, Wazuh  ── không nằm trên đường dữ liệu chính của Phase 1
```

## 3. Sysmon (v15.22, phát hành 2026-09-10 [T:S1])

**Kiến trúc và luồng dữ liệu.** Dịch vụ Windows kèm driver, cài một lần và giữ nguyên qua khởi động lại; ghi sự kiện vào event log, **không phân tích sự kiện và không che giấu bản thân** [T:S1]. Service chạy ở dạng protected process [T:S1]. Sự kiện nằm ở `Applications and Services Logs/Microsoft/Windows/Sysmon/Operational`, thời gian UTC; được thu bằng Windows Event Collection hoặc agent SIEM [T:S1]. Mô hình **standalone**, không cần server.

**Phạm vi sự kiện** (ID 1 đến 29 và 255) [T:S1]: có Event 25 ProcessTampering (phát hiện hollowing/herpaderp), 29 FileExecutableDetected, 15 FileCreateStreamHash (Mark-of-the-Web). Event 3 (network) và Event 7 (image load) **tắt mặc định**; tài liệu cảnh báo bật tất cả Event 7 hoặc 10 sinh rất nhiều log [T:S1]. Event 23 lưu bản sao file bị xóa vào `C:\Sysmon` (mặc định) và thư mục này có thể lớn nhanh; Event 26 chỉ ghi log [T:S1]. Event 11 ghi cả tạo mới lẫn ghi đè [T:S1]. Event 13 "ghi giá trị cho kiểu DWORD và QWORD" [T:S1], nên việc giá trị chuỗi có được ghi hay không cần kiểm chứng bằng mẫu thật **[?]**.

**Windows và triển khai.** Trang chính thức ghi "Runs on": client Windows 11 trở lên, Server 2019 trở lên [T:S1]. **Môi trường lab của nhóm đang ghi Windows 10/11 → cần xác nhận** (mục 8). Lệnh: `sysmon64 -i [config]`, `-c` (cập nhật/dump), `-s` (in schema), `-u`; không cần khởi động lại [T:S1]. Từ 2026, Sysmon có thể bật như tính năng tùy chọn tích hợp sẵn của Windows 11, cập nhật qua Windows Update [T:S3]; bản tích hợp và bản standalone không cùng tồn tại [T:S5]. Quyền: cài driver/service cần quyền quản trị [N] (trang đã đọc không nêu rõ).

**Cấu hình.** File XML có `schemaversion`; luật `include`/`exclude` theo từng loại sự kiện, **exclude thắng include**; các điều kiện (is, contains, begin with, end with, image...) **không phân biệt hoa thường**; cùng tên trường là OR, khác tên trường là AND; `RuleGroup` đặt AND/OR tường minh; thuộc tính `name` trên luật làm sự kiện mang `RuleName` [T:S1]. Mục cấu hình: `HashAlgorithms`, `DnsLookup`, `ArchiveDirectory`, `CopyOnDelete*`, `CheckRevocation`... [T:S1].

**Interface và output.** Không có API riêng; đọc qua Windows Event Log API; output là XML sự kiện [T:S1, N]. Đây chính là đường Collector Week 3 đang dùng.

**License.** Sysinternals Software License Terms: phần mềm "được cấp phép, không bán"; cấm công bố để người khác sao chép, cho thuê, dùng cho dịch vụ lưu trữ thương mại... [T:S2]. **Không đưa file nhị phân Sysmon vào repo**; dẫn link tải chính thức. Config XML do nhóm tự viết thì không bị ràng buộc này.

**Độ phức tạp và tài nguyên (định tính).** Cài đặt thấp; vận hành trung bình vì phải tinh chỉnh bộ lọc và kiểm soát volume [N, T:S1]. Chưa có số đo.

**Khuyến nghị: DÙNG làm nguồn telemetry chính.** Điều chỉnh các tài liệu Tuần 2 dựa trên khảo sát này: (a) Event 25 có tồn tại, nên "process hollowing ngoài phạm vi" ở `04-technical-limitations` mục 1.4 cần sửa thành "có tín hiệu qua Event 25, chưa đánh giá"; (b) ghi chú phiên bản hỗ trợ Windows; (c) kiểm chứng giả định về Event 13. **Trạng thái:** (a) đã sửa ở file 04 Tuần 2 mục 1.4; (b) và (c) chờ mẫu thật và thử nghiệm trên VM.

## 4. Atomic Red Team (test tooling)

**Kiến trúc.** Thư viện thử nghiệm: thư mục `atomics` có một thư mục cho mỗi kỹ thuật ATT&CK, mỗi test có file YAML và bản markdown [T:A1]. **Invoke-AtomicRedTeam** là module PowerShell thực thi các test [T:A1]. Standalone, không cần server; có chạy cục bộ, chạy từ xa, kiểm tra/cài điều kiện tiên quyết, **lệnh cleanup**, và runner chạy liên tục theo lịch CSV [T:A2, A3, A4].

**Cảnh báo chính thức.** Chạy test có thể để hệ thống ở trạng thái không mong muốn; chỉ chạy khi có phép; nên dùng máy test giống môi trường thật **và đã có sẵn hệ thống thu thập/EDR đang hoạt động** [T:A2]. Điều này khớp với cách nhóm dùng VM lab có snapshot.

**Windows và triển khai.** Module PowerShell; đường dẫn mặc định trong cấu hình runner là `C:\AtomicRedTeam\...` [T:A4]. Quyền yêu cầu và việc Windows Defender có chặn một số test **chưa xác minh [?]**; nhiều test mô phỏng kỹ thuật thật nên khả năng cần quyền admin và bị antivirus can thiệp là có [N].

**Output và tích hợp.** Công cụ tạo hành vi, không tạo dữ liệu cho pipeline; kết quả kiểm thử là việc kiểm tra telemetry của chính nhóm (Sysmon, Silver, rule) có phản ánh hành vi đó không [N].

**License.** Invoke-AtomicRedTeam: MIT [T:A1]. Thư viện atomics: MIT theo nguồn thứ cấp [T:A6], cần đối chiếu file LICENSE trong repo `atomic-red-team` **[?]**.

**Phiên bản.** Không xác minh được số phiên bản chính thức; một hướng dẫn ghi Invoke-AtomicRedTeam 2.1.0 (nguồn thứ cấp) [T:A6]. Thư viện atomics cập nhật liên tục theo repo.

**Độ phức tạp.** Thấp đến trung bình (PowerShell, YAML); rủi ro nằm ở việc chọn test an toàn [N].

**Khuyến nghị: DÙNG làm test tooling**, chỉ chạy tập con an toàn do Cyber duyệt, trên VM có snapshot. Bổ sung (không thay thế) các script vô hại của nhóm ở Week 3.

## 5. osquery (v5.23.1 là bản ổn định mới nhất xác nhận được [T:O4])

**Kiến trúc và luồng dữ liệu.** Framework "SQL powered operating system instrumentation"; có Linux, macOS, Windows, FreeBSD [T:O5]. Hai thành phần chính: **osqueryd** (daemon chạy các truy vấn đã lên lịch và sinh log) và **osqueryi** (shell SQL tương tác) [T:O1]. Lịch truy vấn khai báo trong `osquery.conf` [T:O2]. Kết quả ghi thành log JSON: **differential** (chỉ phần thay đổi; mặc định) vào `osqueryd.results.log`, hoặc **snapshot** vào `osqueryd.snapshots.log` [T:O3]. Bảng có hậu tố `_events` là bảng sự kiện, nhận sự kiện từ API của hệ điều hành; tập bảng sự kiện **khác nhau giữa các nền tảng** [T:O2]. Kiến trúc plugin cho phép đẩy log vào pipeline bên ngoài [T:O1]. Mô hình **agent độc lập** (không bắt buộc server); có nhiều fleet manager bên thứ ba mà dự án osquery không bảo trợ hay kiểm thử [T:O5].

**Bảng liên quan Windows.** `processes`, `registry`, `windows_events`, `ntfs_journal_events`; `process_etw_events` (bảng sự kiện process dựa trên ETW, được bổ sung ở một bản 5.x, số bản cụ thể chưa xác minh **[?]**) [T:O6]. `ntfs_journal_events` do Trail of Bits phát triển để theo dõi thay đổi file gần thời gian thực [T:O6]; liệu bảng có cho biết tiến trình thực hiện thao tác hay không **chưa xác minh [?]** (nhận định: nhật ký NTFS thường không ghi tiến trình [N]). Bảng `registry` là bảng truy vấn trạng thái, không phải luồng sự kiện [N].

**Triển khai Windows.** Gói MSI và ZIP (x86_64, arm64) trong release 5.23.1 [T:O4]. Quyền chạy daemon và đọc nhật ký sự kiện **chưa xác minh [?]**. Release 5.23.1 vá lỗi tràn bộ đệm trong bảng `processes` trên Windows [T:O4]: cần luôn dùng bản mới.

**Interface.** Shell SQL, log JSON, plugin logger; ứng dụng tùy chỉnh dùng **Thrift API** [T:O5].

**License.** `Apache-2.0 OR GPL-2.0-only`, người dùng chọn một [T:O5]. Điều kiện thuận lợi nhất trong 5 công cụ nếu cần tái sử dụng mã (chọn Apache-2.0, vẫn phải giữ thông báo bản quyền) [N].

**Độ phức tạp.** Trung bình: thêm một daemon cần cấu hình lịch truy vấn và quản lý log; nhưng SQL và JSON gần với stack DuckDB của nhóm [N].

**Khuyến nghị: THAM KHẢO**; cân nhắc **spike tùy chọn ở Phase 2** cho `ntfs_journal_events` (khoảng trống write/rename) và `registry` (snapshot đối chiếu). Không thêm agent thứ hai trong Phase 1.

## 6. Velociraptor (v0.77.3 theo banner tài liệu [T:V1])

**Kiến trúc.** Nền tảng mã nguồn mở cho giám sát endpoint, DFIR và phản ứng [T:V1]. Ba cách dùng: **client–server** (client là service cài trên endpoint, giữ kết nối tới server và chạy các truy vấn **VQL** do server giao); **offline collector** (binary cấu hình sẵn, thu artifact vào file ZIP mã hóa cục bộ); **phân tích ảnh đĩa** [T:V1]. Một binary cho mỗi hệ điều hành/kiến trúc, vai trò (server hay client) chọn bằng dòng lệnh [T:V2]. Lệnh `velociraptor gui` dựng GUI, frontend và một client cục bộ trên cùng máy [T:V3]. Phát hiện thời gian thực nhờ nguồn sự kiện **ETW** (Windows) hoặc eBPF (Linux) và luật **Sigma** [T:V1]. Triết lý: đẩy truy vấn xuống endpoint thay vì gom hết dữ liệu về trung tâm [T:V1].

**Interface và tích hợp.** API **gRPC** (mTLS) dùng được từ Python, Go, Java hoặc shell [T:V1, V5]; xuất dữ liệu sang Splunk, Elastic, Timesketch; có artifact đọc sự kiện Sysmon đẩy sang Elastic [T:V1].

**Windows và triển khai.** Client cài thành service bằng MSI: bản release cài vào `C:\Program Files\Velociraptor\`, service chạy bằng tài khoản **Local System**, khởi động tự động có trễ; cài MSI cần quyền nâng cao [T:V2]. Client có thể chạy thủ công bằng người dùng thường nhưng bị giới hạn dữ liệu truy cập [T:V2]. Windows 7 không còn được hỗ trợ cho bản build hiện đại do giới hạn của Go [T:V2]. Client cần file cấu hình chứa vật liệu mã hóa và địa chỉ server [T:V2].

**License.** **AGPL-3.0** [T:V4]. Điều kiện copyleft mạnh (kể cả khi cung cấp dịch vụ qua mạng) [N]: **không sao chép mã** vào repo; dùng như công cụ ngoài hoặc chỉ lấy ý tưởng.

**An toàn vận hành.** Tài liệu hiện kêu gọi cập nhật lên 0.77.3 để vá nhiều CVE [T:V1]: nếu dùng thử trong lab, dùng bản mới nhất và không mở ra ngoài mạng lab [N].

**Độ phức tạp.** Cao nếu dựng client–server (server, chứng chỉ, cấu hình, tạo MSI); thấp hơn ở chế độ offline collector hoặc `gui` cục bộ [N]. Với cam kết "không có central server", mô hình client–server **không khớp Phase 1** [N].

**Khuyến nghị: THAM KHẢO ý tưởng**; dùng thử có giới hạn ở chế độ cục bộ nếu cần đối chiếu dữ liệu thu được. Không tích hợp vào pipeline và không sao chép mã.

## 7. Wazuh (v4.14.9, 2026-10-14 [T:W4])

**Kiến trúc.** Agent đa nền tảng + ba thành phần trung tâm: **server** (phân tích qua decoder và rule, đối chiếu IOC), **indexer** (tìm kiếm và lưu alert), **dashboard** (giao diện web) [T:W1, W2]. Luồng: agent gửi sự kiện liên tục tới server; server dùng Filebeat gửi alert/sự kiện tới indexer qua TLS; dashboard truy vấn server API (mặc định cổng 55000/TCP) và indexer [T:W1]. Ba kiểu triển khai: all-in-one, single-node (tách máy), multi-node cluster [T:W1].

**Windows và triển khai.** Agent hỗ trợ Windows từ XP đến Windows 11 và Server 2022; cài bằng MSI, **cần quyền admin**; file tại `C:\Program Files (x86)\ossec-agent`; cấu hình `ossec.conf` [T:W5]. **Các thành phần trung tâm yêu cầu Linux 64-bit** (Amazon Linux 2/2023, RHEL 7 đến 10, Ubuntu 16.04 đến 24.04); yêu cầu phần cứng phụ thuộc số lượng endpoint [T:W3].

**Thu thập Sysmon.** Agent đọc kênh `Microsoft-Windows-Sysmon/Operational` qua khối `<localfile>` với `log_format` là `eventchannel` [T:W6]. Đây cùng ý tưởng với collector của nhóm; Wazuh và Sysmon **bổ sung** cho nhau, không thay thế nhau.

**FIM.** Giám sát file và khóa registry trên Windows; registry theo quét định kỳ (tài liệu 5.0-beta); realtime áp dụng cho thư mục; whodata cho biết ai thực hiện thao tác [T:W7].

**Interface và output.** REST API của server và indexer, dashboard web [T:W1, W2]; định dạng alert chi tiết (ví dụ file alerts JSON) **chưa xác minh trong đợt này [?]**.

**License.** GPLv2 và Apache 2.0 tùy thành phần [T:W3]. Copyleft GPLv2: **không sao chép mã/rule vào repo**; chỉ tham khảo ý tưởng.

**Phiên bản.** 4.14.9 là bản 4.x mới nhất [T:W4]; tài liệu 5.0-beta đã xuất hiện [T:W7], nên có thể có thay đổi lớn sắp tới [N].

**Độ phức tạp.** Cao so với Phase 1: bốn thành phần, cần máy Linux riêng, cấu hình rule/decoder dạng XML [N]; mâu thuẫn với "không central server" và ràng buộc stack Python/DuckDB [N]. Tài liệu chưa cung cấp, và nhóm chưa đo, số liệu tài nguyên.

**Khuyến nghị: THAM KHẢO** (kiến trúc agent→decoder→rule→alert, làm giàu MITRE, cấu hình tập trung), **loại khỏi pipeline Phase 1**.

## 8. Điểm chưa chốt và kế hoạch thử nghiệm tối thiểu (không bắt buộc)

| Mã | Điều cần xác minh | Cách làm | Trạng thái |
|---|---|---|---|
| U1 | Sysmon v15.22 có chạy trên Windows 10 lab không, hay phải dùng Windows 11? | Cài thử trên VM đang dùng | Chưa thực hiện |
| U2 | Dùng Sysmon tích hợp sẵn của Windows 11 hay bản standalone ghim phiên bản? | Quyết định ở ADN-001 | Chờ review |
| U3 | Giá trị chuỗi có xuất hiện trong Details của Event 13 không? | Mẫu thật Week 3 (thí nghiệm E5/E6) | Chờ mẫu |
| U4 | Atomic test nào có sẵn cho từng trong 13 kỹ thuật và test nào an toàn? | `Invoke-AtomicTest <T-id> -ShowDetailsBrief` trên VM | Chưa thực hiện |
| U5 | `ntfs_journal_events` có cho biết tiến trình ghi file không? | Cài osquery trên VM và truy vấn (Phase 2) | Chưa thực hiện |
| U6 | Định dạng log đầu ra của Wazuh server | Đọc tài liệu Wazuh (mục alert) | Chưa thực hiện |

## 9. Nguồn (truy cập 2026-10-19)

**Tài liệu nội bộ:** `phase-1-scope.md`, `week-1-decisions.md`, `data_pipeline_phase_1_scope.md`, `threat_model_v1.md`, `selected_mitre_techniques_v1.md`, tài liệu Week 2 và Week 3 của Software.

**Sysmon**
- S1 Microsoft Learn, Sysmon v15.22 (cập nhật 2026-09-10): https://learn.microsoft.com/en-us/sysinternals/downloads/sysmon
- S2 Sysinternals Software License Terms: https://live.sysinternals.com/Eula.txt
- S3 Sysmon tích hợp trong Windows 11 (nguồn thứ cấp): https://petervanderwoude.nl/post/easily-enabling-sysmon-in-windows-11/
- S4 Ví dụ cấu hình cộng đồng ghi CC BY 4.0 (bản gist sao chép): https://gist.github.com/terminal-root/2c15bb15432674ff88b09a89c0c42f41
- S5 Bản tích hợp và standalone không cùng tồn tại (nguồn thứ cấp): https://nxlog.co/news-and-blog/posts/sysmon-event-ids

**Wazuh**
- W1 Architecture: https://documentation.wazuh.com/current/getting-started/architecture.html
- W2 Components: https://documentation.wazuh.com/current/getting-started/components.html
- W3 Quickstart (yêu cầu, license): https://documentation.wazuh.com/current/quickstart.html
- W4 Release notes 4.x: https://documentation.wazuh.com/current/release-notes/index-4x.html
- W5 Cài agent Windows: https://documentation.wazuh.com/current/installation-guide/wazuh-agent/wazuh_agent_package_windows.html
- W6 Thu thập kênh Sysmon: https://wazuh.com/blog/detecting-defense-evasion-techniques-with-wazuh/
- W7 FIM registry (5.0-beta): https://documentation.wazuh.com/5.0-beta/user-manual/capabilities/file-integrity/windows-registry-monitoring.html
- W8 Release 4.14.0 (hot reload cấu hình agent): https://documentation.wazuh.com/current/release-notes/release-4-14-0.html

**osquery**
- O1 Tài liệu: https://osquery.readthedocs.io/
- O2 Cấu hình: https://osquery.readthedocs.io/en/stable/deployment/configuration/
- O3 Logging: https://osquery.readthedocs.io/en/stable/deployment/logging/
- O4 Releases: https://github.com/osquery/osquery/releases (5.23.1; một kết quả tìm kiếm nhắc 5.24.0 nhưng trang release trả lỗi 404 khi truy cập, nên không dùng)
- O5 Repo và LICENSE (`Apache-2.0 OR GPL-2.0-only`): https://github.com/osquery/osquery ; https://fossies.org/linux/osquery/LICENSE
- O6 Bảng sự kiện Windows: https://blog.trailofbits.com/2020/03/16/real-time-file-monitoring-on-windows-with-osquery/ ; https://chat.osquery.io/t/16332485/hi-everyone-does-osquery-does-not-give-real-time-data-for-wi

**Velociraptor**
- V1 Overview: https://docs.velociraptor.app/docs/overview/
- V2 Deploying Clients: https://docs.velociraptor.app/docs/deployment/clients/
- V3 Repo: https://github.com/Velocidex/velociraptor
- V4 License AGPL-3.0 (gói phân phối): https://build.opensuse.org/projects/openSUSE:Factory/packages/velociraptor/files/velociraptor.spec ; https://gitlab.com/velocidex/velociraptor/-/releases
- V5 API Python/gRPC: https://docs.velociraptor.app/blog/html/2019/02/09/velociraptor_python_api

**Atomic Red Team**
- A1 Invoke-AtomicRedTeam (MIT): https://github.com/redcanaryco/invoke-atomicredteam
- A2 Wiki (cảnh báo, hướng dẫn): https://github.com/redcanaryco/invoke-atomicredteam/wiki
- A3 Cleanup: https://github.com/redcanaryco/invoke-atomicredteam/wiki/Cleanup-After-Executing-Atomic-Tests
- A4 Continuous testing: https://github.com/redcanaryco/invoke-atomicredteam/wiki/Continuous-Atomic-Testing
- A6 License và phiên bản (nguồn thứ cấp): https://tech-insider.org/atomic-red-team-setup-2026/
