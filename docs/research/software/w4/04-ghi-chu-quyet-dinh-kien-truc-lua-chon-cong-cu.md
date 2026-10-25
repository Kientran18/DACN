# Ghi chú quyết định kiến trúc (ADN): lựa chọn công cụ

**Ngày:** 2026-10-19 · **Trạng thái chung:** **Đề xuất, chờ review của Cyber và Data (M1)**; chưa có quyết định nào được xác nhận. Bằng chứng: toàn bộ từ tài liệu, **chưa có thử nghiệm** (xem file 01 mục 0). Nguồn ở file 01 mục 9.

## Tóm tắt

| ADN | Công cụ | Đề xuất | Vai trò | Giai đoạn |
|---|---|---|---|---|
| 001 | (Khung đánh giá) | Đánh giá theo vai trò, không xếp hạng đối đầu | — | — |
| 002 | Sysmon | **SỬ DỤNG** | Nguồn telemetry chính | P1 |
| 003 | Atomic Red Team | **SỬ DỤNG** | Test tooling (tập con an toàn) | P1 |
| 004 | Wazuh | **THAM KHẢO**; loại khỏi pipeline Phase 1 | Nguồn ý tưởng kiến trúc/luật | — |
| 005 | osquery | **THAM KHẢO**; spike tùy chọn Phase 2 | Nguồn bổ sung snapshot/event table | P2 |
| 006 | Velociraptor | **THAM KHẢO**; loại khỏi pipeline Phase 1 | Nguồn ý tưởng DFIR/VQL | — |
| 007 | (Chung) | Quy tắc license khi tham khảo | — | P1 |
| 008 | Sysmon | **MỞ**: Windows 10 hay 11; bản tích hợp hay standalone | — | P1 |

---

## ADN-001: Khung đánh giá theo vai trò

- **Bối cảnh.** Năm công cụ thuộc năm lớp khác nhau: sensor (Sysmon), nền tảng XDR/SIEM (Wazuh), framework truy vấn endpoint (osquery), nền tảng DFIR (Velociraptor), thư viện test mô phỏng (Atomic Red Team).
- **Quyết định.** Không xếp hạng đối đầu. Mỗi công cụ được đánh giá theo câu hỏi "nó giải quyết phần nào của pipeline Phase 1, và có khớp ràng buộc không".
- **Lý do.** So sánh trực tiếp Sysmon với Wazuh hay Atomic Red Team với osquery sẽ cho kết luận sai.
- **Hệ quả.** Bảng ở file 02 mục D đối chiếu từng công cụ với ràng buộc Phase 1, không chấm điểm tổng.

## ADN-002: Sysmon: SỬ DỤNG làm nguồn telemetry chính

- **Quyết định.** Giữ Sysmon là nguồn thu thập chính cho process, file, registry, network, DNS.
- **Lý do.**
  - Đã nằm trong phạm vi Phase 1: bàn giao việc móc nối OS cho Sysmon, không viết kernel hook (`data_pipeline_phase_1_scope.md`).
  - Mô hình standalone, không cần server; ghi vào event log mà collector Python đọc được [T:S1].
  - Có GUID tiến trình, bộ lọc include/exclude, `RuleName` [T:S1].
  - Wazuh cũng đọc kênh Sysmon theo cách này [T:W6], nên đây là mô hình thu thập phổ biến.
- **Phương án đã xem xét.** Dùng `process_etw_events` của osquery, nguồn ETW của Velociraptor hoặc ETW trực tiếp: chi phí tích hợp cao hơn, độ chi tiết chưa xác minh; để Phase 2.
- **Hệ quả và rủi ro.**
  - Giới hạn đã biết (không write/rename, network chỉ ở mức kết nối...) giữ nguyên ở file 04 Week 2.
  - Event 25 ProcessTampering có tồn tại [T:S1]: cần sửa giới hạn "hollowing ngoài phạm vi" ở file 04 Week 2.
  - Event 13 chỉ được tài liệu mô tả cho DWORD/QWORD [T:S1]: kiểm chứng bằng mẫu thật.
  - Không đưa binary vào repo [T:S2] (xem ADN-007).
- **Xem xét lại nếu:** mẫu thật Week 3 cho thấy thiếu trường quan trọng với DET-001 đến 010 và không có cách bù.

## ADN-003: Atomic Red Team: SỬ DỤNG làm test tooling

- **Quyết định.** Dùng Atomic Red Team để kiểm thử và nghiệm thu độ phủ 13 kỹ thuật; chỉ chạy **tập con an toàn do Cyber duyệt**, trên VM có snapshot. Bổ sung (không thay) script mô phỏng vô hại của nhóm.
- **Lý do.**
  - Có test mô tả bằng YAML cho từng kỹ thuật ATT&CK, có lệnh cleanup [T:A1, A3].
  - Tài liệu chính thức khuyên chạy trên máy test đã có hệ thống thu thập hoạt động [T:A2], đúng với mô hình lab.
  - License MIT cho module [T:A1].
- **Phương án đã xem xét.** Chỉ dùng script tự viết: ít tốn công nhưng độ phủ nhỏ và khó chứng minh với người ngoài. Dùng bộ mô phỏng khác: chưa khảo sát.
- **Hệ quả và rủi ro.**
  - Một số test có thể gây hại hoặc bị Defender can thiệp; quyền chạy chưa xác minh [?].
  - Cần tra danh sách atomics cho từng trong 13 kỹ thuật (U4 ở file 01).
- **Xem xét lại nếu:** phần lớn test của 13 kỹ thuật không chạy an toàn trên lab, hoặc Defender chặn nên không thể kiểm thử.

## ADN-004: Wazuh: THAM KHẢO, loại khỏi pipeline Phase 1

- **Quyết định.** Không dùng Wazuh trong pipeline Phase 1; chỉ lấy ý tưởng (decoder → rule → alert, làm giàu MITRE, cấu hình agent, FIM).
- **Lý do.**
  - Thành phần trung tâm cần máy Linux 64-bit [T:W3] và gồm server, indexer, dashboard [T:W1]: mâu thuẫn với "không có central server" và stack Python/DuckDB/Streamlit của Phase 1.
  - Chồng lấn với phần nhóm đang tự xây (Silver, Detection, UI): dùng Wazuh sẽ làm mất mục tiêu học tập và đánh giá của đồ án [N].
  - GPLv2 [T:W3]: không sao chép mã/rule (ADN-007).
- **Phương án đã xem xét.** Dùng agent Wazuh làm collector: vẫn cần server để có giá trị. Dùng Wazuh làm hệ thống tham chiếu đối chiếu kết quả: tốn một máy Linux, để Phase 2.
- **Hệ quả và rủi ro.** Wazuh 5.0 đang beta [T:W7]; nếu muốn dùng làm tham chiếu về sau cần theo dõi thay đổi. Định dạng alert chưa xác minh [?].
- **Xem xét lại nếu:** đồ án chuyển sang kiến trúc tập trung (nhiều endpoint, server trung tâm).

## ADN-005: osquery: THAM KHẢO, spike tùy chọn ở Phase 2

- **Quyết định.** Không thêm osquery vào Phase 1. Lấy ý tưởng differential/snapshot (A2) và gói truy vấn (C5). Nếu có thời gian ở Phase 2, thử `ntfs_journal_events`, `process_etw_events` và `registry` để xem có bù được khoảng trống write/rename và snapshot registry.
- **Lý do.**
  - Thêm một daemon thứ hai khi Sysmon đã bao phủ 4 nhóm telemetry [N].
  - Có bảng sự kiện cho Windows nhưng độ chi tiết và gán tiến trình chưa xác minh [T:O6, ?].
  - License thuận lợi (Apache-2.0 hoặc GPLv2, chọn một) [T:O5]: là công cụ dễ chấp nhận nhất nếu về sau cần dùng.
- **Phương án đã xem xét.** Dùng osquery làm nguồn chính thay Sysmon: mất GUID tiến trình và bộ lọc quen thuộc của Sysmon [N]; không chọn.
- **Hệ quả và rủi ro.** Cần luôn dùng bản mới (5.23.1 vá lỗi bảng `processes` Windows [T:O4]).
- **Xem xét lại nếu:** mẫu thật cho thấy thiếu write/rename quan trọng với DET-008 và Cyber yêu cầu bù.

## ADN-006: Velociraptor: THAM KHẢO, loại khỏi pipeline Phase 1

- **Quyết định.** Không tích hợp vào pipeline; lấy ý tưởng (artifact YAML C4, process tracker A3, offline collector A6, notebook S3). Có thể dùng thử ở chế độ cục bộ để đối chiếu nếu cần.
- **Lý do.**
  - Mô hình client–server [T:V1] không khớp Phase 1; chế độ offline/cục bộ khớp hơn nhưng không phải sensor chạy liên tục [N].
  - AGPL-3.0 [T:V4]: không sao chép mã (ADN-007).
  - Nhiều CVE đã được vá ở 0.77.3 [T:V1]: nếu dùng thử phải dùng bản mới nhất và không mở ra ngoài mạng lab [N].
- **Phương án đã xem xét.** Dùng Velociraptor làm collector chính: cần server, chứng chỉ và đóng gói MSI [T:V2]; quá nặng cho Phase 1.
- **Xem xét lại nếu:** Phase 2 cần điều tra nhiều endpoint hoặc cần khả năng thu thập theo yêu cầu.

## ADN-007: Quy tắc license khi tham khảo

- **Quyết định.**
  1. Không sao chép mã, rule, decoder hay artifact từ Wazuh (GPLv2) và Velociraptor (AGPL-3.0) vào repo; chỉ lấy ý tưởng và ghi nguồn trong tài liệu.
  2. Không đưa binary Sysmon vào repo; dẫn link tải chính thức (Sysinternals, điều khoản [T:S2]).
  3. Nếu dùng cấu hình Sysmon cộng đồng (ví dụ bản ghi CC BY 4.0 [T:S4]) phải ghi công; mặc định nhóm viết config riêng.
  4. Với osquery chọn Apache-2.0 nếu cần dùng mã; với Invoke-AtomicRedTeam (MIT) giữ thông báo bản quyền.
- **Lý do.** Tránh ràng buộc copyleft lên mã của đồ án. Đây là nhận định kỹ thuật, không phải tư vấn pháp lý: hỏi giảng viên hướng dẫn khi cần dùng mã của các dự án này.

## ADN-008 (MỞ): Phiên bản Windows và hình thức cài Sysmon

- **Vấn đề.** Trang Sysmon ghi hỗ trợ client Windows 11 trở lên và Server 2019 trở lên [T:S1], trong khi tài liệu lab của nhóm ghi Windows 10/11. Sysmon cũng có thể bật như tính năng tích hợp của Windows 11 [T:S3] và không cùng tồn tại với bản standalone [T:S5].
- **Lựa chọn.** (a) VM Windows 11 + Sysmon standalone ghim phiên bản; (b) VM Windows 11 + bản tích hợp, cập nhật qua Windows Update; (c) giữ Windows 10, kiểm tra Sysmon chạy được hay không.
- **Đề xuất tạm.** (a): ghim phiên bản để mẫu và test tái lập được [N]. Cần chốt sau khi chạy thử U1 (file 01 mục 8).
- **Cần Data và Cyber xác nhận:** VM chung của team đang dùng bản Windows nào.

## Câu hỏi chờ review

| # | Câu hỏi | Gửi |
|---|---|---|
| R1 | Đồng ý phân loại Sử dụng / Tham khảo ở bảng tóm tắt? | Cyber, Data |
| R2 | Cyber duyệt tập con atomic test an toàn (sau khi có danh sách ở U4)? | Cyber |
| R3 | Sigma có được chấp nhận làm định dạng luật ở Phase 2 (C6)? | Cyber |
| R4 | Data có cần nhận log JSON từ nguồn khác Sysmon (ví dụ osquery) vào Silver? | Data |
| R5 | VM chung dùng Windows 10 hay 11 (ADN-008)? | Data, Cyber |

## Cập nhật sau W5

- **Không có quyết định nào ở ADN-001 đến ADN-007 thay đổi.** Căn cứ của các ADN này vẫn hoàn toàn là tài liệu; các thử nghiệm thư viện ở W5 chạy trên Linux và **không** được dùng làm căn cứ chọn công cụ cho môi trường Windows.
- **ADN-002 (Sysmon):** hợp đồng Bronze v1 ở W5 coi Sysmon là nguồn duy nhất của Phase 1, nên rủi ro về phiên bản Windows hỗ trợ ảnh hưởng trực tiếp tới pipeline.
- **ADN-008 vẫn MỞ:** theo dõi tiếp ở O-07 trong W5 file 05. Khi chọn xong bản Windows cho VM chung, ghi kết quả vào ADN-008 và `environment-log.md`.
- **Tập con atomic test (ADN-003):** vẫn chờ Cyber duyệt (R2).
