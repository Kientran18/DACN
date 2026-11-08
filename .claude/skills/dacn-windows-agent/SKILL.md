---
name: dacn-windows-agent
description: Thiết kế và phát triển Windows Endpoint Agent hay collector runtime của DACN. Tự dùng khi bàn về service, vòng đời collector, đọc Event Log bằng EvtNext hoặc EvtSubscribe, bookmark, checkpoint, batching, retry, backpressure, quyền tối thiểu, CPU và RAM trên Windows 10/11. Không tự cài service hay đổi cấu hình Windows. Kiểm thử trên Windows VM thuộc dacn-windows-integration-test.
---

# Windows Endpoint Agent (collector runtime)

## Hiện trạng cần nắm (xác minh lại bằng code)
- `poc/sysmon-collector/sysmon_collector_poc.py`: file mode chạy được; `iter_events_live` dùng `win32evtlog.EvtQuery` + `EvtNext`, đọc **newest-first, tối đa N sự kiện**, đây **không phải** subscription liên tục. Live mode chưa chứng minh trên Windows thật (`CLAUDE.md` mục 3.1).
- Chưa có: service chạy liên tục, bookmark/checkpoint bền, sealed segment writer, manifest, replay (kiến trúc v2 mục 10).

## Đọc trước
`docs/research/software/w5/04-error-recovery-and-operational-notes.md` (giao thức checkpoint at-least-once, ma trận lỗi C-001..C-006), `01-collector-to-bronze-interface-contract-v1.md`, `03-local-storage-and-pipeline-integration-design.md`, `docs/architecture/local-edr-reference-architecture-v2.md` mục 5.2, 8, 9; `poc/sysmon-collector/bronze_contract.py`; `docs/research/software/w1/05-windows-lab-environment.md`.

## Quy trình thiết kế/phát triển
1. **Xác định nguồn:** Sysmon là nguồn chính; Security/System log chỉ khi được bật audit đúng; ETW/WMI là hướng nghiên cứu. Collector chỉ đọc và đóng gói, không suy diễn threat.
2. **Chọn cơ chế đọc:** pull (`EvtNext` theo lô, tự điều tiết) hoặc `EvtSubscribe` có bookmark. Tên hàm `pywin32` về bookmark ghi nhận là **chưa kiểm chứng trên VM**; kiểm tra trước khi viết code phụ thuộc chúng.
3. **Thứ tự ghi bền theo tài liệu:** đọc lô → dựng bản ghi `bronze-event/1.0` → ghi `.part` + flush/`fsync` → mới cập nhật bookmark → seal segment (manifest, hash). Chết trước bước cập nhật bookmark thì đọc lại và dedup nhờ `event_id` xác định.
4. **Lỗi và phục hồi:** dùng mã lỗi hiện có (C-001 XML, C-002 thiếu System field, C-003 giải mã, C-004 ghi đĩa, C-005 bookmark/stale, C-006 access denied). Lỗi tạm thời: retry backoff có giới hạn; lỗi vĩnh viễn: quarantine và tiếp tục. Không âm thầm bỏ sự kiện.
5. **Backpressure và tài nguyên:** hàng đợi có giới hạn; khi đầy dừng đọc (sự kiện vẫn nằm trong Event Log, cần theo dõi nguy cơ ghi đè do kích thước channel). Ngưỡng CPU/RAM/IO **chỉ đặt sau khi đo trên VM**; không ghi con số không có đo đạc.
6. **Cấu hình:** có schema, kiểm tra hợp lệ, thay đổi nguyên tử, không nhận cấu hình từ nguồn không xác thực.
7. **Quyền tối thiểu:** đọc channel `Microsoft-Windows-Sysmon/Operational` (thường cần Administrator hoặc quyền đọc log), ghi vào thư mục dữ liệu riêng. Tách quyền response khỏi collector. Ghi rõ quyền nào cần và lý do.
8. **Hành vi khi dừng/khởi động lại:** tín hiệu dừng → seal và lưu bookmark; chết đột ngột → cắt dòng dở dang, quarantine phần hỏng; giờ hệ thống đổi → dựa `record_id`, không dựa đồng hồ.

## Nguyên tắc không được vi phạm
- Không tự cài/gỡ service, không sửa Sysmon config, Defender, Audit Policy, ACL hay registry trên máy. Chỉ viết script/hướng dẫn cho người dùng tự chạy, nêu rõ tác động và cách hoàn tác.
- Không đổi event identity, `bronze-event/1.0`, UUIDv5; thêm `channel_epoch` chỉ là đề xuất P0 cần review liên nhóm (kiến trúc v2 mục 5.2).
- Không tuyên bố live mode, delivery guarantee hay hiệu năng khi chưa chạy trên Windows thật và chưa có số đo.
- Dùng mẫu synthetic hoặc mẫu lab; phân biệt rõ khi báo cáo (xem `dacn-sysmon-telemetry`).

## Kiểm tra kết quả
Test logic thuần (parser, rotation, checkpoint ordering, cắt dòng dở) chạy được trên Linux bằng pytest với dependency injection thay `win32evtlog`; phần phụ thuộc Windows ghi rõ "chưa kiểm chứng" và chuyển sang `dacn-windows-integration-test`.

## Đầu ra
Thiết kế hoặc patch theo yêu cầu cụ thể, kèm: bảng quyền cần thiết, ma trận lỗi → hành vi, danh sách giả định chưa kiểm chứng trên Windows, hướng dẫn cho người dùng chạy trên VM.

## Cần hỏi người dùng
Trước khi: thêm dependency (`pywin32` đã được dùng, thư viện mới thì hỏi), đổi cấu trúc thư mục dữ liệu, thêm process/service mới, đổi giao diện collector–pipeline (ảnh hưởng Data).

## Phối hợp với skill khác
- Trước đó: dacn-edr-architecture
- Cùng lúc: dacn-sysmon-telemetry, test-driven-development
- Sau đó: dacn-windows-integration-test, dacn-performance-reliability
