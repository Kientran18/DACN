# EDR — Hướng dẫn sử dụng (PH12-T02)

> Trạng thái: viết từ hành vi đã kiểm thử trên Linux. Các bước ghi **[W]** chưa được kiểm chứng trên Windows. Cài đặt và gỡ cài đặt: [../EDR_INSTALL_GUIDE.md](../EDR_INSTALL_GUIDE.md). Kịch bản lab an toàn: [../EDR_DEMO_PLAN.md](../EDR_DEMO_PLAN.md).

## 1. Nguyên tắc an toàn

- Chỉ chạy trên VM lab có snapshot `clean`. Không tắt Windows Defender.
- Response mặc định **`dry-run`**: chỉ ghi kế hoạch, không đổi hệ thống. `execute` cần **hai** khóa do bạn tự đặt trong `config/response-policy.yaml` (`mode: execute` và `execute_unlocked: true`) và chỉ nhắm tiến trình/tệp mang marker lab trong thư mục lab.
- Auto-response tắt mặc định. Block hash chỉ là phát hiện, không chặn thực thi (mã auto-response và block-hash nằm ở `experimental/`, không nằm trong `src/response/`). Quy tắc hai người (`require_distinct_approver`) mặc định BẬT: demo một người dùng phải đặt `false` trong `config/response-policy.yaml`.
- API chỉ lắng nghe loopback; token lưu dạng hash.

## 2. Khởi động và dừng

Dùng `edr_ctl` (cú pháp và biến môi trường chi tiết trong hướng dẫn cài đặt):

```bash
python -m edr_ctl start --config <edr.yaml>
python -m edr_ctl status --config <edr.yaml>
python -m edr_ctl logs --config <edr.yaml>
python -m edr_ctl stop --config <edr.yaml>
```

Mở `http://127.0.0.1:<cổng>/ui`, dán token. Token tạo bằng `python -m api.auth --config <edr.yaml> --role <vai trò> --actor <tên>`; token chỉ hiện một lần.

## 3. Vai trò

| Vai trò | Được làm |
|---|---|
| viewer | Xem dữ liệu, alert, rule |
| analyst | Như viewer + đổi trạng thái alert, ghi chú, incident, yêu cầu response, xem raw_xml (có audit) |
| approver | Duyệt/từ chối hành động response |
| responder | Chỉ dành cho tiến trình responder: nhận hành động đã duyệt và báo kết quả; không đọc dữ liệu |

## 4. Quy trình điều tra

1. **Overview:** kiểm tra agent/core còn sống. Nếu có biểu ngữ **DỮ LIỆU MẪU** thì dữ liệu là synthetic, không phải telemetry thật.
2. **Alerts:** lọc theo trạng thái; mở chi tiết để xem rule, phiên bản rule, severity và lý do, MITRE (chỉ khi có căn cứ).
3. **Bằng chứng:** từ alert tới `event_id` Silver rồi Bronze (segment, số dòng) và `raw_xml`. Trạng thái bằng chứng: `FULL`, `PARTIAL`, `RAW_EXPIRED`, `NO_LINEAGE`, `SEGMENT_INVALID`. Chỉ `FULL` mới xác minh được hash đầy đủ.
4. **Timeline và cây tiến trình:** tổ tiên thiếu hoặc lệch giờ được đánh dấu, không suy diễn.
5. **Trạng thái:** NEW → TRIAGED → INVESTIGATING → FALSE_POSITIVE | CONFIRMED | CLOSED; chuyển sai bị từ chối; mọi thay đổi được ghi vào audit.
6. **Coverage gaps:** kết quả `INSUFFICIENT_TELEMETRY` nghĩa là *thiếu dữ liệu để kết luận*, không phải an toàn và không phải đe dọa.
7. **Events và Rules:** tra cứu sự kiện Silver có lọc/phân trang; xem rule (chỉ đọc).

## 5. Response

1. Analyst tạo yêu cầu (từ chi tiết alert hoặc trang Response): loại `TERMINATE_PROCESS`, `QUARANTINE_FILE` hoặc `RESTORE_FILE`.
2. Approver duyệt hoặc từ chối (từ chối cần lý do).
3. Ở `dry_run`, kết quả là kế hoạch. Ở `execute`, responder xác minh lại danh tính tiến trình (PID, thời điểm tạo, đường dẫn ảnh) và từ chối nếu không khớp, nếu thuộc danh sách bảo vệ, hoặc nếu nằm ngoài thư mục lab.
4. Quarantine giữ tệp cùng sha256, không xóa vĩnh viễn; restore không ghi đè và kiểm hash.
5. Mọi bước trước/sau thực thi nằm trong audit; kiểm tra tính toàn vẹn chuỗi audit qua `/response/audit`.

**Allowlist:** `ADD_WHITELIST`/`REMOVE_WHITELIST` (theo SHA-256) đi qua cùng quy trình yêu cầu → duyệt → thực thi như các hành động khác; thao tác này làm hash đó không còn bị phát hiện nên cần lý do (≥ 5 ký tự) và có thể hoàn tác bằng `REMOVE_WHITELIST`. Chưa chạy trên Windows.

## 6. Sự cố thường gặp

| Hiện tượng | Hướng xử lý |
|---|---|
| Dashboard báo "Token không hợp lệ" | Tạo token mới; kiểm tra vai trò |
| Agent báo `C-006` | Tài khoản chạy agent không có quyền đọc channel Sysmon **[W]** |
| Segment bị quarantine | Segment sai hash/manifest; dữ liệu gốc còn trong `bronze/`, không bị xóa |
| `stop` không dừng | Dùng `--force` (chỉ ép kết thúc tiến trình đã xác minh đúng) |
| Alert "PARTIAL" bằng chứng | Bronze bị thiếu/hết hạn hoặc bị sửa; không tin raw_xml đó |
