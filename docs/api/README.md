# API cục bộ DACN EDR (PH8)

> Trạng thái: MVP, chạy và kiểm thử trên Linux bằng dữ liệu synthetic. Đặc tả máy đọc được: [`openapi.json`](openapi.json) (sinh bằng `src/api/export_openapi.py`). Chưa chạy trên Windows; hiệu năng chưa đo.

## Chạy
```bash
python -m api.auth --role analyst --actor <tên>    # in token MỘT LẦN, lưu băm vào $EDR_HOME/api_tokens.json
python -m api --config edr.yaml                      # bind 127.0.0.1 (cấu hình từ chối host khác)
```
Mọi yêu cầu (trừ `GET /livez`) cần `Authorization: Bearer <token>`.

## Vai trò
| Vai trò | Quyền |
|---|---|
| viewer | đọc: health, endpoint, events, detections, alerts, evidence (không `raw_xml`), rules, response |
| analyst | viewer + đổi trạng thái alert, incident/ghi chú, yêu cầu response, xem `raw_xml` (có audit) |
| approver | analyst + duyệt/từ chối hành động response |
| responder | chỉ tiến trình responder: nhận (`claim`), báo kết quả, ghi audit EXEC_BEGIN/END |

`actor` luôn lấy từ token, không nhận từ nội dung yêu cầu.

## Endpoint chính

W07 bổ sung `/static/analyses`, `/static/candidates` (+ detail/history/transition), `/static/knowledge` (+ activate/rollback). Xem [request/response, phân quyền và lỗi W07](../research/software/w7/02-candidate-review-and-integration-api.md). Static file root do server ấn định tại `<EDR_HOME>/lab`, không nhận root từ HTTP; kết quả không tự response.

`/livez` (công khai) `/me` `/stats` `/health` `/endpoint` `/events` `/detections` `/alerts` `/alerts/{id}` `/alerts/{id}/history` `/alerts/{id}/transition` `/alerts/{id}/evidence` `/alerts/{id}/timeline` `/alerts/{id}/process-tree` `/coverage-gaps` `/incidents` (+ `/incidents/{id}/alerts`, `/incidents/{id}/notes`) `/rules` `/rules/{id}` `/response/actions` (+ `approve`, `reject`, `claim`, `result`) `/response/audit`.

Rủi ro tổng hợp (2026-11-25, **chỉ đọc**, vai trò có quyền `read`): `GET /risk/config` (phiên bản, sha256, giá trị cấu hình, ML bật/tắt), `GET /risk/subjects?kind=process|host&min_level=&limit=&offset=`, `GET /risk/process?hostname=&process_guid=`, `GET /risk/host?hostname=&until=` (cửa sổ theo thời gian dữ liệu), `GET /alerts/{id}/risk`. Kết quả gồm `score`, `level`, từng thành phần (cơ chế, nguồn, điểm gốc, trọng số, hệ số allowlist, lý do), `not_evaluated`, `data_gaps`, `triggers_response: false`. Trọng số là heuristic chưa hiệu chỉnh; điểm không kích hoạt response. Thiết kế: [`RISK_SCORING.md`](../implementation/RISK_SCORING.md).

Điều tra cây tiến trình (2026-11-26, **chỉ đọc**, quyền `read`: viewer/analyst/approver; responder 403). Mọi truy vấn lọc theo `hostname` và nối cha-con bằng ProcessGuid (không bằng PID); không trả `raw_data`; `since`/`until` phải có múi giờ.
- `GET /investigation/process-tree?hostname=&process_guid=&max_depth=1..20 (8)&max_nodes=1..500 (200)&since=&until=`: `nodes` phẳng (tổ tiên xa → gần, trọng tâm, con cháu theo BFS), mỗi nút có `status` (`OBSERVED`/`NO_DATA`), `role`, `depth`, trường Event 1 (image, command line, user, integrity, pid/ppid, `file_sha256`, `hashes`, `imphash`, `start_utc`), `end_utc` (Event 5), `event_counts` (file/registry/network/dns), `alerts` (`alert_id`, `rule_id`, `severity`, `status`), `children_truncated`. Nút `NO_DATA` chỉ có `parent_image`/`parent_command_line`/`pid_from_child` lấy từ Event 1 của con (`evidence_source`), các trường khác `null`. Cờ: `coverage_status` (`FULL`/`PARTIAL_ANCESTRY`/`NOT_FOUND`), `ancestors_truncated`, `descendants_truncated`, `node_limit_reached`. Cửa sổ thời gian chỉ lọc con cháu và số sự kiện.
- `GET /investigation/process-events?hostname=&process_guid=&kinds=process,file,registry,network,dns&since=&until=&limit=1..200&offset=`: timeline gộp các bảng Silver, có `category`, `summary`, `detail`, `has_more`.
- `GET /investigation/process-search?hostname=&image=&sha256=&limit=`: tìm Event 1 theo image (chứa chuỗi, không phân biệt hoa thường, escape ký tự đại diện) hoặc sha256 (64 hex). Cần ít nhất một trong hai.

Điểm rủi ro theo nút do dashboard lấy từ `/risk/subjects` và `/risk/process` (không tính thêm ở endpoint điều tra). raw_xml vẫn chỉ xem qua `/alerts/{id}/evidence?include_raw=true` (analyst trở lên, có audit).

`openapi.json` được sinh lại ngày 2026-11-26 (thêm `/investigation/*`); trước đó ngày 2026-11-25 (thêm `/static/*`).

`POST /response/actions` nhận `action_type` ∈ `TERMINATE_PROCESS`, `QUARANTINE_FILE`, `RESTORE_FILE`, `ADD_WHITELIST`, `REMOVE_WHITELIST` (khớp `ACTION_TYPES` của policy); policy vẫn kiểm mục tiêu ngay khi yêu cầu (`422 E-POLICY`).

## Lỗi
Mọi lỗi: `{"error": {"code": "E-...", "message": "..."}}` (401 `E-UNAUTHENTICATED`, 403 `E-FORBIDDEN`, 404 `E-NOT_FOUND`, 409 `E-INVALID_TRANSITION`/`E-INVALID_STATE`, 411 `E-LENGTH_REQUIRED` (POST/PUT/PATCH thiếu `Content-Length`), 413 `E-TOO_LARGE`, 422 `E-VALIDATION`/`E-POLICY`, 500 `E-INTERNAL`). Không lộ stack hay đường dẫn.

## Giới hạn đã biết
- Một khóa toàn cục quanh kết nối DuckDB; chưa đo tải. Giới hạn nội dung 64 KB dựa trên `Content-Length`.
- `/rules` chỉ đọc (đổi rule qua tệp YAML + kiểm tra, ngoài phạm vi MVP).
- Chưa có HTTPS (loopback), chưa có hết hạn token, chưa giới hạn tần suất. Thu hồi token: xóa dòng tương ứng trong tệp token; API nạp lại khi tệp đổi (không cần khởi động lại).
- Audit chỉ phát hiện sửa (chuỗi băm); API không có endpoint sửa/xóa audit.
