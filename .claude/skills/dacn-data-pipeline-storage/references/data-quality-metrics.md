# Chỉ số chất lượng và quan sát dữ liệu (tham chiếu)

Nguồn trong repository: `docs/architecture/w5/validation_quality_lineage_and_governance_v1.md` (mục 3.2, 4.1, 5, 6), `docs/research/software/w5/04-error-recovery-and-operational-notes.md` (mục 5), `docs/architecture/local-edr-reference-architecture-v2.md` (mục 8.2). Các ngưỡng bên dưới là **mục tiêu đề xuất trong tài liệu**, chưa được đo; đọc lại tài liệu gốc trước khi dùng.

## Sáu chiều chất lượng
| Chiều | Cách đo | Lưu ý |
|---|---|---|
| Completeness | bản ghi đủ field bắt buộc ÷ tổng bản ghi đầu vào | "bắt buộc" phụ thuộc loại sự kiện |
| Validity | đúng kiểu, miền giá trị, regex UUID/IP ÷ tổng | |
| Uniqueness | `COUNT(DISTINCT event_id)` ÷ `COUNT(*)` theo từng bảng Silver | phải bằng 100% nhờ khóa chính |
| Consistency | sự kiện File/Registry/Network có `process_guid` khớp bảng Process ÷ tổng | thiếu khi collector khởi động muộn là bình thường, phải ghi nhận chứ không sửa |
| Timeliness | `ingest_timestamp − timestamp` (trung vị, p95) | chỉ có nghĩa khi chạy stream |
| Quarantine ratio | bản ghi vào DLQ ÷ bản ghi đọc từ Bronze | tách theo `error_code` |

## Chỉ số vận hành bổ sung
- **Time skew:** chênh `System.TimeCreated` và `EventData.UtcTime` (validator đếm khi lệch quá 5 giây; tài liệu W05 ghi nhận mẫu lab lệch cỡ chục giây). Cửa sổ correlation không được giả định chính xác theo vài giây khi chưa đo.
- **Event loss:** so khoảng trống `record_id` liên tiếp theo channel; khoảng trống có thể do bộ lọc Sysmon hoặc ghi đè log, chưa chắc là mất dữ liệu của pipeline. Cần đối chiếu số đã đọc, đã seal, đã nạp Silver, đã quarantine; chúng phải cộng lại khớp.
- **Duplicate rate:** `duplicates_dropped` trên tổng; tăng đột biến sau restart là bình thường theo giao thức at-least-once, tăng không lý do là cảnh báo.
- **Ingestion latency, lag:** tuổi sự kiện cũ nhất chưa đọc, thời lượng batch, thời lượng insert.
- **Schema compatibility:** `schema_version` lạ → V-001; `mapping_version` đổi → reprocess từ Bronze.
- **Tài nguyên:** dung lượng trống, kích thước từng thư mục, file DuckDB.

## Quy tắc báo cáo
1. Mỗi số đi kèm: lệnh hoặc truy vấn, dữ liệu đầu vào (đường dẫn, nhãn synthetic/lab/live), thời điểm.
2. Không nêu SLO "đạt" khi chưa đo; không suy ra tỷ lệ từ mẫu nhỏ synthetic cho cả hệ thống.
3. Health alert (thiếu dữ liệu, đầy đĩa) khác threat alert; mất heartbeat chỉ chứng minh khoảng trống tầm nhìn, không chứng minh tamper.
4. Chỉ số chỉ đọc dữ liệu có sẵn; không tạo dữ liệu để chỉ số đẹp.
