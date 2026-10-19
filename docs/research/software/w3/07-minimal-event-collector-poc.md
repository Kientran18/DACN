# Minimal Event Collector PoC

> **Cập nhật 2026-10-19:** Đã có mẫu thật và kết quả file mode; thông tin chưa chạy/chưa cài bên dưới là ghi chú lịch sử trước lần lab. Trạng thái hiện hành và đường dẫn tái lập ở [index](00-index-and-dod.md). Python live mode vẫn chưa có bằng chứng. Không diễn giải mọi lệnh hướng dẫn là đã thử thành công.


**Code:** `poc/sysmon_collector_poc.py` · **Test:** `poc/test_sysmon_collector_poc.py` · **Dữ liệu test:** `poc/fixtures/synthetic_events.xml` (giả lập, không phải mẫu thật)

## 1. Chức năng

| Chế độ | Nguồn | Trạng thái |
|---|---|---|
| `--mode file` | XML xuất bằng `wevtutil` / `Get-WinEvent` (các phần tử `<Event>` không có root) | Đã test bằng sự kiện giả lập |
| `--mode live` | Kênh `Microsoft-Windows-Sysmon/Operational` qua `pywin32` (`EvtQuery`, `EvtNext`, `EvtRender`), mới nhất trước | **Chưa chạy trên Windows** |

Chuẩn hóa 11 loại sự kiện (1, 3, 4, 5, 11, 12/13/14, 15, 16, 22, 23/26, 29); bản đồ trường chi tiết dành cho Event 1, 3, 11/26/29, 12/13/14, 22. Đầu ra: JSON (mảng) hoặc JSONL.

## 2. Cách dùng

```powershell
# Từ mẫu đã xuất (không cần quyền đặc biệt)
python poc\sysmon_collector_poc.py --mode file --input samples\raw\recent_events_all.xml --event-id 1 --max 20 --output samples\json\process_events.json

# Đọc trực tiếp (Administrator, cần: pip install pywin32)
python poc\sysmon_collector_poc.py --mode live --event-id 1 --event-id 3 --max 20 --output samples\json\live_events.json

# Chạy test
cd poc; python -m pytest -q
```

## 3. Quyết định thiết kế

| Quyết định | Lý do / điểm chờ xác nhận |
|---|---|
| `event_id` = UUIDv5 từ `(computer, channel, record_id)` | Xuất lại cùng sự kiện luôn cho cùng ID (chống trùng). Spec của Data ghi ULID/UUIDv4: cần Data chấp nhận (Q-X3) |
| `timestamp` = `TimeCreated/@SystemTime` (UTC, 100 ns) giữ nguyên chuỗi | Gần yêu cầu nanosecond hơn `UtcTime` (mili-giây) |
| `process_guid` bỏ `{}`, giữ nguyên chữ hoa/thường | Khớp cách Data mô tả; cần dùng cùng một hàm ở mọi bảng |
| `source` = `SYSMON`; `event_type` theo tên envelope của Data (`PROCESS_START`...) | Enum của Data chưa có `SYSMON` và Cyber dùng tên khác (Q-X3, file 02 Week 2 mục H) |
| Giữ `raw_data` nguyên bản | Không mất trường khi Silver chưa có cột (Q-D6) |
| `direction`, `value_type_inferred`, `hive/key_path/value_name` là suy luận | Sysmon không cung cấp trực tiếp; dùng quy tắc đã nêu ở file 02 Week 2 |

## 4. Kết quả kiểm thử

`13 passed` (pytest, môi trường Linux, **dữ liệu giả lập**): đọc nhiều `<Event>` không root, parse hash/GUID, ánh xạ Event 1/3/11/13, `event_id` ổn định, giữ `raw_data`, suy luận kiểu registry, xuất JSON/JSONL, thông báo rõ khi thiếu `pywin32`.

Điều test này **không** chứng minh: chạy live trên Windows, mã hóa file từ PowerShell (`Out-File` mặc định UTF-16; collector đã xử lý cả UTF-16 và UTF-8 BOM nhưng chưa thử thật), và việc các trường thật khớp với giả định.

## 5. Giới hạn của PoC

Không có bookmark (khởi động lại sẽ đọc lại từ mới nhất), không có chế độ theo dõi liên tục (`EvtSubscribe`), không làm giàu dữ liệu (`token_elevation_type`, kích thước file...), không ghi vào Bronze/DuckDB, `host_id` và `host_context` chưa có.

## 6. Bước tiếp theo

1. Chạy live trên VM và sửa lỗi phát sinh.
2. Chuyển sang `EvtSubscribe` + bookmark (TR-01), phát sự kiện `telemetry_dropped_events_total` khi `EventRecordID` đứt quãng.
3. Tích hợp với `pipeline/ingestion/collector.py` của Data: thống nhất ai sở hữu code thu thập để tránh hai bản song song.
4. Cập nhật bản đồ trường theo mẫu thật.
