---
name: dacn-sysmon-telemetry
description: Sysmon và telemetry Windows trong DACN. Tự dùng khi làm việc với sysmon_collector_poc, Sysmon Event ID, raw XML và EventData, mapping process, file, registry, network, DNS, normalization, kiểm thử file mode trên mọi hệ điều hành. Đọc mapping thật, không đoán field, không nói live mode chạy nếu chưa kiểm chứng trên Windows. Không dùng cho kế hoạch kiểm thử trên Windows VM (dacn-windows-integration-test).
---

# Sysmon telemetry cho DACN

Hỗ trợ phát triển và kiểm thử `poc/sysmon-collector/`. Mọi khẳng định về field, Event ID hay mapping phải dựa trên **file trong repository**, đọc tại thời điểm làm việc.

## Quy tắc

1. **Đọc mapping thật, không suy đoán.** Trước khi nói một Sysmon Event ID có field nào, đọc `_map_data`, `STATIC_EVENT_TYPES`, `REGISTRY_TYPES`, `_event_type` trong `poc/sysmon-collector/sysmon_collector_poc.py` và mẫu trong `references/samples/raw/`. Field không có trong mẫu hoặc mapping thì ghi "không có bằng chứng trong repository", không tự thêm vào code, test hay tài liệu (Zero Data Fabrication).
2. **Phân biệt nguồn dữ liệu** trong mọi báo cáo:
   - *Synthetic*: `poc/sysmon-collector/configs/synthetic_events.xml`, `docs/architecture/w5/contracts/examples/synthetic_process_event1.xml` - do con người viết, **không phải telemetry thu thập**.
   - *Mẫu lab/export*: `references/samples/` - theo README và `CLAUDE.md`, xuất từ máy lab; vẫn chưa khử định danh hoàn toàn.
   - *Live*: dữ liệu đọc trực tiếp bằng `win32evtlog` trên Windows. **Hiện chưa có bằng chứng đã chạy.**
3. **Không tuyên bố live mode hoạt động** (`--mode live`, `pywin32`, quyền Administrator) khi chưa có kết quả chạy trên Windows thực. Trên Linux, chỉ file mode kiểm thử được. Nếu người dùng cung cấp kết quả chạy trên Windows, ghi lại: máy (không ghi tên thật), phiên bản Windows/Sysmon, lệnh, thời điểm, kết quả.
4. Không chạy live mode, không cài `pywin32`, không cài hay thay đổi Sysmon/cấu hình hệ thống, không chạy `run-poc-activities.ps1` hoặc `export-samples.ps1` (script tạo hoạt động/xuất log trên máy). Chỉ đọc chúng để hiểu. Chạy trên Windows là việc người dùng tự làm.
5. Không đổi event identity, UUIDv5, schema hay field mapping khi chưa được phê duyệt; dùng skill `dacn-contract-review` để đánh giá tác động.
6. Không sao chép tên máy/người dùng trong mẫu vào tài liệu, báo cáo hay commit message.

## Kiến thức nền (đã xác minh từ code hiện tại; đọc lại nếu nghi ngờ)

**Kênh**: `Microsoft-Windows-Sysmon/Operational` (`SYSMON_CHANNEL`).

**Raw XML**: `<Event>` có `System` (`EventID`, `EventRecordID`, `Channel`, `Computer`, `TimeCreated/@SystemTime`, `Provider`, ...) và `EventData` (các `Data Name=...`). Collector parse bằng `parse_event_xml` / `_parse_event_element`.

**Nhóm sự kiện** (theo mapping hiện có):

| Nhóm | Sysmon Event ID | Ghi chú |
|---|---|---|
| Process | 1 (Create), 5 (Terminate) | Validator Silver nhóm process `{1,5}` |
| File | 11, 15, 23, 26, 29 | Collector map 23 và 26 cùng `FILE_DELETE` |
| Registry | 12, 13, 14 | `event_type` suy ra từ `EventData.EventType` |
| Network | 3 (Connect/Accept), 22 (DNS) | 3 phân biệt bằng `Initiated`; Silver nhóm network `{3,22}` |
| Trạng thái Sysmon | 4, 16 | Collector có map; validator hiện **không** có trong `SUPPORTED_SYSMON_IDS` |

**Sinh định danh**: `event_id = uuid5(EVENT_ID_NAMESPACE, "Computer|Channel|EventRecordID")`; `process_guid` được `strip_guid` bỏ ngoặc nhọn (ADR 0002).

**Hai bộ tên event type** (collector và validator) chưa thống nhất (Q-X3); đừng giả định chúng khớp.

## Quy trình phát triển/kiểm thử collector

1. Đọc `README.md`, ADR 0001–0003, `docs/architecture/w5/contracts/README.md` và issue liên quan.
2. Xác định Event ID và field cần dùng; mở mẫu XML tương ứng trong `references/samples/raw/` (và `w5_negative_and_edge_samples.md` cho trường hợp biên/âm tính). Chưa có mẫu thật cho field cần thiết thì dừng và báo cáo thiếu mẫu, không bịa.
3. Viết test trước (skill `test-driven-development`) trong `poc/sysmon-collector/test_*.py`; dùng fixture hiện có hoặc synthetic được gắn nhãn rõ.
4. Cài đặt tối thiểu, giữ `raw_data`/`event_data` nguyên bản.
5. Chạy kiểm thử từ thư mục gốc repository (import dùng tên module trần, xem `CLAUDE.md` mục 5):

```bash
python -m pytest -q poc/sysmon-collector
python -m pytest -q tests/
```

6. Chạy thử file mode ghi ra ngoài repository:

```bash
python poc/sysmon-collector/sysmon_collector_poc.py --mode file \
  --input references/samples/raw/raw_process_create_event1.xml --output /tmp/out.json
```

7. Báo cáo kết quả kèm lệnh và thời điểm, ghi rõ "file mode, dữ liệu mẫu/synthetic".

## Kiểm thử theo vùng

- **Parse**: XML sai cấu trúc (mã `C-001`), thiếu trường `System` (mã `C-002`), EventData rỗng, ký tự đặc biệt/Unicode trong đường dẫn và command line.
- **Normalization**: kiểu số (`ProcessId`, cổng), `Hashes` (`parse_hashes`), `Initiated` và `DestinationIsIpv6`, tách key/value registry, trích extension file.
- **Identity**: cùng input cho cùng `event_id`; khác `Computer|Channel|EventRecordID` cho `event_id` khác.
- **Validation**: bản ghi thiếu field bắt buộc phải vào quarantine với mã `ERR_*`, không được điền mặc định.
- **Bất biến Zero Data Fabrication**: field vắng trong XML phải vắng (hoặc `None` theo đúng hành vi hiện tại) ở đầu ra.

## Việc chưa được chứng minh (không được tuyên bố đã làm)

Theo `CLAUDE.md` mục 3.1: live mode trên Windows thật; collector chạy liên tục (service), bookmark, checkpoint, delivery guarantee; segment sealing, manifest, replay end-to-end. Khi báo cáo, liệt kê những mục này là *chưa kiểm chứng* nếu công việc có liên quan.

## Hướng dẫn cho người dùng chạy trên Windows (để họ tự thực hiện, Claude không chạy)

Chỉ đưa ra khi người dùng cần kiểm chứng live mode; phải nêu rõ cần Windows, Sysmon đã cài, `pywin32` và quyền Administrator, và kết quả chỉ có giá trị khi người dùng gửi lại đầu ra thật. Ví dụ lệnh (tham số theo `main()` hiện tại):

```bash
python poc/sysmon-collector/sysmon_collector_poc.py --mode live --max 20 --output out_live.json
```

## Mẫu báo cáo

```markdown
## Phạm vi (Event ID, module)
## Nguồn dữ liệu đã dùng (synthetic / mẫu lab / live: ghi rõ)
## Mapping đã đối chiếu (file:dòng)
## Test đã chạy (lệnh, thời điểm, kết quả)
## Chưa kiểm chứng (live mode, service, bookmark...)
```

## Phối hợp với skill khác
- Trước đó: dacn-contract-review khi đổi mapping
- Cùng lúc: test-driven-development
- Sau đó: dacn-windows-integration-test (phần cần Windows thật)
