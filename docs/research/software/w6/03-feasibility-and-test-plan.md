# W06 Windows integration feasibility & test plan

Designed; kết quả chạy thực tế nằm trong [hồ sơ #40](../w7/03-issue-40-handoff-and-review.md).

| Rủi ro | Cách xử lý / cách kiểm |
|---|---|
| pywin32/Python ABI, Event Log quyền đọc | Khóa runtime sau khi thử VM; verify_windows_env; không coi API giả là live Sysmon |
| DuckDB embedded locking | Core+API+Static cùng connection/RLock; agent chỉ Bronze; test reader khi ingest và crash/restart trên VM |
| Memory/CPU | Bounded static chunks/prefix; 16MiB/5s; pending chains có thể tăng bộ nhớ khi source time dừng, cần quota ở phase runtime |
| Source/ingest time skew | SystemTime clock, host watermark, separate UtcTime; test host khác, late delete, grace, clock regression |
| Python dependencies | requirements chưa ghim, môi trường riêng; ghi versions trong test report, không đổi stack để che lỗi baseline |
| Logging/permissions | Metadata/reason_code; không log file bytes/command line/token; lab root read-only; review API role |
| Crash publish | W06 evaluation/cursor/outbox atomic; alert+ack atomic, metadata rule đóng băng; W07 alert+candidate transaction có rollback test |

## Test matrix

- Existing fixture DET-001/003: positive, benign, missing; DET-010: full/pending/closed/wrong order/path/device.
- `test_issue40_correlation.py`: host khác không đóng window, late source-time sửa closed partial thành MATCH, replay không thêm evaluation, lifetime/parent khác host không join.
- Synthetic XML/JSON và W03 samples dùng nội bộ. Mẫu thật chưa khử định danh không sao chép vào báo cáo/public example.
- W07 tests: hash/size/entropy oracle, minimal PE, missing/large/denied/changed file, chunk-boundary pattern, expiry/rollback/corrupt package, API role/CAS/audit/transaction và static không tự response.

Lệnh từ repo root:

```powershell
python -m pytest -q poc/sysmon-collector tests/detection tests/alerts tests/static_analysis tests/api
python -m pytest -q
```

**Windows 10 VirtualBox còn cần:** verify Python/Sysmon/pywin32; chạy file lab benign với normal/admin để kiểm quyền; locked-file share mode, reparse/UNC/ADS, signature provider nếu được chọn; Sysmon → Silver → Detection → Alert → raw; đo CPU/RAM/duration có input hash và versions. Không tự chạy response thật, thay cấu hình Sysmon hoặc tấn công lab trong #40.
