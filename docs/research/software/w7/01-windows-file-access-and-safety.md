# W07 Windows File Access & Safety Notes

**Implemented:** file reference root guard, same-handle read, hash/size/byte entropy, minimal PE COFF, literal pattern matching; structured error, byte/time budgets. **Designed:** optional offline digital-signature provider, forensic snapshot, cache mở rộng. **Future:** signed update distribution, Windows service/driver protection.

Không cài hoặc chạy file đang phân tích. PE được đọc như bytes; không LoadLibrary/ShellExecute. Chỉ phục vụ absolute path trong root lab do operator kiểm soát; không network share/ADS/device path. Không ghi bytes, path máy thật, username hay token vào public evidence.

| Tình huống | Expected | Test |
|---|---|---|
| File missing/deleted | NOT_FOUND, features null | test_file_access_errors |
| File share locked / thiếu quyền | ACCESS_DENIED_OR_LOCKED, không retry vô hạn | PermissionError simulated; cần Windows VM lock thật |
| Quá max bytes / tăng khi đọc | TOO_LARGE, partial hash bị bỏ | known-size và loop guard |
| Hết thời gian | TIMEOUT, không kết luận benign | monotonic clock simulated |
| Thay file giữa stat/open/read | FILE_CHANGED hoặc safe I/O error | changing-during-read fixture |
| Symlink/reparse, UNC/ADS | reject trước đọc | symlink test có thể skip nếu không có quyền Windows |
| Hash telemetry khác current bytes | HASH_MISMATCH; INSUFFICIENT | workflow nguồn Silver |
| Non-PE / malformed header | NOT_PE/MALFORMED/UNAVAILABLE_HEADER riêng | benign synthetic header |
| Không có signature provider | UNAVAILABLE; không tự gán unsigned/trusted | output schema + extractor test |

Một handle và metadata checks chỉ giảm race trong lab có ACL, không chống admin sửa bytes rồi khôi phục metadata. Mtime không phải cryptographic identity; `historical_identity=HASH_VERIFIED` chỉ khi hash nguồn khớp, không nhận đã có bản sao raw file lịch sử. File đã xóa không thể khôi phục từ Event26 nếu không có archive thật.

Timeout hiện là deadline hợp tác kiểm tra giữa các chunk, không hủy được system call đọc đang bị driver/filesystem treo. Root phải là thư mục local được operator kiểm soát; hard deadline cần worker process có timeout và admission control trong triển khai tiếp theo. Không dùng API này để quét toàn ổ đĩa hoặc tự quét mọi Sysmon file event.

Giới hạn PoC 16MiB/5s và prefix64KiB là cấu hình bảo vệ tài nguyên, chưa đo CPU/RAM/latency trên Windows10 VirtualBox. Đo thực tế phải ghi Windows build, Python/dependencies, Sysmon, VM CPU/RAM, input hash, quyền và expected/observed. Không dùng host tests với fixture để nhận live Sysmon VM đã đạt.

Nguồn đã đối chiếu ngày 17/11/2026: [Microsoft PE/COFF format](https://learn.microsoft.com/en-us/windows/win32/debug/pe-format), [Python 3.12 stat_result và Windows timestamp](https://docs.python.org/3.12/library/os.html#os.stat_result). Timestamp COFF chỉ là metadata nguồn, không bằng chứng ngày build đáng tin; metadata PE không thay xác minh trust của chữ ký.
