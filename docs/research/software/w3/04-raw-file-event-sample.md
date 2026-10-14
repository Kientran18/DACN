# Raw File Event Sample (Sysmon Event 11, 26, 29, 15)

**Trạng thái: CHƯA THU THẬP.** Dùng bước 3 của `run-poc-activities.ps1`. File nguồn: `samples/raw/raw_file_create_event11.xml`, `raw_file_delete_event26.xml`, `raw_file_executable_event29.xml`.

## Mẫu thật – Event 11 (dán vào đây)
```xml
<!-- PASTE REAL SYSMON EVENT 11 HERE -->
```
## Mẫu thật – Event 26
```xml
<!-- PASTE REAL SYSMON EVENT 26 HERE -->
```
## Mẫu thật – Event 29 (`_drop.exe`)
```xml
<!-- PASTE REAL SYSMON EVENT 29 HERE (or note that it did not appear) -->
```

## Kiểm tra từng trường

| Trường | PoC / Silver | Có trong mẫu? | Ghi chú |
|---|---|---|---|
| ProcessGuid, Image | `process_guid`, `image_path` | ☐ | |
| TargetFilename | `file_path` (`file_extension` suy ra) | ☐ | Đường dẫn dạng thật của `%TEMP%` |
| CreationUtcTime | — | ☐ | |
| Hash trong Event 11 | `file_sha256` | ☐ | Dự kiến **không có** |
| Hashes, IsExecutable, Archived trong Event 26/29 | `file_sha256`, `is_executable` | ☐ | Event 26 có `Hashes` không? Event 29 có không? |
| Kích thước file, số byte | `file_size_bytes`, `byte_delta` | ☐ | Dự kiến **không có** |

## Thí nghiệm liên quan (kết quả ghi ở file 09)
- **E1:** ghi đè file (`Set-Content` lên file có sẵn) có sinh Event 11 không?
- **E2:** nối thêm (`Add-Content`) có sinh Event 11 không?
- **E3:** `Rename-Item` có sinh sự kiện nào không? (dự kiến: không; quyết định tính khả thi của DET-008, Q-C1)
- **E8:** sao chép file thực thi vào Temp có sinh Event 29 không, và Event 11 có xuất hiện cho cả file `.exe` và `.txt` không?
