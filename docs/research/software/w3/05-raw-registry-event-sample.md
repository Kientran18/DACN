# Raw Registry Event Sample (Sysmon Event 12, 13, 14)

**Trạng thái: ĐÃ CÓ MẪU THẬT.** Xem [XML đã commit](../../../../references/samples/raw/raw_registry_setvalue_event13.xml) và [index](00-index-and-dod.md). Các bảng kiểm tra cần reviewer xác nhận; không coi placeholder bên dưới là dữ liệu. Dùng bước 4 của `run-poc-activities.ps1` (khóa an toàn `HKCU\Software\EDR_PoC`). File nguồn: `samples/raw/raw_registry_key_event12.xml`, `raw_registry_setvalue_event13.xml`.

## Mẫu thật – Event 12 (CreateKey / DeleteKey)
```xml
<!-- Xem file XML đã liên kết ở đầu trang; không sao chép mẫu giả vào đây.
```
## Mẫu thật – Event 13 (SetValue, chuỗi và DWORD)
```xml
<!-- Xem file XML đã liên kết ở đầu trang; không sao chép mẫu giả vào đây.
```

## Kiểm tra từng trường

| Trường | PoC / Silver | Có trong mẫu? | Ghi chú |
|---|---|---|---|
| EventType | `operation` | ☐ | Quan sát giá trị: CreateKey, DeleteKey, SetValue, DeleteValue? |
| TargetObject | `target_object`, `hive`, `key_path`, `value_name` | ☐ | HKCU có hiển thị `HKU\<SID>\...`? Đoạn cuối là tên value khi SetValue? |
| Details | `new_data_str`, `value_type_inferred` | ☐ | Chuỗi hiển thị thế nào; DWORD có dạng `DWORD (0x00000001)`? |
| Image, ProcessGuid | `image_path`, `process_guid` | ☐ | Image là `powershell.exe` |
| Giá trị cũ / mã trạng thái | `previous_data_*`, `status_code` | ☐ | Dự kiến **không có** |

## Thí nghiệm liên quan
- **E5:** xóa value và xóa key có sinh Event 12 với `EventType` nào?
- **E6:** `TargetObject` của HKCU có tiền tố `HKU\<SID>` không (ảnh hưởng cách viết rule Sysmon và regex của Cyber)?
- Tùy chọn: chạy lại với `-RunKeyTest` để có mẫu cho khóa `\CurrentVersion\Run` (DET-003).
