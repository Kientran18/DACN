# Raw Network Event Sample (Sysmon Event 3, 22)

**Trạng thái: ĐÃ CÓ MẪU THẬT.** Xem [XML đã commit](../../../../references/samples/raw/raw_network_connect_event3.xml) và [index](00-index-and-dod.md). Các bảng kiểm tra cần reviewer xác nhận; không coi placeholder bên dưới là dữ liệu. Dùng bước 5 của `run-poc-activities.ps1` (HTTPS tới `example.com`, cần Internet). File nguồn: `samples/raw/raw_network_connect_event3.xml`, `raw_dns_query_event22.xml`.

## Mẫu thật – Event 3
```xml
<!-- Xem file XML đã liên kết ở đầu trang; không sao chép mẫu giả vào đây.
```
## Mẫu thật – Event 22
```xml
<!-- Xem file XML đã liên kết ở đầu trang; không sao chép mẫu giả vào đây.
```

## Kiểm tra từng trường

| Trường | PoC / Silver | Có trong mẫu? | Ghi chú |
|---|---|---|---|
| ProcessGuid, Image | `process_guid`, `image_path` | ☐ | |
| Protocol, Initiated | `protocol`, `direction` | ☐ | `Initiated=true` → OUTBOUND |
| SourceIp/Port, DestinationIp/Port | `src_*`, `dest_*` | ☐ | |
| SourceIsIpv6 / DestinationIsIpv6 | `ip_version` | ☐ | |
| DestinationHostname | — | ☐ | Với `DnsLookup=False` dự kiến là `-` |
| QueryName, QueryStatus, QueryResults (Event 22) | `dns_query_name` | ☐ | Quan sát **định dạng** `QueryResults` |
| TCP state, bytes, duration, SNI | — | ☐ | Dự kiến **không có** |

## Thí nghiệm liên quan
- **E7:** cùng `process_guid`, `DestinationIp` của Event 3 có nằm trong `QueryResults` của Event 22 không (cách correlate DNS với kết nối, file 02 mục D của Week 2)? Khoảng thời gian giữa hai sự kiện là bao lâu?
- Có sự kiện Event 3 nào cho `INBOUND` / `LISTEN` không (dự kiến: không)?
