# Field Compatibility Mapping: XML → PoC JSON → Bronze v1 → Silver

**Trạng thái:** DRAFT. Dựa trên mã PoC Tuần 3 (`sysmon_collector_poc.py`), schema Silver trong `week_01_data_foundation_report.md` §3.1, `sysmon_to_silver_schema_mapping.md` và spec của Data. **Chưa đối chiếu với mẫu thật**; chạy `contract_check.py` trên `references/samples` để xác nhận cột "Mẫu thật". Chủ xử lý: **S** = Software, **D** = Data, **C** = Cyber (đề xuất, chờ chấp nhận).

**Nhãn bằng chứng:** **[X, Linux]** = kiểm chứng trong container Linux (Python 3.12), **chưa** trên Windows; xác nhận lại bằng `verify_windows_env.py` (W01, W03, file 06). Giá trị mẫu trong tài liệu là giả lập.

Ký hiệu trạng thái: **OK** khớp · **Renamed** đổi tên · **Derived** suy ra · **Lost** mất ở PoC · **Added** thêm ở Bronze v1 · **Silver thiếu cột** · **NULL** Sysmon không cung cấp.

## A. Phần `System` của XML → PoC JSON → Bronze v1

| XML `System` | PoC v0.1 (Tuần 3) | Bronze v1 | Trạng thái |
|---|---|---|---|
| `Provider@Name`, `@Guid` | Không có | `provider.name`, `provider.guid` | **Lost** ở PoC → **Added** |
| `EventID` | `sysmon_event_id` | `sysmon_event_id` | OK |
| `Version`, `Level`, `Task`, `Opcode`, `Keywords` | Không có | cùng tên | Lost → Added |
| `TimeCreated@SystemTime` | `timestamp` (cùng chuỗi) | `time_created` | Renamed |
| `EventRecordID` | `record_id` | `record_id` | OK |
| `Execution@ProcessID`, `@ThreadID` | Không có | `writer_process_id`, `writer_thread_id` | Lost → Added |
| `Channel` | `channel` | `channel` | OK |
| `Computer` | `hostname` | `hostname` | OK |
| (không có) | Không có | `host_id` (dẫn xuất từ hostname) | **Added** (D-05) |
| `Security@UserID` | Không có | `log_writer_sid` | Lost → Added (SID của dịch vụ ghi log) |
| `Correlation` | Không có | Chỉ trong `raw_xml` | Lost (giá trị thấp) |
| Toàn bộ văn bản XML | Không có | `raw_xml` | Lost → Added |
| `EventData/Data[@Name]` | `raw_data` (dict) | `event_data` (dict) | OK; **thứ tự không giữ, tên trùng bị ghi đè, `Data` không có `Name` bị bỏ**; `raw_xml` giữ đầy đủ |
| (dẫn xuất) | `event_id` (uuid5) | `event_id` | OK |
| (dẫn xuất) | `event_type`, `data`, `process_guid`, `source` | Chỉ giữ `source`; ba trường còn lại chuyển sang Silver transform | **Moved** (D-02, M-17) |

## B. `EventData` → Silver (theo loại sự kiện)

Cột "PoC `data`" là tên trường trong đầu ra PoC; cột "Silver" lấy từ báo cáo Tuần 1 (cột hiện có) và tài liệu mapping của Data.

### Sysmon 1: Process Create

| EventData | PoC `data` | Silver | Trạng thái | Ghi chú / chủ |
|---|---|---|---|---|
| ProcessGuid | `process_guid` (bỏ `{}`, giữ hoa/thường) | `process_guid` | OK + quy tắc | Chuẩn hóa dạng chuẩn (M-08), **D** |
| ProcessId | `pid` | `pid` | OK | |
| ParentProcessId | `ppid` | `ppid` | OK | |
| ParentProcessGuid | `parent_guid` | `parent_guid` | OK + quy tắc | Như ProcessGuid |
| Image | `image_path` | `image_path` | OK | |
| CommandLine | `command_line` | `command_line` | OK | |
| CurrentDirectory | `current_working_directory` | `current_working_directory` | OK | |
| User | `user_name` | `user_name` | OK | Spec cần `user_sid`: Sysmon không cho (M-12) |
| Hashes | `file_sha256` (+ `hashes`) | `file_sha256` | OK + quy tắc | Sysmon in hoa: chuẩn hóa chữ thường (M-07), **D** |
| ParentImage | `parent_image` | không có | **Silver thiếu cột** | DET-001/002 cần (M-13), **D** |
| ParentCommandLine | `parent_command_line` | không có | Silver thiếu cột | M-13 |
| IntegrityLevel | `integrity_level` | không có | Silver thiếu cột | M-13 |
| TerminalSessionId | `session_id` | không có | Silver thiếu cột | M-13 |
| UtcTime | chỉ trong `raw_data` | `timestamp` (Data đang parse từ đây) | **Khác nguồn thời gian** | PoC dùng `SystemTime` (100 ns, UTC) còn Data dùng `UtcTime` (ms); chọn một (M-09), **D** |
| LogonId, LogonGuid, OriginalFileName, FileVersion, Description, Product, Company | chỉ `raw_data` | không có | Trường có sẵn chưa ánh xạ | Danh sách theo Sysmon docs **[T:S1]**, xác nhận bằng mẫu; **D** quyết định |

### Sysmon 5: Process Terminate

| EventData | PoC | Silver | Trạng thái | Ghi chú |
|---|---|---|---|---|
| ProcessGuid, Image, ProcessId | `process_guid`, `image_path`, `pid` | cùng tên | OK | |
| UtcTime / `time_created` | `timestamp` | `end_time` | **Silver thiếu cột** | Cần UPDATE dòng Event 1 theo `process_guid`; Event 5 đến trước Event 1 (hiếm) cần quy tắc (M-04), **D** |
| ExitCode | không có | không có | **NULL** | Sysmon không cung cấp; cần Security 4689 hoặc ETW (Phase 2) |

### Sysmon 3: Network Connect

| EventData | PoC `data` | Silver | Trạng thái | Ghi chú |
|---|---|---|---|---|
| ProcessGuid | `process_guid` | `process_guid` | OK | |
| Protocol | `protocol` (in hoa, ví dụ `TCP`) | `protocol` | OK + quy tắc | Sysmon in chữ thường; enum spec là `TCP`/`UDP` (M-20) |
| Initiated | `direction` | `direction` | **Derived** | `true` → `OUTBOUND`, `false` → `INBOUND` |
| SourceIp, SourcePort | **`src_ip`, `src_port`** | **`source_ip`, `source_port`** | **Renamed** | M-01: spec dùng `src_*`, Silver dùng `source_*`, PoC dùng `src_*`; **D** chọn, **S** căn theo |
| DestinationIp, DestinationPort | `dest_ip`, `dest_port` | `dest_ip`, `dest_port` | OK | |
| SourceIsIpv6, DestinationIsIpv6 | `ip_version` | không có | Silver thiếu cột | M-13 |
| DestinationHostname, SourceHostname | chỉ `raw_data` | không có | Có thể là `-` | Với `DnsLookup=False` dự kiến `-` (M-18, cần mẫu) |
| (trạng thái TCP, bytes, duration, SNI) | không có | không có | **NULL** | Sysmon không cung cấp |

### Sysmon 22: DNS Query

| EventData | PoC `data` | Silver | Trạng thái | Ghi chú |
|---|---|---|---|---|
| QueryName | `dns_query_name` | `dns_query_name` (theo mapping doc) | **Silver thiếu cột** | Báo cáo Tuần 1 không liệt kê cột này trong `NetworkEvent` |
| QueryResults, QueryStatus | `query_results`, `query_status` | không có | Silver thiếu cột | Cần để correlate với Event 3 |
| (dòng DNS không có `dest_ip`, `dest_port`) | — | `dest_ip`… bắt buộc? | **Mâu thuẫn** | DNS là dòng riêng trong `silver_network_events` hay làm giàu dòng Event 3? Cần `Optional` hoặc bảng riêng (M-05), **D** |

### Sysmon 11 / 23 / 26: File

| EventData | PoC `data` | Silver | Trạng thái | Ghi chú |
|---|---|---|---|---|
| TargetFilename | `file_path` | `file_path` | OK | |
| (suy từ đuôi) | `file_extension` (chữ thường, không dấu chấm) | `file_extension` | Derived | Quy tắc cần Data xác nhận (M-19) |
| (loại sự kiện) | không có `operation` | `operation` (mapping doc) | **Thiếu** ở cả PoC lẫn báo cáo Tuần 1 | Suy `CREATE`/`DELETE` từ event id (M-03), **D** thêm cột, **S** phát giá trị |
| Image | `image_path` | không có | Silver thiếu cột | Process thực hiện (có thể suy qua `process_guid`) |
| Hashes (23/26) | `file_sha256` | không có cột trong `FileEvent` | Silver thiếu cột | M-13 |
| IsExecutable, Archived | `is_executable`, `archived` | không có | Silver thiếu cột | |
| (kích thước file) | không có | `file_size_bytes` | **NULL** | Sysmon không cung cấp; `os.stat` làm giàu có race (TR-02) |
| (`chunk_entropy`, `byte_delta`) | không có | không có | NULL | Ngoài Phase 1 |

### Sysmon 12 / 13 / 14: Registry

| EventData | PoC `data` | Silver | Trạng thái | Ghi chú |
|---|---|---|---|---|
| EventType | `operation` (giá trị gốc: `CreateKey`, `SetValue`...) | `operation` (mapping doc) | **Thiếu cột + khác từ vựng** | Ba bộ tên: Sysmon `SetValue`, spec `VALUE_SET`, envelope `REGISTRY_SET_VALUE` (M-06, M-10), **D+C** |
| TargetObject | `target_object` (+ `hive`, `key_path`, `value_name`) | `target_object` | OK | Phần tách hive/key/value là suy luận, chưa có cột |
| Details | `details` (+ `value_type_inferred`) | `details` | OK | Kiểu giá trị chỉ suy ra được một phần |
| (giá trị cũ, nội dung binary, mã trạng thái) | không có | không có | **NULL** | Sysmon không cung cấp |

### Sysmon 4, 15, 16, 29

Không có bảng Silver đích; Sysmon 4/16 phục vụ DET-007 (tamper), 15/29 phục vụ T1204.002 và T1105. Quyết định bảng lưu trữ ở Q-X1 và Q-D8 (Week 2).

## C. Điều kiện thiếu dữ liệu và quy tắc đề xuất

| Điều kiện | Biểu hiện trong Bronze | Quy tắc Silver đề xuất | Mức xác nhận |
|---|---|---|---|
| Sysmon điền `-` cho trường rỗng (ví dụ `RuleName`, `SourceHostname`, `DestinationHostname`) | Giữ chuỗi `-` nguyên văn | Với danh sách trường đã biết, ánh xạ `-` thành `NULL` (M-18) | **[?]** cần mẫu thật |
| `HashAlgorithms` không gồm SHA256, hoặc hash thất bại | `Hashes` thiếu `SHA256=` hoặc rỗng | `file_sha256 = NULL`, không coi là lỗi | [?] |
| `User` của tiến trình hệ thống | Ví dụ tài khoản dịch vụ | Giữ nguyên chuỗi | [?] |
| Process cha chạy trước Sysmon | `ParentProcessGuid` có nhưng không có dòng Event 1 của cha | Không phải thiếu trường: cây bị cụt, đặt cờ `tree_truncated` (Q-D9) | [N] |
| `Details` của registry không phải chuỗi/DWORD/QWORD | Có thể là `Binary Data` hoặc dạng khác | `value_type_inferred = REG_BINARY` khi nhận ra, ngược lại `STRING_UNSPECIFIED` | [?] (Sysmon docs chỉ nhắc DWORD/QWORD **[T:S1]**) |
| Event 22 truy vấn thất bại | `QueryStatus` khác 0, `QueryResults` rỗng | Giữ; không correlate với Event 3 | [?] |
| Event 11 do ghi đè so với tạo mới | Không phân biệt được bằng trường | `operation = CREATE` cho cả hai; ghi chú giới hạn (L1) | [N] |
| `EventData` có tên trùng hoặc `Data` không tên | `event_data` mất; `raw_xml` còn đủ | Silver không dùng; chỉ debug | [N] |
| Giá trị `event_data` chứa ký tự xuống dòng (ví dụ command line nhiều dòng) | JSON thoát thành `\n`/`\r\n` trong chuỗi, giữ nguyên | Giữ nguyên; không dùng làm khóa hay so khớp theo dòng | [?] cần mẫu thật |
| Chuỗi chứa ký tự đặc biệt XML (`&`, `<`) | Bộ parse giải mã thành ký tự gốc; `raw_xml` giữ dạng thoát | Không cần xử lý | [N] |

## D. Danh sách mismatch và người xử lý (đề xuất)

| Mã | Vấn đề | Chủ | Cách xử lý đề xuất | Cần trước |
|---|---|---|---|---|
| M-01 | `src_*` (spec, PoC) và `source_*` (Silver) | **D** chọn; **S** căn theo | Chốt một tên cho cả hai tầng | W05 |
| M-02 | PoC JSON không có `host_id`, Silver yêu cầu | **S** | Thêm `host_id` (D-05); **D** xác nhận cách sinh | W06 |
| M-03 | Không có `operation` cho file event | **D** thêm cột; **S** phát giá trị | Suy từ event id | W06 |
| M-04 | Chưa có `end_time`; Event 5 cần cập nhật dòng cũ | **D** | Thêm cột; quy tắc khi Event 5 đến trước Event 1 | W06 |
| M-05 | DNS (Event 22) lưu thế nào trong bảng network | **D** | Dòng riêng với cột nullable, hoặc bảng riêng | W05 |
| M-06 | Từ vựng registry (`SetValue` / `VALUE_SET` / `REGISTRY_SET_VALUE`) | **D + C** | Một bảng quy đổi (cùng Q-X3) | W05 |
| M-07 | Hash in hoa của Sysmon | **D** | Chuẩn hóa chữ thường | W06 |
| M-08 | Dạng chuẩn của GUID: hoa/thường, không phải UUIDv4 **[X, Linux]** | **D** | Chuẩn chữ thường, kiểu `UUID`/chuỗi; **không dùng `UUID4`** | W05 |
| M-09 | `SystemTime` (100 ns, UTC, có `Z`) so với `UtcTime` (ms, không múi giờ); thư viện cắt xuống µs **[X, Linux]** | **D** | Chọn nguồn `timestamp`; giữ chuỗi gốc ở Bronze | W05 |
| M-10 | Tên `event_type`: Cyber `PROCESS_CREATE`, Data `PROCESS_START` | **D + C** | Bảng quy đổi ở file 02 Week 2 mục H | W05 |
| M-11 | Enum `source` của Data chưa có `SYSMON` | **D** | Thêm 4 giá trị đề xuất | W05 |
| M-12 | `user_sid` không có trong Sysmon Event 1 | **D** | Optional/NULL, hoặc resolve ở Silver | W06 |
| M-13 | Silver thiếu cột (xem mục B) | **D** | Chốt danh sách cột (Q-D6) | W05 |
| M-14 | Tài liệu của Data ghi sai tên channel (`Microsoft-Windows-System/Operational`) | **D** | Sửa tài liệu; kiểm tra `collector.py` | W05 |
| M-15 | PoC đọc mới nhất trước | **S** | Đọc xuôi + bookmark (P-02) | W06 |
| M-16 | PoC không giữ `raw_xml` và metadata `System` | **S** | Hợp đồng này (P-01) | W06 |
| M-17 | Hai nơi ánh xạ ngữ nghĩa (PoC `data` và Silver) | **S + D** | D-02: Silver là nơi duy nhất | W05 |
| M-18 | Quy tắc cho giá trị `-` | **D** | Danh sách trường và quy tắc | W06 |
| M-19 | Quy tắc `file_extension` | **D** | Chữ thường, không dấu chấm, chỉ đuôi cuối | W06 |
| M-20 | Chữ hoa/thường của `protocol` | **D** | Enum `TCP`/`UDP` | W06 |
| M-21 | Mã hóa UTF-8 BOM/UTF-16 của file xuất bằng PowerShell | **S** | Collector đọc cả hai; Bronze ghi UTF-8 không BOM | W06 |
| M-22 | Silver chưa có cột truy vết (`bronze segment`, dòng, run) | **D** | Thêm cột lineage (file 03 mục 4) | W06 |
| M-23 | JSONL ghi ở chế độ văn bản trên Windows bị đổi `\n` thành `\r\n`, trái hợp đồng (LF) | **S** | Đã sửa ở PoC (`newline="\n"`, có test); mọi writer segment/manifest/log theo quy tắc này; kiểm W05 trên VM | W06 |
| M-24 | Git trên Windows (`autocrlf`) có thể đổi xuống dòng của mẫu thô trong `references/samples`, làm `raw_xml` không còn nguyên văn | **S + cả nhóm** | Thêm `references/samples/** -text` vào `.gitattributes` **trước khi** commit mẫu thật | W05 |
| M-25 | Tên segment/file chứa ký tự cấm của Windows (ví dụ `:`) | **S** | Dùng `YYYYMMDDTHHMMSSZ`; đã ghi trong hợp đồng (file 01 mục 4); kiểm W07 | W06 |
