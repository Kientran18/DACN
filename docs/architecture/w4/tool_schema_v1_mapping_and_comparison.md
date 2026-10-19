# Đối Chiếu Mô Hình Dữ Liệu Các Công Cụ Với Endpoint Event Schema v1 (Silver Layer)

**Dự án:** Hệ thống Giám sát & Phát hiện Xâm nhập Điểm cuối Cục bộ (Local EDR)  
**Người thực hiện:** Huỳnh Hữu Nhật (Data Engineer)  
**Tài liệu tham chiếu gốc:** `docs/architecture/endpoint_event_schema_v1.md` & `docs/architecture/sysmon_raw_to_silver_mapping_v1.md` (Tuần 3)  
**Thời điểm cập nhật:** Tuần 4 (10/2026)

---

## 1. Mục Đích Tài Liệu

Tài liệu này thực hiện đối chiếu chi tiết (field-by-field mapping) giữa đầu ra dữ liệu của các công cụ được khảo sát ở Tuần 4 (**Sysmon, Wazuh, osquery, Velociraptor**) với hợp đồng dữ liệu chuẩn **`Endpoint Event Schema v1`** đã được thiết lập ở Tuần 3. Qua đó:
1. Xác định các quy tắc ánh xạ (mapping rules) có thể **tái sử dụng trực tiếp**.
2. Chỉ rõ các **trường bị khuyết thiếu (Data Gaps)** của từng công cụ khi đặt cạnh yêu cầu của Cyber Team và AI Feature Engineering.
3. Đặc tả các **phép biến đổi dữ liệu (ETL Transformations)** bắt buộc nếu đưa dữ liệu vào Silver Layer.
4. Thiết kế **Schema Ánh Xạ Nhãn Kiểm Thử (`silver_atomic_test_runs`)** cho công cụ **Atomic Red Team** để gắn nhãn tự động các bản ghi trong Silver Layer.

---

## 2. Bảng Đối Chiếu Khung Bao Đóng Chung (Common Event Envelope v1)

Khung bao đóng `Common Event Envelope v1` yêu cầu 10 trường cốt lõi để đảm bảo tính toàn vẹn, chống trùng lặp (`ADR 0001`), liên kết tiến trình (`ADR 0002`) và bảo tồn dữ liệu gốc (`ADR 0003`).

| Trường Schema v1 (`Silver`) | Kiểu Dữ Liệu | **Sysmon v15.15** `[TESTED POC]` | **Wazuh v4.9** (EventChannel) `[DOCS]` | **osquery v5.13** `[DOCS]` | **Velociraptor v0.72** `[DOCS]` | Đánh Giá Khả Năng Tái Sử Dụng & Biến Đổi Cần Thiết |
| :--- | :--- | :--- | :--- | :--- | :--- | :--- |
| `event_id` | `VARCHAR(36)` (UUIDv5) | Sinh từ `Computer \| Channel \| EventRecordID` | Sinh từ `data.win.system.(computer \| channel \| eventRecordID)` hoặc `id` | Phải đổi công thức sang `hostIdentifier \| name \| unixTime \| counter` | Sinh từ `ClientId \| Artifact \| System.EventRecordID` | **Sysmon & Wazuh** tái sử dụng 100% hàm `generate_deterministic_event_id()` Tuần 3. **osquery** không có `EventRecordID`, nếu restart daemon thì `counter` reset gây nguy cơ va chạm khóa. |
| `timestamp` | `TIMESTAMP` (UTC) | `System.TimeCreated.SystemTime` (Độ chính xác $100\text{ ns}$) | `data.win.system.systemTime` (Hoặc `timestamp` của Manager) | `unixTime` (Epoch seconds) hoặc `calendarTime` | `Timestamp` (ISO 8601 UTC) | **Sysmon, Wazuh, Velociraptor** tái sử dụng bộ parser ISO 8601 UTC. **osquery** chỉ có độ phân giải **giây (`unixTime`)**, làm hỏng thứ tự nhân quả khi nhiều sự kiện xảy ra trong cùng 1 giây! |
| `source` | `VARCHAR` | Hằng số `'SYSMON'` | `'WAZUH_SYSMON'` hoặc `'WAZUH_FIM'` | `'OSQUERY'` | `'VELOCIRAPTOR'` | Gán hằng số định danh nguồn tại bước Ingestion. |
| `event_type` | `VARCHAR` (Enum) | Ánh xạ từ `System.EventID` (`1`, `3`, `5`, `11`, `12`–`14`, `22`, `23`) | Ánh xạ từ `data.win.system.eventID` hoặc `syscheck.event` | Ánh xạ từ tên bảng (`processes` + `action='added'`) | Ánh xạ từ tên Artifact và `System.ID` | **Wazuh** (khi bọc Sysmon) và **Velociraptor** (khi đọc EVTX) tái sử dụng hoàn toàn bảng ánh xạ `EventID -> event_type` của Tuần 3. |
| `sysmon_event_id` | `INTEGER` | `int(System.EventID)` | `int(data.win.system.eventID)` | **`[THIẾU - NULL]`** | `int(System.ID)` (nếu dùng Sysmon EVTX) | Trường đặc thù của Sysmon; nếu dùng osquery hoặc ETW thuần sẽ mang giá trị `NULL`. |
| `channel` | `VARCHAR` | `System.Channel` | `data.win.system.channel` | `name` (Tên Scheduled Query) | `Artifact` (Tên VQL Artifact) | Ánh xạ tương đương ngữ cảnh kênh thu thập. |
| `record_id` | `BIGINT` | `int(System.EventRecordID)` | `int(data.win.system.eventRecordID)` | `int(counter)` (Không bền vững khi restart) | `int(System.EventRecordID)` (hoặc `FlowId`) | **Khoảng trống lớn của osquery:** `counter` chỉ đếm trong phiên chạy hiện tại của process `osqueryd`. |
| `hostname` | `VARCHAR` | `System.Computer` | `agent.name` hoặc `data.win.system.computer` | `hostIdentifier` | `Hostname` | Đều đáp ứng tốt; chuẩn hóa `.upper().strip()`. |
| `process_guid` | `VARCHAR(36)` | `strip_guid(EventData.ProcessGuid)` | `strip_guid(data.win.eventdata.processGuid)` | **`[THIẾU HOÀN TOÀN]`** (Chỉ có `pid`) | Có nếu đọc Sysmon; nếu dùng ETW phải tự sinh hash từ `Pid + CreateTime` | **Chốt chặn kiến trúc:** Việc osquery thiếu `process_guid` vi phạm trực tiếp `ADR 0002` của dự án. |
| `raw_data` | `JSON` | `json.dumps(EventData)` | `json.dumps(data.win.eventdata)` | `json.dumps(columns)` | `json.dumps(EventData)` | Đều đáp ứng chiến lược bảo tồn dữ liệu thô (`ADR 0003`). |

---

## 3. Đối Chiếu Chi Tiết 4 Nhóm Sự Kiện Trọng Yếu (Category Schemas v1)

### 3.1. Process Event Schema (`silver_process_events`)

| Trường Schema v1 | Bắt Buộc | **Sysmon (ID 1, 5)** `[TESTED]` | **Wazuh (Sysmon Wrapper)** `[DOCS]` | **osquery (`processes`)** `[DOCS]` | **Velociraptor (ETW/Sysmon)** `[DOCS]` | Khoảng Trống (Data Gaps) & Biến Đổi Cần Thiết |
| :--- | :---: | :--- | :--- | :--- | :--- | :--- |
| `pid` / `ppid` | **Có** | `ProcessId` / `ParentProcessId` | `data.win.eventdata.processId` / `parentProcessId` | `columns.pid` / `columns.parent` | `EventData.ProcessId` / `ParentProcessId` | Ép kiểu `int()`. Wazuh lưu mọi số dưới dạng chuỗi nên bắt buộc phải cast. |
| `parent_guid` | **Có** | `ParentProcessGuid` | `data.win.eventdata.parentProcessGuid` | **`[THIẾU]`** | Có trong Sysmon hoặc dựng từ `ProcessChain` | **osquery** không thể dựng cây tiến trình đệ quy an toàn nếu xảy ra PID Reuse. |
| `image_path` | **Có** | `Image` | `data.win.eventdata.image` | `columns.path` | `EventData.Image` (hoặc `Exe`) | Wazuh escape dấu gạch chéo ngược thành `\\\\`, cần unescape chuẩn hóa đường dẫn Windows. |
| `command_line` | Không | `CommandLine` | `data.win.eventdata.commandLine` | `columns.cmdline` | `EventData.CommandLine` | Đều cung cấp đủ để tính **Shannon Entropy** và bắt LOLBins. |
| `current_working_directory` | Không | `CurrentDirectory` | `data.win.eventdata.currentDirectory` | `columns.cwd` | `EventData.CurrentDirectory` | Đáp ứng đầy đủ trên cả 4 công cụ. |
| `user_name` | Không | `User` (`DOMAIN\User`) | `data.win.eventdata.user` | Chỉ có `columns.uid` (cần JOIN bảng `users`) | `EventData.User` hoặc `Username` | **osquery** mặc định trả về `uid` (SID/RID) trong bảng `processes`, phải viết SQL JOIN với bảng `users` mới lấy được tên tài khoản. |
| `integrity_level` | Không | `IntegrityLevel` | `data.win.eventdata.integrityLevel` | **`[THIẾU]`** trong bảng `processes` | `EventData.IntegrityLevel` | **osquery** thiếu mức toàn vẹn Token (`System`/`High`/`Medium`/`Low`), gây mù thông tin cho luật phát hiện Leo thang đặc quyền (Privilege Escalation). |
| `parent_image` & `parent_command_line` | Không | `ParentImage`, `ParentCommandLine` | `parentImage`, `parentCommandLine` | **`[THIẾU]`** (Phải tự self-JOIN bảng `processes` qua `parent = pid`) | Trích xuất từ mảng `ProcessChain[0]` | Với **Sysmon**, thông tin tiến trình cha được gắn sẵn vào bản ghi con (Denormalized), giúp luật phát hiện chạy tức thì mà không tốn chi phí JOIN. |
| `file_sha256` & `hashes` | Không | `Hashes` (`SHA256=...`) | `data.win.eventdata.hashes` | **`[THIẾU]`** (Phải JOIN bảng `hash` qua `path`, rất tốn CPU) | `EventData.Hashes` hoặc hàm VQL `hash(path=Exe)` | Tái sử dụng regex `SHA256=([A-Fa-f0-9]{64})` của Tuần 3 cho Sysmon/Wazuh. |

### 3.2. File Event Schema (`silver_file_events`)

| Trường Schema v1 | Bắt Buộc | **Sysmon (ID 11, 23, 26)** `[TESTED]` | **Wazuh FIM (`syscheck`)** `[DOCS]` | **osquery (`ntfs_journal_events`)** `[DOCS]` | **Velociraptor (`watch_evtx` / USN)** `[DOCS]` | Khoảng Trống (Data Gaps) & Biến Đổi Cần Thiết |
| :--- | :---: | :--- | :--- | :--- | :--- | :--- |
| `process_guid` & `image_path` | **Có** / Không | `ProcessGuid`, `Image` | **`[THIẾU]`** trong chế độ FIM mặc định (chỉ có nếu bật Audit Whodata) | **`[THIẾU]`** (USN Journal của NTFS không lưu PID/Process tạo file!) | Có nếu dùng Sysmon; **`[THIẾU]`** nếu đọc trực tiếp `$UsnJrnl` | **Phát hiện quan trọng:** Đọc NTFS USN Journal (osquery/Velociraptor) hoặc FIM (Wazuh) chỉ biết *"File X vừa bị tạo/sửa"*, nhưng **không biết tiến trình nào thực hiện**! Chỉ có Kernel Minifilter của **Sysmon** mới gắn chặt sự kiện File với `ProcessGuid` và `Image`. |
| `operation` | **Có** | ID 11 $\rightarrow$ `FILE_CREATE`, ID 23/26 $\rightarrow$ `FILE_DELETE` | `syscheck.event` (`added`, `modified`, `deleted`) | `action` (`FileCreate`, `FileDelete`) | Mapping từ Event ID hoặc USN Reason | Tái sử dụng logic mapping Tuần 3 cho Sysmon. |
| `file_path` & `file_extension` | **Có** / Không | `TargetFilename` + `Path().suffix` | `syscheck.path` | `columns.path` | `TargetFilename` / `FullPath` | Tái sử dụng hàm trích xuất `file_extension` của Tuần 3. |
| `file_sha256` | Không | `Hashes` (Có sẵn ở ID 23/26 khi xóa file) | `syscheck.sha256_after` (Chỉ có khi thêm/sửa, không có khi xóa) | **`[THIẾU]`** | Có thể gọi hàm VQL `hash()` nếu file chưa bị xóa | Sysmon ID 23 lưu trữ và băm file **trước khi lệnh xóa hoàn tất ở cấp nhân**, chống lại kỹ thuật Drop-Execute-Delete. |

### 3.3. Registry Event Schema (`silver_registry_events`)

| Trường Schema v1 | Bắt Buộc | **Sysmon (ID 12, 13, 14)** `[TESTED]` | **Wazuh (`syscheck` Registry)** `[DOCS]` | **osquery (`registry`)** `[DOCS]` | **Velociraptor (ETW/Sysmon)** `[DOCS]` | Khoảng Trống (Data Gaps) & Biến Đổi Cần Thiết |
| :--- | :---: | :--- | :--- | :--- | :--- | :--- |
| `process_guid` & `image_path` | **Có** / Không | `ProcessGuid`, `Image` | **`[THIẾU]`** khi dùng Wazuh FIM Registry (quét định kỳ) | **`[THIẾU HOÀN TOÀN]`** (Bảng `registry` chỉ đọc trạng thái tĩnh trên đĩa) | Có khi đọc qua Sysmon hoặc ETW Registry | **osquery** và **Wazuh FIM** không cho biết tiến trình nào đã ghi vào khóa `Run`/`RunOnce`. |
| `operation` | **Có** | `EventType` (`SetValue`, `CreateKey`, `DeleteValue`) | `syscheck.event` (`added`, `modified`, `deleted`) | `action` (`added`, `removed` qua diff query) | `EventData.EventType` | Tái sử dụng mapping Tuần 3. |
| `target_object`, `hive`, `key_path`, `value_name` | **Có** / Không | `TargetObject` (Tách chuỗi theo `\`) | `syscheck.path` + `syscheck.value_name` | `columns.path`, `columns.key`, `columns.name` | `EventData.TargetObject` | Tái sử dụng 100% thuật toán tách `hive`, `key_path`, `value_name` từ `windows_registry_type_inference_heuristics.md` (Tuần 3). |
| `value_type_inferred` | Không | Suy diễn từ `Details` (`REG_DWORD`, `REG_QWORD`, `REG_BINARY`, `STRING_UNSPECIFIED`) | Có sẵn `syscheck.value_type` | Có sẵn `columns.type` (`REG_SZ`, `REG_DWORD`,...) | Suy diễn từ `Details` | **Ý tưởng học hỏi:** osquery và Wazuh trả về kiểu Registry tường minh. Với Sysmon, hàm heuristic `infer_registry_value_type()` ở Tuần 3 đã bù đắp hoàn toàn khoảng trống này. |

### 3.4. Network Event Schema (`silver_network_events`)

| Trường Schema v1 | Bắt Buộc | **Sysmon (ID 3 & ID 22)** `[TESTED]` | **Wazuh (Sysmon Wrapper)** `[DOCS]` | **osquery (`process_open_sockets`)** `[DOCS]` | **Velociraptor (`NetstatEnriched` / ETW)** `[DOCS]` | Khoảng Trống (Data Gaps) & Biến Đổi Cần Thiết |
| :--- | :---: | :--- | :--- | :--- | :--- | :--- |
| `process_guid` & `image_path` | **Có** / Không | `ProcessGuid`, `Image` | `data.win.eventdata.processGuid`, `image` | Chỉ có `columns.pid` (**`[THIẾU process_guid & image_path]`**) | Có `Pid` + `Exe` (cần ánh xạ sang GUID) | Với **osquery**, muốn biết tên file thực thi mở socket phải JOIN `process_open_sockets` với `processes` qua `pid`. |
| `protocol` & `ip_version` | **Có** / Không | `Protocol.upper()`, `SourceIsIpv6` | `protocol`, `sourceIsIpv6` | `columns.protocol` (Trả về số IANA: `6` = TCP, `17` = UDP), `columns.family` (`2` = IPv4) | `Protocol`, `Family` | Nếu dùng osquery phải viết bảng tra cứu số hiệu giao thức (`6 -> 'TCP'`, `17 -> 'UDP'`). |
| `direction` | **Có** | `Initiated == 'true'` $\rightarrow$ `'OUTBOUND'`, ngược lại `'INBOUND'` | `data.win.eventdata.initiated` | **`[THIẾU]`** (Chỉ có `state` như `ESTABLISHED`, `LISTEN`) | Suy diễn từ `State` hoặc Sysmon `Initiated` | **osquery** không có cờ xác định bên nào chủ động khởi tạo kết nối (`Initiated`) sau khi kết nối đã sang trạng thái `ESTABLISHED`. |
| `src_ip`, `src_port`, `dest_ip`, `dest_port` | **Có** | `SourceIp`, `SourcePort`, `DestinationIp`, `DestinationPort` | Tương đương trong `data.win.eventdata.*` | `local_address`, `local_port`, `remote_address`, `remote_port` | `Laddr.IP`, `Laddr.Port`, `Raddr.IP`, `Raddr.Port` | Đều cung cấp đủ bộ 4-tuple mạng. |
| `dns_query_name` | Không | `QueryName` (Sysmon ID 22) | `data.win.eventdata.queryName` | **`[THIẾU]`** trên Windows (Không có bảng bắt DNS event gốc ổn định) | `Windows.ETW.DNS` (`QueryName`) | Sysmon Event ID 22 bắt chính xác tên miền C2 gắn liền với `ProcessGuid` vừa gọi hàm phân giải DNS. |

---

## 4. Thiết Kế Schema Đối Chiếu & Gắn Nhãn Cho Atomic Red Team

Vì **Atomic Red Team** là công cụ mô phỏng tấn công và sinh nhãn kiểm thử (không phải nguồn thu thập sự kiện hệ thống), dữ liệu của Atomic Red Team không ánh xạ vào 4 bảng sự kiện mà được chuẩn hóa thành bảng **`silver_atomic_test_runs`** trong DuckDB để phục vụ đối chiếu (Ground-Truth Correlation) ở Tuần 5:

### 4.1. Đặc tả bảng `silver_atomic_test_runs` (DuckDB Silver Layer)

| Trường Dữ Liệu | Kiểu Dữ Liệu | Nguồn Từ Atomic Red Team (YAML + Execution Log) | Mục Đích Gắn Nhãn & Đối Chiếu Với Telemetry Sysmon |
| :--- | :--- | :--- | :--- |
| `test_run_id` | `VARCHAR(36)` | `UUIDv5(hostname \| atomic_guid \| start_time_utc)` | Khóa chính xác định duy nhất cho mỗi lần chạy thử nghiệm kịch bản. |
| `atomic_guid` | `VARCHAR(36)` | `auto_generated_guid` (trong file `Txxxx.yaml`) | Định danh chuẩn của bài test Atomic Red Team. |
| `mitre_technique_id` | `VARCHAR(16)` | `attack_technique` (ví dụ: `T1059.001`, `T1547.001`) | Nhãn kỹ thuật MITRE ATT&CK dùng để đối chiếu với kết quả của Cyber Detection Engine. |
| `test_name` | `VARCHAR` | `name` / `test_name` | Tên mô tả kịch bản tấn công. |
| `hostname` | `VARCHAR` | `hostname` | Máy trạm thực thi bài test (khớp với `hostname` của Sysmon). |
| `runner_pid` | `INTEGER` | `runner_pid` (Process ID của PowerShell/CMD chạy test) | Dùng để tìm ra `root_process_guid` trong bảng `silver_process_events`. |
| `start_time_utc` | `TIMESTAMP` | `start_time_utc` (Chuẩn hóa ISO 8601 UTC) | Mốc thời gian bắt đầu cửa sổ đối chiếu sự kiện. |
| `end_time_utc` | `TIMESTAMP` | `end_time_utc` (Chuẩn hóa ISO 8601 UTC) | Mốc thời gian kết thúc cửa sổ đối chiếu sự kiện. |
| `command_executed` | `VARCHAR` | `command_executed` | Dòng lệnh thực tế đã thực thi để đối khớp chuỗi con với `command_line` của Sysmon. |

### 4.2. Thuật toán liên kết nhãn (Lineage & Labeling Correlation Logic)
Để tránh gán nhãn nhầm các tiến trình nền của hệ điều hành (Background Noise) chạy trùng vào khoảng thời gian `[start_time_utc, end_time_utc]`, nhóm Data thiết kế thuật toán gắn nhãn 2 bước dựa trên **Cây phả hệ tiến trình (`ProcessGuid` Lineage)**:

1. **Bước 1 – Tìm Tiến Trình Gốc (Anchor Process Discovery):**
   Tìm bản ghi trong `silver_process_events` thỏa mãn đồng thời:
   * `hostname = atomic.hostname`
   * `timestamp BETWEEN (atomic.start_time_utc - INTERVAL '1 second') AND (atomic.end_time_utc + INTERVAL '2 seconds')`
   * `pid = atomic.runner_pid` (hoặc `parent_pid = atomic.runner_pid` / khớp `RuleName` chứa `technique_id`).
   $\rightarrow$ Thu được tập hạt giống `seed_process_guids`.
2. **Bước 2 – Lan Truyền Nhãn Theo Cây Đệ Quy (Recursive Lineage Propagation):**
   Sử dụng truy vấn đệ quy `WITH RECURSIVE` trên DuckDB theo khóa `parent_guid = process_guid` để tìm toàn bộ các tiến trình con, cháu (`descendant_process_guids`) sinh ra từ `seed_process_guids`. Mọi sự kiện Process, File, Registry, Network có `process_guid` nằm trong tập phả hệ này đều được gán nhãn chính xác 100% là **`mitre_technique_id`** và **`atomic_guid`** của lần chạy thử đó.