# Rule Sigma trong DACN

> Trạng thái: **đã hiện thực trên Linux, tắt mặc định, `synthetic_only`** (2026-11-28). Thiết kế do Claude đề xuất, người dùng duyệt
> ngày 2026-11-28 thay cho Cyber; **chưa có review độc lập**. Chưa chạy trên Windows 10 VM. Không có số liệu chất lượng phát hiện.
> Rule Sigma chỉ tạo alert (`response_policy: alert_only`); điểm rủi ro không bao giờ kích hoạt response.

## 1. Mục tiêu và phạm vi

DACN nạp được **một tập con** rule Sigma (định dạng SigmaHQ) cho Windows, đánh giá trên Silver của DACN, và đưa kết quả qua
**cùng luồng** `DetectionResult` → outbox → alert như rule DACN. Mỗi kết luận có giải thích: selection nào đúng, condition, giá trị
field đã khớp, tác giả và giấy phép rule gốc.

Ngoài phạm vi đợt này: correlation/aggregation Sigma (`count()`, `near`, `timeframe`, correlation rule), keyword search,
rule collection nhiều document, modifier `expand`, logsource không có telemetry trong Silver (image_load, process_access,
pipe, kênh Security/System…).

## 2. Các quyết định đã duyệt (2026-11-28)

| # | Quyết định | Lý do chính |
|---|---|---|
| S1 | **Tự viết bộ biên dịch tập con** (`src/detection/sigma/`), đánh giá bằng Python từng hàng Silver mới; không dùng pySigma, không sinh SQL | pySigma 2.1.2 là LGPL-2.1, kéo 9 phụ thuộc (có `google-re2`, `jq` native; chưa kiểm chứng wheel cho Windows/Python 3.14), bản cài thử còn thiếu `typing_extensions`; không có backend DuckDB; SQL mất phân biệt NO_MATCH / INSUFFICIENT_TELEMETRY. Không thêm thư viện nào |
| S2 | `rule_id = DACN-SIG-<8 hex đầu của id Sigma>` | Xác định được từ id gốc, không cần bảng gán số; 17 ký tự, vừa `alerts.rule_id VARCHAR(32)` (`SIGMA-<uuid>` dài 42) |
| S3 | Thay đổi contract **tương thích ngược**: rule `type: sigma` + khóa `sigma`, pattern `rule_id` nới thêm `DACN-SIG-…`; `detection_source = SIGMA`; mã lỗi `SIG-E001…E011` | Không đổi DDL, Bronze, `DetectionResult`. `docs/architecture/w6/contracts/rule.schema.json` đã xuất lại |
| S4 | Rủi ro: nhóm riêng `SIGMA` (trọng số 1.0, trần 40) trong `config/risk-scoring.yaml` **v3**; SIGMA và RULE tính là **một** cơ chế khi cộng thưởng đa dạng | Rule cộng đồng chưa hiệu chỉnh cho DACN; Sigma và rule DACN dùng cùng telemetry nên không độc lập |
| S5 | 28 rule SigmaHQ ghim commit `ddf1d4f87fd283513ac1dbf7e178c8a4064047df` (2026-11-28), chọn theo technique của lượt Atomic (T1059.001, T1547.001, T1053.005, T1070.004, T1082) và LOLBins | Không tải cả kho vào repo |

## 3. Ngữ nghĩa đánh giá

- **Nguồn field.** Với Sysmon, field Sigma trùng tên field EventData gốc. Silver giữ EventData nguyên văn trong cột `raw_data`
  (JSON), nên field được đọc từ `raw_data` đúng tên, **không cần cột mới, không suy ra giá trị**. `EventID` lấy từ `sysmon_event_id`.
- **So khớp chuỗi.** Mặc định không phân biệt hoa/thường; wildcard `*` (chuỗi bất kỳ) và `?` (một ký tự); `\` chỉ là ký tự escape
  khi đứng trước `*`, `?`, `\` (theo đặc tả Sigma); ngoài ra là dấu `\` thường. Giá trị số so như chuỗi (`443` khớp `"443"`).
- **Logic ba giá trị.** True / False / chưa biết:
  - field **thuộc** loại sự kiện (theo schema Sysmon của Event ID đó) nhưng **vắng** trong hàng → chưa biết → `INSUFFICIENT_TELEMETRY`
    (vào `coverage_gaps`, không phải alert, không kết luận lành tính); `missing_fields` liệt kê field Sigma;
  - field **không thuộc** loại sự kiện (ví dụ `Details` trên Event 12 khi rule là `registry_event`) → điều kiện là False;
  - `not` của "chưa biết" vẫn là "chưa biết"; `and` với False là False; `or` với True là True.
- **Bộ lọc ngầm** như pipeline Sysmon của Sigma: `registry_add` chỉ nhận `EventType = CreateKey`, `registry_delete` chỉ nhận
  `DeleteKey`/`DeleteValue` (không phân biệt hoa/thường).
- **PowerShell 4104.** `ScriptBlockText` là script block **đã ghép** theo `(hostname, ScriptBlockId, MessageTotal)` như
  DACN-DET-203. Thiếu phần: chỉ báo MATCH trên phần đã có (`coverage_status = PARTIAL_SCRIPT_BLOCK`), chưa khớp thì chưa kết luận.
  Văn bản script **không** vào kết quả/alert: chỉ có sha256 và độ dài.
- **Kết quả MATCH** có `matched_fields.sigma` (`id`, `title`, `condition`, `selections_true`, `fields`, `level`, `status`) và
  `matched_fields.attribution` (`author`, `license`, `license_url`, `source_url`, `source_path`).

### 3.1. Modifier và điều kiện

| Hỗ trợ | Ghi chú |
|---|---|
| `contains`, `startswith`, `endswith`, `all`, `cased` | `all` = mọi giá trị trong danh sách (mặc định danh sách là OR) |
| `re` (+ `i`, `m`, `s`) | Python `re.search`, phân biệt hoa/thường nếu không có `i`. Độ dài pattern ≤ `regex_max_length`. Python `re` không có timeout: rủi ro ReDoS còn lại |
| `windash` | `-` hoặc `/` ở đầu một từ khớp `- / – — ―` (như pySigma) |
| `base64`, `base64offset` (+ `wide`/`utf16le`/`utf16be`/`utf16`) | `base64offset` bắt buộc đi với `contains`; ba độ lệch như pySigma |
| `cidr` | `ipaddress`; giá trị không phải IP là False |
| `exists`, `null`, `lt/lte/gt/gte`, `fieldref` | `null` khớp field vắng hoặc rỗng |
| `and`, `or`, `not`, ngoặc, `1 of X*`, `all of X*`, `1 of them`, `all of them`, danh sách condition (OR) | |

Từ chối khi nạp: keyword search (SIG-E006), `|` aggregation, `near`, `timeframe`, correlation, `N of` với N ≠ 1 (SIG-E005),
`expand` và modifier lạ hoặc kết hợp sai (SIG-E004).

### 3.2. Mã từ chối

| Mã | Ý nghĩa |
|---|---|
| SIG-E001 | YAML/cấu trúc lỗi: thiếu khóa, nhiều document, id lệch manifest, tệp không tồn tại hoặc nằm ngoài `base_dir` |
| SIG-E002 | logsource không hỗ trợ / không có telemetry (kể cả windefend chỉ có Event ID không thu thập) |
| SIG-E003 | field không có trong telemetry của logsource |
| SIG-E004 | modifier không hỗ trợ / kết hợp sai |
| SIG-E005 | điều kiện không hỗ trợ hoặc tham chiếu selection không tồn tại |
| SIG-E006 | keyword search |
| SIG-E007 | status (`experimental` khi chưa bật, `deprecated`, `unsupported`) hoặc level `informational` |
| SIG-E008 | trùng `rule_id` (8 hex đầu): loại **mọi** rule trùng, không chọn ngẫu nhiên |
| SIG-E009 | sha256 tệp khác manifest |
| SIG-E010 | regex lỗi hoặc dài quá giới hạn |
| SIG-E011 | vượt `max_rules` |

## 4. Bảng ánh xạ logsource / field → Silver

| Sigma | Bảng Silver | Event ID | Field được nhận (đọc từ) |
|---|---|---|---|
| `category: process_creation` | `silver_process_events` | 1 | `raw_data`: RuleName, UtcTime, ProcessGuid, ProcessId, Image, FileVersion, Description, Product, Company, OriginalFileName, CommandLine, CurrentDirectory, User, LogonGuid, LogonId, TerminalSessionId, IntegrityLevel, Hashes, ParentProcessGuid, ParentProcessId, ParentImage, ParentCommandLine, ParentUser |
| `category: file_event` | `silver_file_events` | 11 | `raw_data`: chung + TargetFilename, CreationUtcTime |
| `category: registry_set` / `registry_add` / `registry_delete` / `registry_rename` / `registry_event` | `silver_registry_events` | 13 / 12 / 12 / 14 / 12,13,14 | `raw_data`: chung + EventType, TargetObject, Details (13), NewName (14) |
| `category: network_connection` | `silver_network_events` | 3 | `raw_data`: chung + Protocol, Initiated, SourceIsIpv6, SourceIp, SourceHostname, SourcePort, SourcePortName, DestinationIsIpv6, DestinationIp, DestinationHostname, DestinationPort, DestinationPortName |
| `category: dns_query` | `silver_network_events` | 22 | `raw_data`: chung + QueryName, QueryStatus, QueryResults |
| `category: ps_script` hoặc `service: powershell` | `silver_powershell_scriptblock_events` (v1.3 đề xuất) | 4104 | ScriptBlockText (đã ghép), Path (`raw_data`), ScriptBlockId, MessageTotal, EventID |
| `service: windefend` | `silver_defender_events` (v1.3 đề xuất) | 1116, 1117, 5001, 5007, 5013 | EventID→`windows_event_id`, NewValue→`new_value`, OldValue→`old_value`, ProcessName→`process_name`, SourceName→`source_name`, Path→`path_raw`, ThreatName→`threat_name`, ThreatID→`threat_id`, SeverityName, CategoryName, ActionName, DetectionID |

"chung" = EventID, RuleName, UtcTime, ProcessGuid, ProcessId, Image, User. Danh sách field theo Event ID lấy từ schema Sysmon v15;
tên field Event 1 đã đối chiếu với mẫu XML thật trong `references/samples`. Field windefend khác (ví dụ `Value`, `Feature_Name`,
`Reason`) bị từ chối (SIG-E003). Nguồn: `src/detection/sigma/fieldmap.py`.

## 5. Danh sách rule đã chọn (SigmaHQ @ `ddf1d4f87fd2`, 28 rule, đều `test`/`stable`)

Mọi rule: `validation_status: synthetic_only`, `detection_source: SIGMA`, `response_policy: alert_only`. Cột MITRE là tag do tác giả
Sigma gắn, **chưa Cyber xác minh** (ví dụ `T1685` của rule 5001 giữ nguyên theo nguồn). "Nạp được" nghĩa là cú pháp được hỗ trợ,
không phải đã kiểm chứng phát hiện.

| rule_id | Tiêu đề Sigma (SigmaHQ) | Logsource → bảng Silver (Event ID) | level → severity | MITRE (tag Sigma) | Trạng thái hỗ trợ |
|---|---|---|---|---|---|
| `DACN-SIG-57b649ef` | Windows Defender Threat Detected | service:windefend → `silver_defender_events` (1116, 1117) | high → high | T1059 | Nạp được; Event ID 1006, 1015 của rule không được DACN thu thập; chỉ đánh giá [1116, 1117] |
| `DACN-SIG-b28e58e4` | Windows Defender Real-time Protection Disabled | service:windefend → `silver_defender_events` (5001) | high → high | T1685 | Nạp được |
| `DACN-SIG-2aa0a6b4` | Startup Folder File Write | file_event → `silver_file_events` (11) | medium → medium | T1547.001 | Nạp được |
| `DACN-SIG-92fa78e7` | Potential Startup Shortcut Persistence Via PowerShell.EXE | file_event → `silver_file_events` (11) | high → high | T1547.001 | Nạp được |
| `DACN-SIG-0dba975d` | Uncommon Network Connection Initiated By Certutil.EXE | network_connection → `silver_network_events` (3) | high → high | T1105 | Nạp được |
| `DACN-SIG-36e037c4` | DNS Query Request By Regsvr32.EXE | dns_query → `silver_network_events` (22) | medium → medium | T1559.001, T1218.010 | Nạp được |
| `DACN-SIG-c7e91a02` | Network Connection Initiated By Regsvr32.EXE | network_connection → `silver_network_events` (3) | medium → medium | T1559.001, T1218.010 | Nạp được |
| `DACN-SIG-1139d2e2` | Usage Of Web Request Commands And Cmdlets - ScriptBlock | ps_script → `silver_powershell_scriptblock_events` (4104) | medium → medium | T1059.001 | Nạp được |
| `DACN-SIG-363eccc0` | Powershell Create Scheduled Task | ps_script → `silver_powershell_scriptblock_events` (4104) | medium → medium | T1053.005 | Nạp được |
| `DACN-SIG-403c2cc0` | Suspicious PowerShell Download - Powershell Script | ps_script → `silver_powershell_scriptblock_events` (4104) | medium → medium | T1059.001 | Nạp được |
| `DACN-SIG-09576804` | Suspicious PowerShell IEX Execution Patterns | process_creation → `silver_process_events` (1) | high → high | T1059.001 | Nạp được |
| `DACN-SIG-0ef56343` | Suspicious Execution of Systeminfo | process_creation → `silver_process_events` (1) | low → low | T1082 | Nạp được |
| `DACN-SIG-19b08b1c` | Suspicious Download Via Certutil.EXE | process_creation → `silver_process_events` (1) | medium → medium | T1027, T1105 | Nạp được |
| `DACN-SIG-24357373` | Direct Autorun Keys Modification | process_creation → `silver_process_events` (1) | medium → medium | T1547.001 | Nạp được |
| `DACN-SIG-379fa130` | File Deletion Via Del | process_creation → `silver_process_events` (1) | low → low | T1070.004 | Nạp được |
| `DACN-SIG-3b6ab547` | PowerShell Download Pattern | process_creation → `silver_process_events` (1) | medium → medium | T1059.001 | Nạp được |
| `DACN-SIG-7be5fb68` | Suspicious Execution of Hostname | process_creation → `silver_process_events` (1) | low → low | T1082 | Nạp được |
| `DACN-SIG-867356ee` | Potentially Suspicious Regsvr32 HTTP/FTP Pattern | process_creation → `silver_process_events` (1) | medium → medium | T1218.010 | Nạp được |
| `DACN-SIG-92626ddd` | Scheduled Task Creation Via Schtasks.EXE | process_creation → `silver_process_events` (1) | low → low | T1053.005 | Nạp được |
| `DACN-SIG-9fc51a3c` | Usage Of Web Request Commands And Cmdlets | process_creation → `silver_process_events` (1) | medium → medium | T1059.001 | Nạp được |
| `DACN-SIG-b66474aa` | Potential Persistence Via Powershell Search Order Hijacking - Task | process_creation → `silver_process_events` (1) | high → high | T1053.005, T1059.001 | Nạp được |
| `DACN-SIG-b98d0db6` | Remotely Hosted HTA File Executed Via Mshta.EXE | process_creation → `silver_process_events` (1) | high → high | T1218.005 | Nạp được |
| `DACN-SIG-ca2092a1` | Suspicious Encoded PowerShell Command Line | process_creation → `silver_process_events` (1) | high → high | T1059.001 | Nạp được |
| `DACN-SIG-de587dce` | Potential Persistence Attempt Via Run Keys Using Reg.EXE | process_creation → `silver_process_events` (1) | medium → medium | T1547.001 | Nạp được |
| `DACN-SIG-e593cf51` | Potentially Suspicious Rundll32 Activity | process_creation → `silver_process_events` (1) | medium → medium | T1218.011 | Nạp được |
| `DACN-SIG-f2c64357` | Suspicious Command Patterns In Scheduled Task Creation | process_creation → `silver_process_events` (1) | high → high | T1053.005 | Nạp được |
| `DACN-SIG-20f0ee37` | CurrentVersion Autorun Keys Modification | registry_set → `silver_registry_events` (13) | medium → medium | T1547.001 | Nạp được |
| `DACN-SIG-9c5037d1` | Suspicious Run Key from Download | registry_event → `silver_registry_events` (12, 13, 14) | high → high | T1547.001 | Nạp được |

Chưa chọn rule nào cho T1059.003 (C02 là đối chứng trong lượt Atomic).

Kiểm tra ngoài tập này (chỉ để đánh giá bộ biên dịch, không đưa vào repo): biên dịch toàn bộ 2.427 rule Windows của SigmaHQ cùng commit
→ 1.845 nạp được, 570 SIG-E002, 12 SIG-E003, không có lỗi bất thường. Đối chiếu ngữ nghĩa với bộ so khớp của pySigma 2.1.2 (cài tạm
trong thư mục scratchpad, không phải phụ thuộc của repo) trên sự kiện synthetic sinh từ giá trị của chính rule: 28 rule đã chọn
khớp 325/325; toàn kho 20.320 khớp, 85 lệch, đều ở hai chỗ đã biết: bộ lọc ngầm `EventType` của `registry_add`/`registry_delete`
(DACN có chủ ý) và cách hiểu `\*` trong một rule (DACN theo đặc tả). Đây là kiểm tra cú pháp/ngữ nghĩa, **không phải số đo phát hiện**.

## 6. Thêm rule Sigma

1. Chép tệp `.yml` **nguyên văn**:
   - rule SigmaHQ: `src/detection/sigma/rules/sigmahq/<đường dẫn trong kho SigmaHQ>` (cùng commit đã ghim; đổi commit thì cập nhật
     `source.commit` của manifest và kiểm lại mọi rule);
   - rule tự viết hoặc nguồn khác: `src/detection/sigma/rules/local/`.
2. Kiểm tra hỗ trợ:
   ```bash
   PYTHONPATH=src:poc/sysmon-collector python -m detection.sigma check src/detection/sigma/rules/local/<tệp>.yml
   # rule SigmaHQ: thêm --origin sigmahq
   ```
   Lệnh in kết luận (hỗ trợ / mã SIG-E* + lý do), bảng Silver, Event ID và **dòng manifest gợi ý** (có sha256).
3. Thêm dòng đó vào `src/detection/sigma/manifest.yaml` (rule `local` cần `license`). Sửa tệp sau này → sha256 lệch → SIG-E009,
   buộc cập nhật manifest có chủ ý (sha256 tính trên nội dung đã chuẩn hóa xuống dòng về LF, nên Git đổi CRLF trên Windows không ảnh hưởng).
4. `PYTHONPATH=src:poc/sysmon-collector python -m detection.sigma list` để xem toàn bộ đã nạp / bị loại.
5. Viết fixture synthetic có nhãn (TP/TN) trong `tests/detection/test_sigma_engine.py` nếu rule quan trọng.

## 7. Cấu hình và vận hành

`config/sigma-rules.yaml` (mặc định **tắt**):

| Khóa | Mặc định | Ý nghĩa |
|---|---|---|
| `enabled` | `false` | Bật thì core/API nạp rule Sigma vào cùng registry với rule DACN |
| `allow_experimental` | `false` | Nhận rule `status: experimental` |
| `max_rules` | 50 | Số rule Sigma bật tối đa; vượt → SIG-E011 |
| `regex_max_length` | 1000 | Độ dài tối đa một regex |
| `manifest` | `null` | `null` = `src/detection/sigma/manifest.yaml` |

- `python -m core` và `python -m api` nhận `--sigma-config <tệp>`; `edr_ctl start` dùng tệp mặc định, nên bật bằng cách sửa
  `enabled: true` trong `config/sigma-rules.yaml` rồi khởi động lại core.
- Đổi tập rule/phiên bản → chữ ký rule của engine đổi → quét lại lịch sử một lần (khử trùng theo `dedup_key`, không tạo alert trùng).
- Hiệu năng: mỗi rule đánh giá từng hàng Silver mới bằng Python. **Chưa đo** trên VM 2 GB; `max_rules` là giới hạn duy nhất hiện có.

### 7.1. API, dashboard, rủi ro

- `GET /sigma/rules` (vai trò đọc): `enabled`, nguồn (repository, commit, giấy phép), `loaded` (rule_id, id Sigma, tiêu đề, level,
  bảng Silver, tác giả, link rule gốc, ghi chú độ phủ), `rejected` (tệp, mã, lý do), bảng mã lỗi. `GET /sigma/rules/{rule_id}`:
  tóm tắt, rule DACN đã dịch, văn bản YAML gốc. Đường dẫn tệp nội bộ không trả ra.
- `GET /alerts?source=SIGMA`; `source_label = "Sigma"`. `source=DACN` giờ **không** gồm alert Sigma.
- Dashboard: cột/bộ lọc nguồn có "Sigma"; chi tiết alert có khung "Rule Sigma" (giải thích, tác giả, giấy phép, link rule gốc mở
  tab mới, `rel=noopener noreferrer`, chỉ link `https://`); trang Rules có mục "Rule Sigma" (đã nạp, bị loại kèm lý do, xem YAML gốc).
- Rủi ro: alert `detection_source = SIGMA` thuộc nhóm `SIGMA` (xem S4). Không bao giờ kích hoạt response (test AST
  `tests/detection/test_sigma_safety.py`).

## 8. Giấy phép (Detection Rule License 1.1)

Rule SigmaHQ theo DRL 1.1 (văn bản: `src/detection/sigma/rules/sigmahq/LICENSE.Detection.Rules.md`). DACN đáp ứng:
- chia sẻ rule: giữ tệp nguyên văn (có trường `author`), manifest ghi link kho + commit, kèm văn bản giấy phép;
- dùng rule trên dữ liệu: mọi kết quả MATCH/alert giữ `attribution.author` (DRL yêu cầu thông điệp khớp giữ tác giả), kèm giấy phép và
  link rule gốc; dashboard hiển thị.

## 9. Giới hạn đã biết

- Chưa chạy trên Windows 10 VM; chưa đối chiếu với Sigma trên dữ liệu thật; không có số liệu TP/FP/FN cho rule Sigma.
- Rule cộng đồng có thể nhiễu trên tải lành tính (ví dụ `Scheduled Task Creation`, `Systeminfo`, `Hostname` là rule level low
  mô tả hành vi phổ biến). Severity theo level Sigma, chưa hiệu chỉnh.
- Field vắng → INSUFFICIENT_TELEMETRY → `coverage_gaps`: nếu `raw_data` của một nguồn thiếu nhiều field, số coverage gap có thể lớn.
  Silver thật từ collector giữ đầy đủ EventData, nhưng chưa đo trên VM.
- Regex Python không có timeout; ngữ nghĩa regex Python khác PCRE ở vài cú pháp (pattern không biên dịch được → SIG-E010).
- windefend: Sigma đặt tên field theo dạng không dấu cách; ánh xạ sang cột Silver do Software đề xuất, chưa có mẫu thật cho mọi field.
- `ParentUser` cần Sysmon ≥ 13.30 (VM dùng v15.22).
- Đối chiếu pySigma chỉ chạy một lần trong phiên phát triển; không phải test tự động của repo.

## 10. Tệp liên quan

`src/detection/sigma/` (`compiler.py`, `fieldmap.py`, `loader.py`, `evaluate.py`, `errors.py`, `__main__.py`, `manifest.yaml`,
`rules/`), `src/detection/schema.py`, `src/detection/loader.py`, `src/detection/engine.py`, `src/alerts/store.py`, `src/api/app.py`,
`src/dashboard/static/`, `src/risk/`, `config/sigma-rules.yaml`, `config/risk-scoring.yaml` (v3), `tests/e2e/atomic_compare.py`
(`--sigma`). Test: `tests/detection/test_sigma_*.py`, `tests/api/test_sigma_api.py`, `tests/risk/test_sigma_risk.py`,
`tests/dashboard/test_dashboard_sigma.py`, `tests/e2e/test_atomic_compare.py`. Hướng dẫn VM:
`docs/implementation/acceptance/SIGMA_VM_GUIDE.md`.
