# EDR — Báo cáo kiểm toán Giai đoạn 0

> Ngày kiểm toán: **2026-11-08** (đo lúc ~09:55 UTC). Môi trường: Linux container (Python 3.13, pytest 9.2, duckdb 2.0.0, jsonschema, pydantic). **Không phải Windows.** Không sửa mã nguồn trong giai đoạn này.
> Mọi trạng thái dưới đây chỉ đúng tại thời điểm trên; chạy lại trước khi dựa vào.

## 1. Nhãn trạng thái

`IMPLEMENTED` đã có code · `VERIFIED` đã kiểm chứng bằng test/chạy thực tế (nêu môi trường) · `PARTIAL` · `PLANNED` · `BROKEN` lỗi đã tái hiện · `UNKNOWN` chưa đủ bằng chứng.

## 2. Phương pháp và nguồn

- Đã đọc: `CLAUDE.md`, `README.md`, ADR 0001–0007, kiến trúc v2, `docs/scope/*`, `docs/architecture/w5/*`, tài liệu Cyber/Software W3–W5, kế hoạch 12 tuần (bản trong PR #36, chưa merge), toàn bộ mã trong `poc/sysmon-collector/` và `src/pipeline/`, DDL, test, 25 skill trong `.claude/skills/`.
- Đã chạy: hai bộ pytest; chuỗi XML mẫu → Bronze → schema → adapter → validator; DDL trong DuckDB; `contract_check.py` (ghi ra ngoài repository); demo `validator_poc.py`.
- GitHub (qua công cụ session): 7 issue mở (#26–#29, #38–#40), PR gần đây (#32–#36, #41–#45), **PR #36 đang mở** (kế hoạch 12 tuần v2). Trạng thái issue **không** dùng để kết luận chức năng đã xong.

## 3. Kết quả kiểm thử thực tế

| Lệnh (từ thư mục gốc) | Kết quả | Ghi chú |
|---|---|---|
| `python -m pytest -q poc/sysmon-collector` | 25 pass, **1 fail** | `test_collector_errors_use_reason_codes` |
| `python -m pytest -q tests/` | 5 pass, **1 fail** | `test_06_time_skew_warning_and_shannon_entropy` |

**Nguyên nhân đã xác minh:**
1. `test_collector_errors_use_reason_codes` — `_parse_event_element` (`sysmon_collector_poc.py`) ném `Event XML is missing EventID or TimeCreated` không kèm mã; test (và bảng mã lỗi W5) kỳ vọng `C-002`. Lỗi nằm ở thông báo lỗi của collector, `build_bronze_record` thì đã có mã. **Trạng thái: BROKEN (nhỏ).**
2. `test_06` — hàm `calculate_shannon_entropy` **đúng** (tính độc lập cho 4,7322). Chuỗi dòng lệnh trong test chỉ có 42 ký tự khác nhau nên entropy tối đa là 5,39 và thực tế 4,73 < 5,0; riêng phần payload base64 UTF-16LE chỉ 3,95 do lặp ký tự `A`. **Kỳ vọng của test không khả thi cho chuỗi này; entropy dòng lệnh > 5 cũng là heuristic yếu cho `-Enc`.** **Trạng thái: BROKEN (test), logic hàm VERIFIED.** Cần Data quyết định sửa fixture hay ngưỡng.

**Kiểm tra bổ sung (tự thực hiện, không nằm trong test của repository):**
- 18 sự kiện từ 9 file raw mẫu + 1 synthetic → Bronze (0 lỗi JSON Schema) → adapter (không lỗi) → validator: **16 vào Silver, 2 vào DLQ** (Event 4 và 16, `ERR_UNSUPPORTED_EVENT_ID`).
- `contract_check.py`: 225 sự kiện (ID 1, 3, 4, 5, 11, 12, 13, 16, 22, 26, 29), **0 vi phạm envelope Bronze**.
- DDL `silver_gold_schema_and_views_v1_1.sql` **chạy được** trong DuckDB (7 bảng + 4 view + 2 bảng Gold). Cột hàng Silver do validator tạo **trùng khớp** cột DDL của 4 bảng Silver (không có cột thừa/thiếu).
- `contract_check.py` có bảng `EXPECTED` lỗi thời: báo `missing_in_silver` cho `ParentImage`, `IntegrityLevel`, `TerminalSessionId`, `DestinationIsIpv6`, `DestinationHostname`… trong khi DDL v1.1 và validator **đã có** cột tương ứng. Báo cáo coverage đang đánh giá thấp hiện trạng.

## 4. Đánh giá theo module

### Software

| Module | Trạng thái | Bằng chứng / giới hạn | Quyết định |
|---|---|---|---|
| Parse + normalize Sysmon XML (`sysmon_collector_poc.py`) | IMPLEMENTED, VERIFIED (file mode, Linux) | 13 test collector; mapping Event 1, 3, 4, 5, 11, 12, 13, 14*, 15, 16, 22, 23, 26, 29 (*14, 15 không có mẫu) | **Giữ**, sửa mã lỗi C-002 |
| Live mode (`iter_events_live`) | IMPLEMENTED, **UNKNOWN trên Windows** | `EvtQuery`+`EvtNext` newest-first tối đa N sự kiện; không phải theo dõi liên tục; không bookmark; chưa chạy trên Windows | **Thay thế bằng nguồn mới** (PH2) |
| Bronze envelope + schema (`bronze_contract.py`, schema JSON) | IMPLEMENTED, VERIFIED (0 lỗi trên 225 sự kiện) | Hợp đồng chung ghi **chưa phê duyệt chéo** | **Giữ nguyên**, chờ sign-off |
| Segment writer / manifest / checkpoint / replay | PLANNED | Thiết kế ở W5-01, W5-04; không có code | **Xây mới** |
| Agent chạy liên tục / dịch vụ | PLANNED | Không có | **Xây mới** (runner trước, service tùy chọn) |
| Config / logging | **Không có** | Không dùng `logging`; CLI `argparse` đơn lẻ | **Xây mới** |
| Script lab PowerShell (`run-poc-activities.ps1`, `export-samples.ps1`) | IMPLEMENTED, UNKNOWN (ghi chú trong file: "chưa chạy trên máy thật") | Chưa đọc kỹ từng dòng; cần người dùng duyệt trước khi chạy | **Giữ**, rà soát |
| Sysmon config (`sysmon-config.xml`, 78 dòng) | IMPLEMENTED | SHA256+IMPHASH; ProcessCreate/Terminate/Network/DNS exclude-rỗng; File/Registry include-lọc; **Event 7, 8, 10 không bật** | **Giữ**, đối chiếu kịch bản (PH2-T08) |

### Data

| Module | Trạng thái | Bằng chứng / giới hạn | Quyết định |
|---|---|---|---|
| Adapter Bronze → Silver (fail closed) | IMPLEMENTED, VERIFIED | 3 test + chạy trên mẫu; kiểm `event_id`, `host_id`, đối chiếu `raw_xml` | **Giữ** |
| Validator (`validator_poc.py`, 909 dòng) | IMPLEMENTED, VERIFIED một phần | 6 test (1 fail do test); chỉ trong bộ nhớ; 10 mã `ERR_*`; dedup theo `event_id` | **Giữ logic, sửa, bọc bằng store bền vững** |
| DDL Silver/Gold v1.1 | IMPLEMENTED (chạy được), chưa được code nào dùng | Khớp cột validator; `gold_*` chưa có writer | **Giữ**; thêm v1.2 (đề xuất) |
| Persistent Silver, ledger, replay | PLANNED | Không có | **Xây mới** |
| Quarantine DLQ bền vững | PARTIAL | Có DLQ trong bộ nhớ (`QuarantineRecord`), chưa ghi file/bảng | **Xây tiếp** |
| Lớp truy vấn / index | PLANNED | Chỉ có view `v_process_tree_lineage` trong DDL | **Xây mới** |
| Feature/Gold | PLANNED | `gold_process_features` là DDL; entropy có hàm | **Xây mới** (P1) |
| Lineage về Bronze (segment/line/hash) | PLANNED | `bronze_source` chỉ là metadata PoC, chưa là cột Silver | **Xây mới, cần duyệt DDL** |

### Cybersecurity

| Module | Trạng thái | Bằng chứng / giới hạn | Quyết định |
|---|---|---|---|
| Threat model v1 | IMPLEMENTED (tài liệu) | Hành vi cần phát hiện; chưa có STRIDE cho chính EDR | **Giữ**, bổ sung |
| 13 MITRE technique + DET-001..010 | IMPLEMENTED (đặc tả), **chưa có engine** | Ma trận trường: DET-001, 002, 003, 010 khả thi với Sysmon hiện có; DET-004 cần Security 4698/4702; DET-007, 008 bị chặn (không đủ telemetry) | **Dùng làm đầu vào** |
| Detection Engine, rule engine, IOC, alert store | PLANNED / **không tồn tại** | | **Xây mới** |
| Rule thực thi được | **0** | | |
| Alert schema | PARTIAL | `gold_security_alerts` (DDL) có thiếu sót (xem mục 6) | **Sửa qua DDL v1.2** |
| Response Engine, policy | PLANNED | Chỉ có thiết kế (kiến trúc v2 mục 7.2) | **Xây mới** |
| Kịch bản kiểm thử an toàn | PARTIAL | Kế hoạch Atomic Red Team (W4-03), `silver_atomic_test_runs` (DDL); chưa chạy | **Xây mới** (PH5) |
| Telemetry thật phục vụ detection | PARTIAL | Mẫu W3 chủ yếu benign; không có mẫu Run/RunOnce thật; ID 14, 15 không có mẫu | **Bổ sung trên VM** |

### Kiểm thử

| Mục | Hiện trạng |
|---|---|
| Module có test | collector (13), Bronze contract (10), adapter (3), validator (6) |
| Module **chưa** có test | `contract_check` (có test gián tiếp), mọi thành phần mới; không test cho logging/config (chưa tồn tại); không test cho script PowerShell |
| Bắt buộc chạy trên Windows | live mode, quyền Event Log, Sysmon thật, hành vi đổi tên/khóa file trong segment writer, kịch bản mô phỏng, response thật |
| Chưa có | CI (`.github/` không tồn tại), `requirements.txt`/`pyproject.toml`, linter/type checker, marker `windows`, cấu hình `pythonpath` |

## 5. Lỗi và nợ kỹ thuật

| ID | Mô tả | Mức | Trạng thái |
|---|---|---|---|
| TD-01 | Thông báo lỗi parse thiếu mã `C-002` | Thấp | BROKEN, nguyên nhân xác minh |
| TD-02 | Test entropy kỳ vọng không khả thi | Thấp | BROKEN (test) |
| TD-03 | Silver ghi `hostname.upper()` trong khi `event_id` tính trên hostname gốc → tính lại từ Silver cho UUID khác | **Cao** (truy vết/replay) | Tái hiện được, cần quyết định |
| TD-04 | Silver cắt timestamp 100 ns → µs | Trung bình | Tái hiện được |
| TD-05 | Event 4/16 vào DLQ làm nhiễu chỉ số | Trung bình | Tái hiện được |
| TD-06 | Hai bộ tên event type (collector ≠ validator), chờ Q-X3 | Trung bình | Xác nhận trong code |
| TD-07 | `contract_check.EXPECTED` lỗi thời | Thấp | Tái hiện được |
| TD-08 | Không có logging/config/dependency manifest/CI | Cao | Xác nhận |
| TD-09 | Import tên module trần, phụ thuộc chạy từ thư mục gốc | Trung bình | Xác nhận |
| TD-10 | Mẫu `sanitized:false` chứa định danh thật | Cao (privacy) | Ghi nhận trong tài liệu, chưa xử lý |
| TD-11 | Live mode chỉ đọc N sự kiện mới nhất, không theo dõi | **Cao** | Xác nhận trong code |
| TD-12 | `process_guid` bắt buộc ở validator cho mọi sự kiện được hỗ trợ; DDL `gold_security_alerts.process_guid NOT NULL` | Trung bình | Xác nhận |

## 6. Phụ thuộc giữa ba nhóm

- **Software → Data:** hợp đồng Bronze `bronze-event/1.0` (**chưa phê duyệt chéo**), segment/manifest, lỗi `C-xxx`. Data cần segment sealed trước khi nạp bền vững.
- **Data → Cyber:** Silver 4 bảng + lớp truy vấn + lineage; Cyber cần `required_fields` thật cho DET-001/003/010 và tham chiếu raw cho alert.
- **Cyber → Software/Data:** `DetectionResult`/alert contract (cột còn thiếu ở mục 4), policy response, kịch bản mô phỏng; Software thực thi response.
- **Mâu thuẫn tài liệu ↔ code ↔ issue cần ghi nhận:**
  1. Kế hoạch 12 tuần (PR #36, chưa merge) đặt Phase 1 chủ yếu là nghiên cứu/thiết kế, PoC thực thi là *tùy chọn*; mục tiêu mới của người dùng là **EDR chạy được** → lệch phạm vi (xem quyết định D-01).
  2. Tài liệu Data ghi trạng thái "APPROVED" trong khi Software còn DRAFT (W5-CY-15); ADR 0007 vẫn PROPOSED.
  3. `CLAUDE.md` mục 3.1 nói DDL "chưa có code thực thi": đúng ở mức tích hợp; nhưng DDL chạy được và khớp validator (kết quả kiểm toán này).
  4. Issue #38–#40 (W06–W07) đề xuất cấu trúc `src/detection/`; chưa tồn tại.

## 7. Rủi ro ảnh hưởng việc hoàn thiện EDR

| Rủi ro | Tác động | Giảm thiểu |
|---|---|---|
| Phạm vi MVP lớn hơn kế hoạch 12 tuần | Trượt tiến độ, ảnh hưởng đồ án | D-01: người dùng chọn phạm vi; làm P0 theo critical path |
| API `pywin32` bookmark/subscription chưa kiểm chứng | Agent không nhận sự kiện liên tục | PH2-T05 spike sớm |
| Defender can thiệp mẫu thử (EICAR, tệp lạ) | Không tách được "EDR phát hiện" khỏi "Defender phát hiện" | Kịch bản ưu tiên mô phỏng không phải malware; ghi nguồn phát hiện |
| Quyết định hợp đồng chưa chốt (hostname, event type, lineage, DDL v1.2) | Làm lại về sau | Chốt trong PH1 trước khi xây Silver bền vững |
| Telemetry không đủ cho một số rule (DET-004, 007, 008; file write) | Rule không phát hiện được | Đánh dấu `blocked`, không tuyên bố |
| DuckDB single-writer | Khóa ghi khi nhiều tiến trình | Một tiến trình core giữ DB; API chạy trong tiến trình đó |
| Mẫu chứa định danh thật | Rò rỉ khi demo/báo cáo | PH1-T12 fixture đã khử định danh |
| Chưa có CI/dependency manifest | Khó tái lập | PH1-T08/T11, đề xuất file dependency (cần duyệt) |

## 8. Thành phần: giữ / sửa / thay thế / xây mới

- **Giữ nguyên:** `bronze_contract.py` + schema, `bronze_to_silver_adapter.py`, DDL v1.1, mapping `_map_data`, mẫu raw, kiến trúc v2, ADR 0001–0003.
- **Sửa:** mã lỗi `C-002`, test entropy, chuẩn hóa hostname (cần quyết định), Event 4/16, tên event type, `contract_check.EXPECTED`.
- **Thay thế:** `iter_events_live` (→ `EventLogSource` có bookmark); validator "in-memory only" (→ bọc bởi store bền vững, giữ logic).
- **Xây mới:** agent runner + segment writer + checkpoint; persistent Silver + ledger + replay + truy vấn; detection engine + rule + IOC; alert/incident; response + policy; API; dashboard; launcher; config/logging; bộ kịch bản và test e2e.

## 9. Quyết định cần người dùng phê duyệt

Xem mục "Quyết định cần phê duyệt" trong [EDR_MASTER_PLAN.md](EDR_MASTER_PLAN.md) (D-01…D-12).
