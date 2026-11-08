# EDR — Kiến trúc đích cho MVP

> **PROPOSAL — chờ phê duyệt** (2026-11-08). Chi tiết hóa kiến trúc `docs/architecture/local-edr-reference-architecture-v2.md` (cũng PROPOSAL) và ADR 0007 (PROPOSED) thành thiết kế **có thể triển khai trong repository hiện tại**. Không thay đổi ADR Accepted, `bronze-event/1.0`, UUIDv5 hay raw preservation. Không có thành phần nào dưới đây đã được triển khai.

## 1. Nguyên tắc

1. **Modular monolith, một máy Windows 10/11 (VirtualBox lab)**; không broker, cloud, cụm máy chủ, container (ADR 0007 phương án B).
2. Tận dụng tối đa mã hiện có: Bronze contract, adapter, validator, DDL v1.1.
3. Chỉ phần **phụ thuộc Windows** nằm trong các tiến trình riêng (Agent, Responder); phần còn lại là Python thuần, chạy và kiểm thử được trên Linux.
4. **Quyền tối thiểu:** chỉ Agent cần quyền đọc Event Log; chỉ Responder có quyền thực thi hành động; Core và API không có quyền response.
5. **Dữ liệu thô bất biến** (Bronze sealed), mọi kết quả suy ra truy vết được về `raw_xml`.
6. **Phát hiện ≠ ngăn chặn ≠ phản ứng sau phát hiện** — ba khái niệm tách bạch trong code, API, giao diện và báo cáo.
7. **Mặc định an toàn:** response `dry_run`, auto-response tắt, API chỉ bind `127.0.0.1`.
8. ML là tùy chọn cắm thêm qua giao diện; tắt ML không đổi hành vi hệ thống.

## 2. So sánh phương án

| Tiêu chí | **A. Modular monolith + spool tệp (đề xuất)** | B. Mọi thứ trong một tiến trình | C. Agent → máy chủ qua mạng (REST/gRPC), nhiều dịch vụ |
|---|---|---|---|
| Phù hợp ADR/kiến trúc v2 | Khớp (sealed JSONL → Silver) | Lệch (mất độ bền Bronze) | Lệch (XDR/phân tán) |
| Chi phí xây dựng | Trung bình | Thấp nhất | Cao |
| Độ phức tạp vận hành | Thấp (3 tiến trình) | Thấp nhất | Cao (mạng, xác thực, dịch vụ) |
| Phục hồi sau sự cố | Tốt (Bronze bền, replay) | Kém | Trung bình |
| Quyền tối thiểu | Tốt (Agent/Responder tách) | Kém (một tiến trình quyền cao) | Tốt |
| Kiểm thử độc lập từng module | Tốt (nguồn giả, spool tệp) | Trung bình | Phức tạp |
| Khả năng thêm ML sau | Tốt | Tốt | Tốt |
| Phù hợp thời gian còn lại | **Tốt** | Tốt | Kém |

**Đề xuất: A.** Lý do: bám kiến trúc đã đề xuất, bảo toàn raw và replay (điều kiện truy vết), ít phụ thuộc, tách quyền, và kiểm thử được phần lớn trên Linux.

## 3. Thành phần và tiến trình

```
┌─────────────────────────── Windows 10/11 VM (lab, snapshot sạch) ───────────────────────────┐
│ Sysmon ─► Event Log (Microsoft-Windows-Sysmon/Operational)                                    │
│                       │ đọc (pywin32)                                                         │
│                ┌──────▼───────┐   sealed JSONL + manifest    ┌────────────────────────────┐  │
│                │ edr-agent    │ ───────────────────────────► │ edr-core (một tiến trình)   │  │
│                │ [Windows]    │   <EDR_HOME>\data\bronze\    │  ingest ► validate ► Silver │  │
│                │ checkpoint   │                              │  (DuckDB, single-writer)    │  │
│                │ health.json  │                              │  detection engine + IOC     │  │
│                └──────────────┘                              │  alert/incident store       │  │
│                                                              │  API (FastAPI, 127.0.0.1)   │  │
│                ┌──────────────┐  HTTP + token, kéo           │  dashboard (tệp tĩnh)       │  │
│                │ edr-responder│ ◄──────────────────────────► │  response policy + queue    │  │
│                │ [Windows]    │  hành động đã DUYỆT          └─────────────▲──────────────┘  │
│                │ dry_run mặc  │                                            │ HTTP             │
│                │ định         │                              Trình duyệt (người vận hành)       │
│                └──────────────┘                                                                │
└────────────────────────────────────────────────────────────────────────────────────────────────┘
```

| Tiến trình | Chạy ở | Quyền | Trách nhiệm |
|---|---|---|---|
| `edr-agent` | Windows (bắt buộc) | Đọc Event Log (thường cần Administrator hoặc nhóm Event Log Readers); ghi `data\bronze` | Thu thập, đóng gói `bronze-event/1.0`, bookmark, seal segment, heartbeat |
| `edr-core` | Windows trong MVP; chạy được trên Linux khi test | Người dùng thường; đọc Bronze, ghi Silver | Nạp, kiểm tra, lưu; phát hiện; alert; API; dashboard |
| `edr-responder` | Windows | Tối thiểu cho hành động được bật (mặc định dry-run) | Kéo hành động đã duyệt, xác minh mục tiêu, thực thi hoặc dry-run, báo kết quả |
| `edr_ctl` | Bất kỳ | Người dùng | Khởi động/dừng/trạng thái 3 tiến trình, không cài service |

**Lý do gộp ingest + detection + API trong một tiến trình:** DuckDB nhúng chỉ nên có một writer; API đọc qua cursor cùng tiến trình, tránh khóa tệp trên Windows.

## 4. Luồng dữ liệu và giao tiếp

| Luồng | Cơ chế | Hợp đồng |
|---|---|---|
| Sysmon → Agent | Event Log (pywin32) | XML nguyên bản |
| Agent → Core | **Tệp**: segment `.jsonl` đã seal + `.manifest.json` (sha256, số bản ghi) | `bronze-event/1.0` (JSON Schema hiện có) |
| Core nội bộ | Hàm Python | Adapter → validator → Silver (DDL v1.1 → v1.2 đề xuất) |
| Detection → Alert | Hàm Python | `DetectionResult` → alert (hợp đồng cần duyệt) |
| Core ↔ Responder | HTTP localhost, Bearer token, Responder **kéo** | `ResponseAction` |
| Core ↔ Trình duyệt | HTTP localhost, token | API REST JSON |
| Agent/Responder → Core (sức khỏe) | `health.json` đọc bởi Core | Trường heartbeat |

## 5. Lưu trữ (theo ADR 0005)

```
<EDR_HOME>\            (mặc định C:\EDR, đường dẫn ngắn)
  config\   edr.yaml, response-policy.yaml, rules\*.yaml, ioc\
  data\
    bronze\sysmon\<host_id>\YYYY\MM\DD\*.jsonl(.part), *.manifest.json
    quarantine\collector\  quarantine\validation\  quarantine\segments\
    silver\endpoint_silver.duckdb   (Silver + alert/incident/audit/response trong cùng tệp)
    response_quarantine\            (tệp cách ly có metadata để khôi phục)
    checkpoints\agent.bookmark.json
  logs\     agent.jsonl core.jsonl responder.jsonl metrics.jsonl
  run\      *.pid, *.lock
```

Parquet/Gold feature store chỉ là P1/P2 (phục vụ ML), không bắt buộc cho MVP.

## 6. Cấu trúc mã nguồn đề xuất

Giữ `poc/sysmon-collector/` và `src/pipeline/` nguyên vị trí (liên kết tài liệu và schema không đổi); thêm package mới dưới `src/` (khớp đề xuất issue #40); thêm `conftest.py`/`pytest.ini` đặt `pythonpath` (quyết định D-03).

```
src/
  common/      config.py  log.py
  agent/       sources/{base,file_source,fake_source,eventlog}.py  bronze_writer.py  checkpoint.py  runner.py  health.py
  pipeline/    (có sẵn) validator_poc.py  sql/…   + segment_reader.py silver_store.py query.py ingest_worker.py
  detection/   schema.py loader.py engine.py evaluator.py correlator.py ioc.py  ml/{interface,features,loader}.py
  alerts/      builder.py store.py evidence.py timeline.py
  response/    policy.py actions.py executor.py responder.py backends/{dryrun,fake,windows}.py
  api/         app.py auth.py routes/…
  dashboard/   static/
  edr_ctl.py
rules/         DACN-DET-001.yaml …          (rule có phiên bản)
config/        edr.example.yaml response-policy.example.yaml
tests/         common/ agent/ pipeline/ detection/ alerts/ response/ api/ dashboard/ e2e/ fixtures/
```

## 7. Công nghệ (kiểm tra theo code và tài liệu)

| Lớp | Lựa chọn | Căn cứ | Phụ thuộc mới? |
|---|---|---|---|
| Ngôn ngữ | Python ≥ 3.11 | `docs/research/software/w1/05` nêu 3.11; môi trường kiểm toán 3.13 | — |
| Windows Event Log | `pywin32` (`win32evtlog`) | đã dùng trong live mode | Có sẵn trong code, chưa trong manifest |
| Lưu trữ | DuckDB | ADR 0005, DDL | Đã dùng |
| Validation schema | `jsonschema` | đã dùng | Đã dùng |
| Rule | YAML + JSON Schema | kiến trúc v2 mục 6.2 | **PyYAML** (D-05) |
| API | FastAPI + uvicorn (đề xuất) | Pydantic đã xuất hiện trong tài liệu; sinh OpenAPI, dễ test | **fastapi, uvicorn** (D-04) |
| Dashboard | HTML/JS tĩnh phục vụ bởi API | ít phụ thuộc, chạy offline, không build | Không |
| Test | pytest, Playwright (UI) | đã dùng / có sẵn trong môi trường kiểm toán | — |

**Phương án API/UI đã so sánh (D-04):** (1) stdlib `http.server` — không phụ thuộc nhưng phải tự viết validation/OpenAPI; (2) **FastAPI + trang tĩnh** — đề xuất; (3) Streamlit (đã nhắc trong tài liệu Software W5) — nhanh để dựng nhưng nặng phụ thuộc, không có API để kiểm thử, mô hình tự chạy lại dễ xung đột với DuckDB single-writer. Nếu nhóm đã chọn Streamlit, vẫn cần lớp `query.py` chung và UI chỉ đọc snapshot.

## 8. Hợp đồng và schema cần có

| Hợp đồng | Trạng thái | Hành động |
|---|---|---|
| `bronze-event/1.0` | Đề xuất, chưa phê duyệt chéo | **Không đổi**; xin sign-off (#26–#29) |
| Silver v1.1 (DDL) | Chạy được, khớp validator | Dùng nguyên; đề xuất v1.2 |
| DDL v1.2 (lineage, detection_results, alerts mở rộng, incidents, response_actions, audit_log) | Chưa có | PH6-T01, **cần duyệt** |
| Rule schema (YAML + JSON Schema) | Chưa có | PH4-T01 |
| `DetectionResult` / `AnomalyResult` | Chưa có (nháp trong kiến trúc v2 mục 6.3) | PH4-T02, **cần duyệt** |
| API (OpenAPI) | Chưa có | PH8 |
| `ResponseAction`, response policy | Chưa có | PH7 |
| Cấu hình `edr.yaml` | Chưa có | PH1-T09 |

## 9. Triển khai trên Windows 10 VirtualBox

- Cấu hình tham chiếu: Windows 10 64-bit, ≥ 4 GB RAM, ≥ 2 vCPU (`docs/research/software/w1/05`), Sysmon phiên bản cố định (mẫu lab dùng 15.22), Python cố định, snapshot "clean".
- Cài đặt: Python + dependency ghim phiên bản; Sysmon cài **bởi người dùng** với cấu hình của repository; `EDR_HOME=C:\EDR`.
- Khởi động: `python -m edr_ctl start` (không đăng ký service); dừng bằng `stop`. Dịch vụ Windows là P2.
- Bất kỳ lệnh có tác dụng phụ (cài Sysmon, bật audit, đổi cấu hình) do người dùng thực hiện có hướng dẫn và cách hoàn tác.
- Mọi con số tài nguyên (CPU/RAM) chỉ ghi sau khi đo trên VM.

## 10. Lỗi, logging, khởi động/dừng

- Log JSONL theo thành phần (`ts, level, component, run_id, event, reason_code`), không ghi command line thô.
- Mã lỗi: `C-xxx` (collector), `V-xxx`/`ERR_*` (validation), mã response riêng; lỗi tạm thời → retry backoff có giới hạn, lỗi vĩnh viễn → quarantine + tiếp tục.
- Dừng sạch: seal segment + lưu bookmark (Agent); hoàn tất batch + đóng DuckDB (Core).
- Health: heartbeat Agent, lag ingest, DLQ, độ sâu hàng đợi, số hành động lỗi. **Health alert tách khỏi threat alert**; mất heartbeat chỉ chứng minh khoảng trống tầm nhìn, không chứng minh bị can thiệp.

## 11. Khả năng bổ sung AI/ML

`MLDetector` (Protocol) nhận `FeatureVector` có `feature_schema_version`, trả `AnomalyResult(score, explanation, model_version, source_event_ids)`. Engine hợp nhất kết quả rule/IOC/ML trong `RiskAggregator` (P1). `NullDetector` là mặc định. Mô hình được nạp từ artifact có hash; sai schema thì từ chối. ML **không** kích hoạt response và không nằm trên critical path MVP. Xem [AI_TRAINING_GUIDE.md](AI_TRAINING_GUIDE.md).

## 12. Ranh giới bảo mật chính (tóm tắt, chi tiết theo `dacn-security-threat-modeling`)

| Ranh giới | Rủi ro | Biện pháp trong thiết kế |
|---|---|---|
| Bronze sealed | Sửa/xóa bằng chứng | Manifest + sha256, ACL NTFS, đọc chỉ segment sealed |
| Rule/IOC/policy | Bị sửa | Phiên bản + checksum, nạp qua kiểm tra schema, không sửa qua UI |
| API | Truy cập trái phép | Bind localhost, token, vai trò đọc/duyệt tách biệt, audit |
| Responder | Leo thang, thao tác nhầm | Pull-only, token, dry-run mặc định, allowlist bảo vệ, xác minh danh tính mục tiêu |
| Dữ liệu nhạy cảm | Lộ user/path/command line | Fixture đã khử định danh; raw XML chỉ cho vai trò được phép và có audit |
| Giới hạn | Agent user-space dựa Sysmon | Không tuyên bố tamper-resistant; ghi trong báo cáo |

## 13. Trạng thái triển khai (cập nhật khi làm)

Tất cả thành phần ở mục 3–6 hiện **PLANNED** trừ Bronze contract, adapter, validator và DDL (IMPLEMENTED, xem [EDR_AUDIT_REPORT.md](EDR_AUDIT_REPORT.md)).
