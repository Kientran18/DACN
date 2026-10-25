# Báo cáo tuần 1 — Khảo sát nền tảng dữ liệu Local EDR

**Phạm vi:** W01 Data, issue [#2](https://github.com/Kientran18/DACN/issues/2), tổng hợp theo bằng chứng repository tính đến 25/10/2026. **Trạng thái:** Đã có đặc tả đầu vào, chưa đủ bằng chứng để công bố pipeline DuckDB hoạt động ở tuần 1.

## 1. Kết quả có thể kiểm chứng

- Đã xác định tám nhóm dữ liệu: process, file, registry, network, file metadata, alert, feature và model prediction. Đặc tả nghiên cứu tại [W1 data requirements](../architecture/w1/edr_data_requirements_architecture.md) và [danh mục yêu cầu](../research/data/w1/data_requirements.md).
- Đã nhận diện các trường truy vết tối thiểu dự kiến: event identity, timestamp, host/source, process context và raw source data; quy tắc đầy đủ theo Event ID được phát triển ở W3 và hiệu chỉnh tại W5.
- Đã phác thảo backlog Data/AI và kiến trúc Bronze/Silver/Gold. Đây là **thiết kế**, không có nghĩa đã triển khai tính năng, training pipeline hay feature store.
- Phạm vi Phase 1 được thống nhất trong [local scope](../scope/data_pipeline_phase_1_scope.md) và [architecture mapping](../architecture/w2/phase_1_local_data_architecture_mapping.md): một Windows endpoint; Sysmon/Windows Event Log → Python collector → Bronze JSONL → Silver DuckDB → Gold/AI theo các tuần thiết kế tiếp theo.

## 2. Phân biệt tài liệu tham khảo và code hiện có

Bản đặc tả W1 ban đầu còn mô tả Kafka/Fabric, native kernel agent, OneLake, GNN và các giới hạn tài nguyên chưa đo. Đó là **phương án mở rộng/định hướng kiến trúc**, không phải hệ thống đã chạy ở Phase 1. Mốc hiện có trên repository đến 25/10:

| Thành phần | Hiện trạng minh chứng | Giới hạn |
|---|---|---|
| Tám nhóm dữ liệu, envelope ban đầu | Tài liệu nghiên cứu W1 | Một số trường được sửa ở W3/W5 |
| Sysmon file-mode collector | `poc/sysmon-collector/sysmon_collector_poc.py`, mẫu thực W3 | Không phải kết quả nghiệm thu W1; chưa chứng minh live mode |
| DDL Silver/Gold, validator | `src/pipeline/` (công việc giai đoạn W5) | Không quy công triển khai về tuần 1 |
| `pipeline/schemas/events.py`, `pipeline/storage/db.py`, `pipeline/ingestion/collector.py`, `pipeline/process_pipeline.py` | **Không có các đường dẫn này trong main** | Không tuyên bố đã code/chạy ở W1 |
| `test_schema.py`, `test_pipeline_e2e.py`, dữ liệu Silver DuckDB vận hành W1 | **Không có bằng chứng file, log test, DB artifact tương ứng trong main** | Bỏ các phát biểu “3/3”, “19/19”, “pipeline E2E PASS” của bản cũ |
| Performance (CPU/RAM/latency) | Mục tiêu thiết kế, chưa có benchmark W1 | Không ghi số liệu đo giả |

## 3. Kết quả bàn giao và tồn đọng

**Bàn giao W1:** các nhóm dữ liệu, trường định danh ban đầu, backlog nghiên cứu, phạm vi Windows/local và điểm giao diện cần thống nhất với Cyber/Software.

**Còn cần xác nhận:** người review độc lập, tài liệu backlog và lịch planning/review cuối W1; đánh giá tính phù hợp của các trường từ mẫu Sysmon (W3). Trạng thái issue Closed không thay thế bằng chứng xác nhận từng DoD.

**Nguồn:** [Issue #2](https://github.com/Kientran18/DACN/issues/2), [architecture W1](../architecture/w1/edr_data_requirements_architecture.md), [W2 mapping](week_02_behavior_telemetry_mapping.md), [W3 schema](../architecture/w3/endpoint_event_schema_v1.md), [W5 schema reconciliation](../architecture/w5/schema_reconciliation_and_dictionary_v1_1.md).
