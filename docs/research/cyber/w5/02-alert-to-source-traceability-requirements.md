# W05 Cyber — Alert-to-Source Traceability Requirements v1

**Issue:** #28 | **Trạng thái:** Thiết kế phục vụ W06/W09; chưa có detection/alert engine end-to-end.

## 1. Yêu cầu truy vết

Luồng mục tiêu:

```text
Sysmon raw XML (System / EventData)
 → Collector + Bronze segment/manifest [source_ref, checksum, line_no]
 → Silver [event_id, source_ref, mapping_version]
 → Feature [source_event_ids[], feature_version, window]
 → Detection result [rule_id, rule_version, matched_fields, missing_fields]
 → Alert/Incident [contributing_event_ids[], severity_reason]
 → Investigation: truy vấn ngược đến raw XML.
```

**Nguyên tắc:** truy vết phải đi **hai chiều**, không cho phép alert chứa event giả, không thay sự kiện raw bằng suy luận Silver, không đánh đồng "có event" với hành vi độc hại.

| Cấp | Trường/khóa phải giữ | Điều kiện |
|---|---|---|
| Source/Bronze | `hostname,channel,record_id,sysmon_event_id,time_created,raw_xml` hoặc raw_ref bền vững, segment/offset, integrity hash, collector version | Có thể dựng lại payload gốc; phát hiện file đổi hoặc mất |
| Silver | `event_id,hostname,channel,record_id,timestamp,raw_data`, ingest time, schema/mapping version, raw_ref | `event_id` là UUIDv5 và **khác** `sysmon_event_id`; log reset cần epoch/khả năng phân biệt |
| Process graph | `hostname,process_guid,parent_guid,pid,ppid` khi EventID hỗ trợ | Link bằng GUID+host, không dùng PID đơn lẻ, ID5 không có parent fields |
| Feature | `feature_record_id,source_event_ids[],window_start/end,feature_version` | Không sử dụng aggregate thiếu nguồn để chứng minh attack |
| Detection/Alert | `alert_id,rule_id,rule_version,contributing_event_ids[],severity,confidence,matched_fields,missing_fields,coverage_status` | Thiếu source ⇒ trạng thái PARTIAL/INSUFFICIENT; W05 chưa triển khai |
| Investigation/Response (W09) | `incident_id,alert_ids[],reviewer,status,action_audit,approval` | Không tự terminate/quarantine dựa trên prototype |

**Vấn đề hợp đồng cần Data/Software chốt:** phần Data Bronze v1.1 mô tả `raw_data,timestamp,bronze_ingest_utc,collector_batch_id,raw_payload_sha256`, phần Software Bronze `bronze-event/1.0` đề xuất `event_data,raw_xml,time_created,ingest.*,host_id`. Cyber yêu cầu **một adapter/contract phiên bản hóa** và raw reference thực sự. Software đề xuất `_bronze_segment,_bronze_line,_ingest_run_id` nhưng DDL Silver chưa có hợp đồng provenance tương đương rõ ràng. Không được claim end-to-end lineage hoàn tất trước khi chốt.

## 2. Ví dụ truy vết dựa trên mẫu Windows W03

Các sự kiện dưới đây là **PoC benign**, không phải attack detection. Đọc trực tiếp `references/samples/json/{file,process}.json` và `references/samples/raw/raw_file_delete_event26.xml`.

| Bước | Bằng chứng gốc | Correlation |
|---|---|---|
| Tạo file | Event **11**, `record_id=182`, `event_id=cab6af4d-a862-5e4c-bfb5-42b5b46081cd`, `09:11:53.2778558Z` | `file_path` kết thúc `_drop.exe`; creator `process_guid=43f71ec6-8d48-6ad4-1c01-000000000400` |
| Chạy file | Event **1**, `record_id=184`, `event_id=2ef59e9e-cff1-525d-a58e-aecae054b171`, `09:11:55.8363770Z` | `image_path` khớp file path; process mới `43f71ec6-8d5b-6ad4-2501-000000000400`, parent GUID khớp creator |
| Xóa file | Event **26**, `record_id=188`, `09:11:57.5737716Z` | Raw XML có cùng `TargetFilename`, nhưng **không nằm trong bốn JSON normalized W3**. Chưa thể tuyên bố đã ingest Silver |
| Process con | Event **1**, `record_id=185`, `event_id=5b452d31-566e-59b4-9929-cbb8377ca690` | `parent_guid` của con trỏ tới process record 184 |

**Ví dụ alert contract ở mức thiết kế, KHÔNG phải output đã chạy:**

```json
{
  "status": "DESIGN_EXAMPLE_NOT_EXECUTED",
  "rule_id": "DET-010",
  "rule_version": "w06-proposed",
  "mitre_technique_id": "T1070.004",
  "contributing_event_ids": [
    "cab6af4d-a862-5e4c-bfb5-42b5b46081cd",
    "2ef59e9e-cff1-525d-a58e-aecae054b171"
  ],
  "additional_raw_evidence": [{
    "sysmon_event_id": 26,
    "record_id": 188,
    "bronze_ref": "NOT_YET_INGESTED"
  }],
  "coverage_status": "PARTIAL_RAW_ONLY",
  "decision": "CANDIDATE_REQUIRES_REVIEW"
}
```

Tránh bịa `event_id` của raw record 188 hoặc cho rằng nó đã được lưu Silver. Khi mở rộng ingestion phải tính ID theo namespace & quy tắc được xác minh và giữ raw provenance.

**DNS/network:** raw DNS Event **22, record 196** (không phải record 193 như một ví dụ W05 Data) và normalized network Event **3, record 194** cùng process GUID, một DNS result khớp destination IP. Correlation có thể có, nhưng không chứng minh C2 và không tạo socket tuple cho DNS.

## 3. Yêu cầu investigation/hunting

- **Process Tree:** join `(hostname,process_guid)` ↔ `(hostname,parent_guid)`, đánh dấu orphan/missing ancestor; ID5 terminate không có parent trực tiếp.
- **Incident Timeline:** giữ `System.TimeCreated.SystemTime` chính, `EventData.UtcTime` phụ, ingest time, record ID và timezone. Mẫu Event3/22 có độ lệch ~12 giây; không mặc định cửa sổ 5 giây đồng nhất.
- **Hunting:** query theo time range, host, process/parent GUID, path, hash, DNS, IP/port (chỉ ID3), registry key, rule ID, severity, gap/quarantine status; filter tôn trọng NULL và field không có ở loại EventID.
- **Retention:** khi raw đã hết hạn, alert phải hiện `RAW_EXPIRED` hoặc có retention hold, không ghi rằng raw_data Silver có thể khôi phục nguyên XML.
- **Audit:** mọi truy vấn raw nhạy cảm, response/quarantine, export và nhãn incident cần người thực hiện và timestamp.
- **Lab provenance:** `poc_run_20261018_021142.json` chứng minh hoạt động lab có marker, không tự gắn nhãn ATT&CK cho toàn bộ cùng time window.

## 4. Acceptance tests thiết kế W06/W09

| Test | Expected outcome |
|---|---|
| TRACE-01 | Một event_id Silver tìm đúng Bronze segment/line/XML và integrity hash |
| TRACE-02 | DET-010 thiếu một bước chỉ trả PARTIAL, không report full sequence |
| TRACE-03 | ID5 không có parent không làm hỏng process tree |
| TRACE-04 | ID22 không có socket fields vẫn truy vấn được DNS bằng GUID/time |
| TRACE-05 | Reprocessing/replay lưu mapping version, không mất raw reference |
| TRACE-06 | Khi raw retention hết hạn, provenance báo RAW_EXPIRED |
| TRACE-07 | Event đến muộn/out-of-order được cập nhật trạng thái evidence thay vì coi "không xảy ra" |
| TRACE-08 | Người không đủ quyền không đọc được XML nhạy cảm; export public đã sanitize |

Các test chưa chạy như một pipeline hoàn chỉnh ở W05. Bàn giao Cyber theo [issue #28](https://github.com/Kientran18/DACN/issues/28) và Team [#26](https://github.com/Kientran18/DACN/issues/26).
