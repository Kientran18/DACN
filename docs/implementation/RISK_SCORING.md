# Chấm điểm rủi ro tổng hợp (Risk Scoring) — thiết kế và hiện thực

> Trạng thái: **đã hiện thực, có test trên Linux với dữ liệu synthetic** (2026-11-25). Trọng số và ngưỡng là **heuristic chưa hiệu chỉnh**. Chưa chạy trên Windows 10 VM, chưa có dữ liệu có nhãn của DACN, chưa được nhóm Cyber/Data duyệt. Điểm rủi ro **không bao giờ kích hoạt response**.

## 1. Mục tiêu và phạm vi

Đề cương yêu cầu "tổng hợp kết quả từ nhiều cơ chế để đưa ra mức độ rủi ro". Trước thay đổi này, mỗi alert chỉ có `severity` cố định do rule gán; không có điểm nào gộp nhiều cơ chế cùng chỉ về một chủ thể.

Module `src/risk/` gộp các tín hiệu sau thành một điểm 0–100 và một mức `NONE | low | medium | high | critical` cho từng **chủ thể**:

| Chủ thể | Khóa | Cửa sổ |
|---|---|---|
| Tiến trình | `(hostname, process_guid)` | toàn bộ vòng đời tiến trình có trong dữ liệu |
| Host | `hostname` | `host_window_seconds` (mặc định 3600 giây) tính lùi từ thời điểm dữ liệu mới nhất của host, hoặc từ `until` |

"Chuỗi sự kiện" của rule correlation (DET-010 drop → execute → delete) được tính qua alert correlation gắn với `process_guid` của sự kiện đầu chuỗi. Ở cấp host, mọi alert trong cửa sổ đều được tính, kể cả alert không có `process_guid`.

Ngoài phạm vi: tự tạo alert hay incident, tự response, chấm theo người dùng (UEBA đầy đủ), tương quan nhiều host.

## 2. Nguồn tín hiệu (thành phần)

| Cơ chế (`category`) | Lấy từ | Điểm gốc |
|---|---|---|
| `RULE` | `alerts` có rule `type: single` | `severity_points[severity]` |
| `CORRELATION` | `alerts` có rule `type: correlation` (DET-010) | `severity_points[severity]` |
| `IOC` | `alerts` có `detection_source = IOC` hoặc rule `type: ioc` (DET-101) | `severity_points[severity]` |
| `STATIC` | `alerts` của `DACN-STATIC-001` (static analysis issue #40) | `severity_points[severity]` |
| `EXTERNAL_AV` | `alerts` có `detection_source` bắt đầu bằng `EXTERNAL_` (Defender `DACN-DET-201`/`202`; từ cấu hình v2, 2026-11-28). Không có `process_guid` nên chỉ vào chủ thể host. Không phải ML: được tính vào thưởng đa dạng | `severity_points[severity]` |
| `ML_STATIC` | `_ml_signals` do `static_signal.py` (EMBER2024 nháp) ghi | `score × ml_max_points.ML_STATIC` |
| `ML_BEHAVIOR` | `_ml_signals` do `behavior.py` (độ hiếm hành vi) ghi | `score × ml_max_points.ML_BEHAVIOR` |

Các thông tin còn lại **không cộng điểm** nhưng được dùng để giải thích:

- `coverage_gaps` (kết quả `INSUFFICIENT_TELEMETRY` của rule) được liệt kê ở `data_gaps`. Thiếu dữ liệu không phải là bằng chứng đe dọa.
- Detector ML đang tắt, chưa chấm hoặc trả `INSUFFICIENT_TELEMETRY` được liệt kê ở `not_evaluated`, kèm `reason`, ví dụ `DISABLED`, `NOT_SCORED`, `DEPENDENCY_MISSING`, `HASH_MISMATCH_CURRENT_BYTES`.
- `completeness` có giá trị `FULL` hoặc `PARTIAL`. `PARTIAL` nghĩa là còn nguồn chưa đánh giá hoặc còn khoảng trống dữ liệu.

## 3. Công thức

```
điểm_thành_phần = điểm_gốc × trọng_số[cơ chế] × hệ_số_allowlist      (0 nếu thành phần bị loại có lý do)
điểm_cơ_chế     = min(Σ điểm_thành_phần cùng cơ chế, trần[cơ chế])
thưởng_đa_dạng  = min(max, per_extra_category × (số cơ chế KHÔNG phải ML có điểm > 0 − 1))
score           = min(100, Σ điểm_cơ_chế + thưởng_đa_dạng)
level           = mức cao nhất có ngưỡng ≤ score; score = 0 → NONE
```

Quy tắc loại hoặc giảm điểm (luôn ghi lý do vào `reason`):

- Alert ở trạng thái `FALSE_POSITIVE`: không tính ("analyst đã đánh dấu alert là FALSE_POSITIVE").
- Alert `DACN-STATIC-001` có candidate `ALLOWLISTED` hoặc `REJECTED`: không tính.
- `file_sha256` ở Event 1 của tiến trình nằm trong allowlist cục bộ (`<EDR_HOME>/ioc/ioc.yaml`, `allowlist_hashes`): mọi thành phần của tiến trình đó bị nhân `allowlist_factor`. Hệ số này giảm điểm chứ không xóa điểm, vì allowlist theo hash không loại trừ việc tiến trình hợp lệ bị lạm dụng (LOLBin).

Thiết kế cố ý đặt **trần ML thấp** (12 + 12 = 24 < ngưỡng medium 30) và **không tính ML vào thưởng đa dạng**. Hai mô hình ML đều là bản nháp chưa hiệu chỉnh, nên riêng ML không thể đẩy một chủ thể lên medium. ML chỉ "hỗ trợ" phát hiện, đúng như đề cương.

Ví dụ trên fixture synthetic: tiến trình có DET-001 (medium) và DET-010 (high, correlation):
`25×1.0 + 45×1.2 + 10 (thưởng: 2 cơ chế độc lập) = 89` → `critical`. Đây là ví dụ minh họa công thức, không phải số đo chất lượng.

## 4. Cấu hình có phiên bản

Tệp `config/risk-scoring.yaml`:

- Có `version`, `changelog` và `status: heuristic_uncalibrated`. Loader **từ chối** mọi giá trị `status` khác, để không ai đổi nhãn thành "đã hiệu chỉnh" khi chưa có số đo.
- Kiểm tra chặt: từ chối khóa thừa hoặc thiếu, trọng số âm, ngưỡng không tăng dần (mã `RISK-CFG`).
- Mọi kết quả kèm `config.version` và `config.sha256` (sha256 của tệp), nên truy được kết quả nào tính bằng cấu hình nào.
- v2 (2026-11-28): thêm `EXTERNAL_AV` với trọng số 1.0 và trần 60 (bằng `RULE`), theo D7 của `docs/architecture/w8/telemetry-defender-powershell-proposal.md`; giá trị 1.0/60 được người dùng duyệt thay Cyber ngày 2026-11-28 (mục 12.16), vẫn chưa hiệu chỉnh. Tệp cấu hình thiếu khóa `EXTERNAL_AV` bị loader từ chối.
- Đổi giá trị: sửa tệp, tăng `version`, thêm dòng `changelog` (ngày, lý do), chạy `python -m pytest -q tests/risk` rồi khởi động lại core/API. Đây là quy trình kiểm soát thay đổi theo NIST SP 800-128 (xem [NIST_MAPPING.md](NIST_MAPPING.md)).

## 5. Lưu trữ và luồng

- **Không lưu điểm.** `RiskService` tính lại mỗi lần truy vấn, nên điểm luôn phản ánh trạng thái alert, allowlist và candidate hiện tại. Cách này không thêm bảng mới và không đổi DDL v1.1/v1.2.
- Tín hiệu ML lưu ở bảng nội bộ `_ml_signals`, do `src/detection/ml/signals.py` tạo (giống `_detection_results` của engine), **không thuộc DDL**. Bảng này chỉ có dữ liệu khi người dùng bật ML.
- Chi phí tăng theo số alert. Như vậy là đủ cho MVP một endpoint; **hiệu năng chưa đo trên VM 2 GB**.

## 6. API và Dashboard

- Các endpoint chỉ đọc (quyền `read`): `GET /risk/config`, `GET /risk/subjects?kind=process|host&min_level=`, `GET /risk/process?hostname=&process_guid=`, `GET /risk/host?hostname=&until=`, `GET /alerts/{id}/risk`. Không có POST; mọi kết quả có `triggers_response: false`.
- Dashboard:
  - Tab **Rủi ro**: liệt kê chủ thể theo tiến trình và theo host; bấm vào một dòng để xem chi tiết.
  - Cột **Rủi ro** trong bảng alert (Tổng quan, Alerts).
  - Mục **Rủi ro tổng hợp** trong chi tiết alert: bảng thành phần (cơ chế, nguồn, điểm gốc, trọng số, điểm, lý do), các nguồn chưa đánh giá, các khoảng trống dữ liệu. Trang ghi rõ "heuristic chưa hiệu chỉnh" và "không kích hoạt response". Nếu endpoint rủi ro lỗi, các phần còn lại của trang vẫn hiển thị.

## 7. Bảo đảm "không kích hoạt response"

- `src/risk` và `src/detection/ml` không import `response`. `src/response` và `experimental/` không import `risk` và không đọc `_ml_signals` hay `risk_score`. Có kiểm tra tĩnh bằng AST trong `tests/risk/test_risk_service.py::test_risk_and_ml_never_reach_response`.
- Test API xác nhận gọi `/alerts/{id}/risk` không làm thay đổi số dòng `response_actions`.

## 8. Kiểm thử (2026-11-25, Linux, Python 3.13)

| Tệp test | Nội dung |
|---|---|
| `tests/risk/test_risk_scoring.py` | Cấu hình có phiên bản và từ chối giá trị sai; công thức, trần, thưởng đa dạng, ML không vượt low, loại có lý do, allowlist, `NONE` |
| `tests/risk/test_risk_service.py` | Gom từ alerts, `_ml_signals`, coverage_gaps, candidate, allowlist; cửa sổ host theo thời gian dữ liệu; sắp xếp; kiểm tra tĩnh "không response" |
| `tests/api/test_risk_api.py` | Cần token, chỉ đọc, 404, 422, không tạo `response_actions` |
| `tests/dashboard/test_dashboard_ui.py` | Playwright: cột rủi ro, trang Rủi ro, mục giải thích, trang vẫn hiển thị khi endpoint rủi ro lỗi |

## 9. Hạn chế và ảnh hưởng liên nhóm

- **Chưa hiệu chỉnh.** Trọng số do Software đặt để thử nghiệm; cần Cyber đề xuất lại dựa trên kịch bản lab (SC01–SC07) và tệp lành tính trên VM. Chưa có TP/FP/FN.
- **Cyber:** severity của rule là đầu vào trực tiếp, nên đổi severity sẽ đổi điểm. Cần Cyber duyệt cách gộp severity, trọng số và việc tách `CORRELATION` khỏi `RULE`.
- **Data:** dùng `alerts` và `coverage_gaps` (DDL v1.2 **đề xuất**) và bảng nội bộ `_ml_signals`. Nếu v1.2 đổi tên cột, `src/risk/service.py` phải sửa theo. Chưa đề xuất đưa điểm vào Gold.
- Chủ thể host dùng thời gian dữ liệu, nên phụ thuộc đồng hồ của endpoint (không chuẩn hóa lệch giờ).
- Allowlist chỉ dùng `file_sha256` của Event 1. Nếu Sysmon không cấu hình băm SHA256 thì không áp dụng được, và trường hợp đó chưa được ghi vào `not_evaluated`.
