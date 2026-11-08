# Hướng dẫn huấn luyện mô hình AI/ML cho DACN EDR (dành cho người dùng)

> PROPOSAL (2026-11-08). **Chưa có mô hình, dataset hay mã huấn luyện nào.** Tài liệu này không khẳng định bất kỳ độ chính xác nào; mọi chỉ số chỉ có nghĩa sau khi bạn huấn luyện và đánh giá trên dữ liệu của bạn. Nhánh ML **không nằm trên critical path** của MVP: EDR rule-based phải chạy được trước.

## 1. Phân công

| Việc | Claude Code | Bạn (người dùng) |
|---|---|---|
| Thiết kế đặc trưng, hợp đồng `feature_schema_version` | Làm (ML-T01) | Duyệt |
| Trích xuất đặc trưng từ Silver, preprocessing | Làm (ML-T02) | Chạy trên dữ liệu của bạn |
| Giao diện `MLDetector`, nạp mô hình, kiểm tra schema/hash | Làm (PH4-T10, ML-T03) | Duyệt |
| Khung mã huấn luyện + đánh giá, unit test | Làm (ML-T04), **không chạy huấn luyện** | Đọc, chạy |
| Chuẩn bị/xác nhận dataset, gán nhãn | Hướng dẫn | **Làm** |
| Thiết lập môi trường training, huấn luyện, chọn mô hình | Hướng dẫn | **Làm** (ML-T05) |
| Kiểm tra metrics, cung cấp artifact | Phân tích kết quả bạn gửi | **Làm** |
| Tích hợp mô hình đã huấn luyện, thử suy luận | Làm sau khi bạn yêu cầu (ML-T06/T07) | Duyệt, chạy trên VM |

## 2. Mục tiêu bài toán

Theo kế hoạch W8 (`docs/plan/…` trong PR #36): **risk scoring** và/hoặc **anomaly detection** làm tín hiệu *bổ trợ* cho rule/IOC. Mô hình **không** thay raw evidence, **không** tự kích hoạt response. Đầu ra: `AnomalyResult(score, explanation, model_version, feature_schema_version, source_event_ids)`.

Chọn một bài toán trước khi làm:
- **Anomaly detection không giám sát** (ví dụ Isolation Forest) — dùng dữ liệu lành tính; ít cần nhãn nhưng khó chứng minh hiệu quả.
- **Phân loại có giám sát** (ví dụ Logistic Regression, Random Forest) — cần nhãn đáng tin cậy cho lành tính và hành vi mô phỏng.

## 3. Dữ liệu — hiện trạng và thiếu hụt

- Có trong repository: `references/samples/` — 225 sự kiện Sysmon (ID 1, 3, 4, 5, 11, 12, 13, 16, 22, 26, 29), chủ yếu hoạt động lành tính từ lab; **quá nhỏ và chưa có nhãn độc hại để huấn luyện mô hình đáng tin**; chưa khử định danh (`sanitized:false`).
- Thiếu: (1) tập lành tính đủ lớn và đa dạng; (2) tập có nhãn cho hành vi mô phỏng; (3) nhiều máy/lượt chạy để chia tập đúng cách; (4) kịch bản hết hạn dữ liệu.
- Nguồn hợp pháp có thể cân nhắc (bạn tự kiểm tra giấy phép, điều khoản, nội dung và tính phù hợp; **chưa được truy cập hay xác minh trong phiên này**): tập log Sysmon/Windows công khai từ cộng đồng nghiên cứu bảo mật (ví dụ các kho dữ liệu mô phỏng tấn công như OTRF Security-Datasets, EVTX-ATTACK-SAMPLES), và **dữ liệu tự sinh** bằng kịch bản mô phỏng an toàn của DACN ([EDR_DEMO_PLAN.md](EDR_DEMO_PLAN.md)) nhiều lượt, nhiều ngày, có `run_id`.
- Không dùng dữ liệu cá nhân hoặc dữ liệu công ty khi chưa được phép. Không tải/chạy mã độc thật để "tạo dữ liệu".

## 4. Quy trình

### 4.1. Chuẩn bị và làm sạch dữ liệu
1. Xuất Bronze/Silver từ các lượt chạy; giữ `event_id`, `process_guid`, `host`, `run_id`, thời gian.
2. Khử định danh trước khi chia sẻ ngoài nhóm (tên máy, người dùng, SID).
3. Loại bản ghi vào DLQ; **không điền giá trị thiếu bằng dữ liệu giả** — thiếu thì ghi cờ thiếu (`is_missing_*`) hoặc bỏ mẫu.
4. Gán nhãn bằng bảng `run_id → kịch bản → nhãn` và cửa sổ thời gian; kiểm tra thủ công một mẫu nhãn.

### 4.2. Feature engineering
Bắt đầu từ các cột thiết kế trong `gold_process_features` (DDL v1.1): `tree_depth`, `child_process_count_10s`, `cmd_length`, `cmd_shannon_entropy`, `is_temp_execution`, `file_create_count_5s`, `file_delete_count_5s`, `reg_set_value_count_10s`, `net_outbound_count_30s`, `unique_dest_ip_count_60s`, `dns_query_count_60s`. Mỗi đặc trưng phải có: nguồn (cột Silver), cửa sổ, đơn vị, cách xử lý thiếu, `source_event_ids`.
- Lưu ý đã xác minh: entropy dòng lệnh là heuristic yếu cho `-EncodedCommand` (payload UTF-16LE base64 ít ký tự khác nhau nên entropy thấp, xem Audit TD-02). Đừng giả định "entropy cao = độc hại".
- **Cấm đưa vào đặc trưng:** chuỗi `DACN_LAB`, `run_id`, đường dẫn thư mục lab, tên tệp mô phỏng, hostname — đây là rò rỉ nhãn.

### 4.3. Chia train / validation / test và chống rò rỉ
- Chia theo **máy / lượt chạy / thời gian**, không chia ngẫu nhiên từng sự kiện (các sự kiện cùng tiến trình rất giống nhau).
- Toàn bộ các sự kiện của cùng một `process_guid` hoặc cùng một chuỗi hành vi phải ở cùng một tập.
- Fit mọi bộ chuẩn hóa/chọn đặc trưng **chỉ trên train**, áp dụng lên validation/test.
- Không dùng test để chọn ngưỡng hay siêu tham số. Giữ test cho một lần đánh giá cuối.
- Kiểm tra rò rỉ: huấn luyện thử với nhãn xáo trộn (phải ra kết quả ngẫu nhiên); kiểm tra đặc trưng quan trọng nhất có hợp lý về bảo mật không.

### 4.4. Mất cân bằng lớp
Hành vi độc hại thường rất ít so với lành tính. Cách xử lý: trọng số lớp (`class_weight`), điều chỉnh ngưỡng trên validation, ưu tiên PR-AUC và recall tại FPR cho phép; chỉ lấy mẫu lại **trên train**, không bao giờ trước khi chia.

### 4.5. Chọn thuật toán (baseline theo kế hoạch W8)
Isolation Forest (không giám sát, khi chỉ có dữ liệu lành tính), Logistic Regression và Random Forest (có giám sát). Bắt đầu với baseline đơn giản; mô hình phức tạp hơn chỉ khi baseline chứng minh không đủ và có đủ dữ liệu.

### 4.6. Huấn luyện
Thực hiện trên máy của bạn, môi trường cố định (ghi phiên bản Python và thư viện), đặt hạt giống ngẫu nhiên, lưu cấu hình. Mã khung do Claude cung cấp (ML-T04) chỉ là điểm bắt đầu; bạn chịu trách nhiệm chạy và kiểm tra.

### 4.7. Đánh giá
Báo cáo trên **test set**: precision, recall, F1, **false positive rate**, ma trận nhầm lẫn, PR curve; kèm cỡ mẫu và khoảng tin cậy. Báo cáo riêng cho từng loại hành vi. Ghi rõ giới hạn (số lượt chạy, một loại VM). Ngưỡng cảnh báo chọn trên validation. **Không** công bố "độ chính xác cao" nếu chưa chạy đánh giá này; nếu FPR cao so với tải cảnh báo chấp nhận được thì không dùng mô hình để cảnh báo.

### 4.8. Lưu mô hình
Cấu trúc đề xuất (thư mục do bạn chọn, không commit mô hình lớn khi chưa thống nhất):
```
models/<tên>/<phiên_bản>/
  model.<định dạng>        # ưu tiên định dạng không thực thi mã khi nạp (ví dụ ONNX hoặc skops); tránh pickle từ nguồn không tin cậy
  model_card.json          # feature_schema_version, danh sách và thứ tự đặc trưng, tham số tiền xử lý,
                           # hash tập huấn luyện, phiên bản thư viện, ngưỡng, metrics test, ngày huấn luyện, người huấn luyện
  SHA256SUMS
```
Nạp pickle/joblib có thể thực thi mã tùy ý: chỉ nạp artifact bạn tự tạo và kiểm tra SHA-256.

### 4.9. Kiểm tra tương thích feature schema
`ModelLoader` (ML-T03) từ chối nạp nếu `feature_schema_version`, tên hoặc thứ tự đặc trưng khác với `feature extractor` hiện hành, hoặc hash không khớp. Bạn không được tự bỏ qua kiểm tra này.

### 4.10. Tích hợp vào EDR
Sau khi bạn gửi artifact và `model_card.json`, yêu cầu Claude thực hiện ML-T06: cấu hình `ml.enabled`, đường dẫn mô hình, ngưỡng; chạy test với detector giả và với mô hình thật trên dữ liệu mẫu. ML chỉ cộng vào điểm rủi ro và giải thích; **không** kích hoạt response.

### 4.11. Thử suy luận thực tế
ML-T07 trên VM: chạy kịch bản SC-06 (lành tính) và SC-01…SC-03 (mô phỏng); so điểm với kỳ vọng; ghi độ trễ suy luận và RAM đo được. Báo cáo kết quả trung thực kể cả khi mô hình không cải thiện so với rule-only.

## 5. Danh sách kiểm tra trước khi gửi mô hình cho Claude

- [ ] Có `model_card.json` và `SHA256SUMS`
- [ ] Chia tập theo máy/lượt/thời gian, không rò rỉ
- [ ] Không dùng marker lab làm đặc trưng
- [ ] Metrics trên test set (precision, recall, F1, FPR) kèm cỡ mẫu
- [ ] Đã kiểm tra nhãn xáo trộn
- [ ] Ghi giới hạn của dữ liệu
- [ ] Phiên bản thư viện và hạt giống được lưu
- [ ] Đã quyết định ngưỡng trên validation (không trên test)

## 6. Những điều không được khẳng định

Không nói mô hình "phát hiện được malware" hay "độ chính xác X%" nếu chưa huấn luyện và đánh giá như trên; không suy rộng kết quả từ dữ liệu lab nhỏ sang môi trường thực.
