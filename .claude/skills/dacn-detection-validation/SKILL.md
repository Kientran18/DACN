---
name: dacn-detection-validation
description: Kiểm thử và đo chất lượng phát hiện DACN. Tự dùng khi cần test case true positive, false positive, false negative, bộ dữ liệu benign và adversary-like an toàn, regression cho rule, alert noise, độ trễ phát hiện. Không bịa số liệu chưa đo, không chạy mô phỏng tấn công. Không dùng để viết rule (dacn-detection-rules-mitre) hay nghiệm thu cả chuỗi (dacn-end-to-end-acceptance).
---

# Kiểm thử và đánh giá phát hiện

## Đọc trước
`docs/architecture/local-edr-reference-architecture-v2.md` mục 11 (test matrix, DET-01/03/10, TRC-01), `docs/research/cyber/w4/03-detection-hunting-response-va-ke-hoach-test.md` mục 3 (Atomic Red Team an toàn), `docs/research/cyber/w5/04-telemetry-gaps-and-w06-w09-backlog.md` (W5-CY-14), `docs/research/cyber/w5/02-alert-to-source-traceability-requirements.md` mục 4, `src/pipeline/sql/silver_gold_schema_and_views_v1_1.sql` (`silver_atomic_test_runs`), `references/samples/w5_negative_and_edge_samples.md`.

## Quy trình
1. **Xác định đối tượng:** rule (id, version) hoặc đường truyền (Silver → DetectionResult → alert). Nếu engine chưa tồn tại, chỉ lập kế hoạch và fixture; không báo kết quả.
2. **Bộ dữ liệu có nhãn:** mỗi bản ghi có `nhãn` (benign / adversary-like an toàn / thiếu telemetry), nguồn (synthetic / lab đã xuất / live), mã hóa ngữ cảnh (host, thời gian, `process_guid`). Hoạt động benign nền phải có (cùng loại với hành vi cần phân biệt). Không dùng mã độc thật; không dùng dữ liệu cá nhân thật.
3. **Ma trận kỳ vọng:** với từng ca ghi kết quả mong muốn (`MATCH` / `NO_MATCH` / `INSUFFICIENT_TELEMETRY` / `PENDING_LATE_EVENTS`) và lý do. Ca đặc biệt: thiếu command line, thiếu Event 26, ancestor bị cắt, sự kiện đến muộn, time skew, replay trùng.
4. **Chạy và so sánh:** đầu ra thực tế so với kỳ vọng; phân loại sai lệch thành FP, FN, hoặc kỳ vọng sai. Bản ghi `INSUFFICIENT_TELEMETRY` không tính là NO_MATCH hay benign.
5. **Alert noise:** đếm alert theo rule/host/cửa sổ trên dữ liệu benign đã nhãn; kiểm tra dedup không gộp sai actor khác.
6. **Hiệu năng/độ trễ:** đo bằng lệnh có thể lặp lại (thời lượng đánh giá, độ trễ từ `timestamp` đến alert) trên VM; ghi cấu hình máy. Không suy ra từ máy khác.
7. **Regression:** mọi rule đã sửa phải chạy lại toàn bộ fixture cũ + ca mới; lưu `rule_version` và `test_run_id`.
8. **Cải tiến:** đề xuất sửa điều kiện/telemetry kèm ca kiểm chứng; không tự sửa rule ngoài yêu cầu.

## Nguyên tắc không được vi phạm
- Không tạo hay "ước lượng" precision, recall, FPR, MTTD khi chưa chạy đo; mẫu nhỏ hoặc synthetic chỉ cho kết luận về chính các ca đó.
- Không tuyên bố rule "phát hiện được T1xxx" chỉ vì có một ca khớp.
- Không chạy mô phỏng tấn công: quy trình Atomic Red Team phải do người dùng thực hiện trên VM có snapshot, mỗi test GUID được xem YAML và cleanup trước (theo tài liệu Cyber W04).
- Không sửa code/test của người khác chỉ để số liệu đẹp hơn.

## Kiểm tra kết quả
Mỗi số liệu có: tập dữ liệu (đường dẫn + nhãn), lệnh, phiên bản rule, thời điểm, môi trường. Tách FP/FN thật khỏi lỗi dữ liệu/ nhãn.

## Đầu ra
```markdown
## Phạm vi (rule/đường truyền, phiên bản)
## Bộ dữ liệu và nhãn
## Ma trận kỳ vọng ↔ quan sát
## FP / FN / noise / độ trễ (kèm cách đo)
## Hạn chế (cỡ mẫu, môi trường, nhãn synthetic)
## Đề xuất cải tiến
```

## Cần hỏi người dùng
Trước khi thêm fixture vào `tests/`/`references/` (cần phê duyệt vị trí), trước khi người dùng chạy kịch bản có tác dụng phụ, trước khi đặt ngưỡng chấp nhận (ví dụ giới hạn FPR).

## Phối hợp với skill khác
- Trước đó: dacn-detection-rules-mitre
- Cùng lúc: test-driven-development
- Sau đó: dacn-end-to-end-acceptance
