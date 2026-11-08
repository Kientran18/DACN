---
name: dacn-performance-reliability
description: Dùng khi thiết kế phép đo và đánh giá hiệu năng, độ ổn định của DACN trên VM lab - CPU/RAM, throughput sự kiện, hàng đợi/buffer, độ trễ ingestion và detection, hiệu năng truy vấn, phục hồi lỗi, profiling. Mọi con số phải đến từ phép đo có thể lặp lại; không tạo tải quá mức ngoài môi trường thử nghiệm.
---

# Hiệu năng và độ tin cậy

## Ranh giới
Chỉ số **chất lượng dữ liệu** (completeness, quarantine ratio, event loss) nằm ở `dacn-data-pipeline-storage/references/data-quality-metrics.md`. Skill này lo **tài nguyên, độ trễ, throughput, độ bền**. Tài liệu Software nêu rõ hiện chưa có số đo hiệu năng nào (`docs/research/software/w5/04-error-recovery-and-operational-notes.md`, `05-integration-feasibility-and-open-issues-w05.md`).

## Đọc trước
`docs/architecture/local-edr-reference-architecture-v2.md` mục 8.2 (metrics, failure drills), 11 (W10–W12: đo trên VM); `docs/research/data/w5/duckdb_olap_indexing_and_feature_windowing.md`; `docs/research/software/w1/05-windows-lab-environment.md` (cấu hình VM); `src/pipeline/validator_poc.py`, `poc/sysmon-collector/`.

## Quy trình
1. **Câu hỏi đo:** mỗi phép đo trả lời một câu (ví dụ "validator xử lý N bản ghi mất bao lâu trên VM lab?"). Chọn chỉ số: CPU%, RSS, IO, bản ghi/giây, độ trễ p50/p95 (`timestamp` → Silver, Silver → alert), kích thước DuckDB/Bronze, thời gian truy vấn.
2. **Môi trường và baseline:** ghi cấu hình máy (CPU, RAM, ổ đĩa, hệ điều hành, phiên bản Python/DuckDB), trạng thái nền, snapshot. Đo baseline trước khi có thay đổi.
3. **Tải thử có kiểm soát:** dùng dữ liệu synthetic/mẫu nhân bản **đã gắn nhãn**, kích thước tăng dần và có trần; chạy trong thư mục tạm/VM lab. Không phát sự kiện thật nhân tạo ồ ạt vào Event Log của máy dùng hằng ngày, không làm đầy đĩa.
4. **Lặp lại và thống kê tối thiểu:** nhiều lần chạy, báo trung vị và biên độ; ghi nhiễu (Defender, cache).
5. **Profiling:** dùng công cụ có sẵn của Python (`cProfile`, `tracemalloc`) khi người dùng đồng ý; chỉ ghi nhận điểm nóng có bằng chứng.
6. **Độ tin cậy:** kịch bản crash/restart, đầy đĩa, bản ghi hỏng, replay (OPS-01); đo thời gian phục hồi và kiểm tra không mất/không trùng dữ liệu (đối chiếu số đếm theo từng tầng).
7. **Queue/buffer:** quan sát độ sâu hàng đợi, hành vi backpressure, lag so với kích thước channel Event Log.
8. **Kết luận theo phạm vi:** đủ cho 1 endpoint lab hay không, dựa số đo; ngưỡng cảnh báo chỉ đặt sau khi có số.

## Nguyên tắc không được vi phạm
- Không bịa số liệu, không ngoại suy từ mẫu nhỏ cho "hệ thống chịu được X sự kiện/giây". Chưa đo thì ghi "chưa đo".
- Không tạo workload quá tải ngoài môi trường thử nghiệm; không chạy stress trên máy thật của người dùng; không tắt cơ chế bảo vệ để đo.
- Không tối ưu sớm bằng cách đổi kiến trúc/contract; đề xuất kèm đo trước/sau.
- Số đo từ Linux không đại diện Windows; ghi nhãn nền tảng.

## Kiểm tra kết quả
Mỗi số có: lệnh/kịch bản, dữ liệu vào (kích thước, nhãn), cấu hình máy, số lần chạy, thời điểm. Có thể chạy lại và ra kết quả cùng bậc.

## Đầu ra
```markdown
## Câu hỏi đo và chỉ số
## Môi trường, baseline
## Kết quả (bảng: kịch bản | chỉ số | giá trị | số lần chạy)
## Độ tin cậy (kịch bản lỗi: kỳ vọng vs quan sát)
## Điểm nghẽn có bằng chứng, đề xuất
## Giới hạn của phép đo
```

## Cần hỏi người dùng
Trước khi chạy tải thử có thể tốn đĩa/CPU, trước khi dùng profiler, hoặc đặt ngưỡng hiệu năng chính thức.
