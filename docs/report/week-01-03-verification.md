# Kết quả kiểm tra bổ sung tuần 1 đến tuần 3

Ngày kiểm tra 2026-10-19. Kiểm tra tại môi trường Python Linux, không phải Windows.

## Đã chạy

```text
python -m pytest -q poc/sysmon-collector/test_sysmon_collector_poc.py
19 passed
```

Đã sửa đường dẫn fixture từ fixtures sang configs và cô lập giả lập thiếu pywin32 để test không phụ thuộc máy có cài pywin32 hay không. Thêm kiểm tra hồi quy đọc XML thật, đối chiếu chính xác bốn JSON đã commit (Process 3, File 2, Registry 2, Network 1), payload Event 5, payload DNS và correlation GUID/host với kết nối.

Các link tương đối trong tài liệu mới/viết lại đã được kiểm tra tồn tại. Đây không phải kiểm tra toàn bộ link lịch sử của repository.

## Chưa kiểm chứng

- Python live mode, quyền đọc channel thực tế của tài khoản thường.
- Cài Sysmon và chạy script lại trong môi trường kiểm tra Linux.
- Hoàn thành E1–E10, benchmark tài nguyên hoặc detection rules.
- Pydantic validation, DuckDB ingestion, toàn bộ pipeline và chất lượng AI.
- Xác nhận nghiệm thu thay Cyber/Data/Software.

[Review chung](../project/week-01-03-review-and-ownership.md) lưu các xác nhận cần bổ sung. Không tự tick toàn bộ DoD hoặc đóng M1 từ kết quả test parser.
