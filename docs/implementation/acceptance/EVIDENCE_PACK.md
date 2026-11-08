# EDR — Gói bằng chứng nghiệm thu (PH11-T04)

> Bằng chứng ở mức **L** (Linux, dữ liệu synthetic/giả lập). Chưa có bằng chứng mức **W** (Windows VM thật). Số liệu cụ thể nằm trong báo cáo sinh tự động; không sao chép tay sang đây để tránh lệch.

| Mục | Nơi lưu |
|---|---|
| Kết quả từng AT (Preconditions/Steps/Expected/Actual/Status/Evidence/Limitations) | [ACCEPTANCE_REPORT.md](ACCEPTANCE_REPORT.md) |
| Kết quả dạng máy đọc, kèm commit, phiên bản thư viện, thời điểm chạy | [acceptance_results.json](acceptance_results.json) |
| Danh sách việc cho người dùng trên Windows VM | [WINDOWS_ACCEPTANCE_CHECKLIST.md](WINDOWS_ACCEPTANCE_CHECKLIST.md) |
| Kịch bản demo và bảng diễn tập | [DEMO_RUNBOOK.md](DEMO_RUNBOOK.md) |
| Ma trận yêu cầu → test | [EDR_ACCEPTANCE_MATRIX.md](../EDR_ACCEPTANCE_MATRIX.md) |

## Tái tạo

```bash
python scripts/acceptance/run_acceptance.py
python -m pytest -q
```

Báo cáo ghi commit (`git rev-parse --short HEAD`) và cờ "cây làm việc có thay đổi chưa commit". Nếu cờ này bật, kết quả chưa gắn được với một commit cụ thể; hãy commit rồi chạy lại để gói bằng chứng khớp commit.

## Ảnh chụp

Ảnh dashboard do `tests/dashboard/test_dashboard_ui.py` sinh trên dữ liệu mẫu có nhãn nằm ở thư mục tạm của lần chạy, không nằm trong repo. Ảnh chụp từ VM phải che tên máy/tên người dùng trước khi đưa vào gói.

## Giới hạn

- Không có kết luận về khả năng phát hiện malware ngoài thực tế; không có tỷ lệ phát hiện.
- PASS ở mức L không chứng minh Windows live, `WinProcessApi`, script lab hay hướng dẫn cài đặt.
