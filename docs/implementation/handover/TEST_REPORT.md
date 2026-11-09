# EDR — Báo cáo kiểm thử (PH12-T03)

> Tổng hợp từ [../acceptance/ACCEPTANCE_REPORT.md](../acceptance/ACCEPTANCE_REPORT.md) (sinh tự động; số liệu chi tiết lấy từ đó). Không sao chép số liệu tay vào các tài liệu khác.

## 1. Phạm vi và môi trường

- Môi trường duy nhất đã chạy: **Linux container**, Python 3.13, pytest 9.2, DuckDB 2.0, FastAPI 0.162, dữ liệu **synthetic/giả lập**. Phiên bản chính xác ở đầu báo cáo sinh tự động.
- **Windows 10 VM: chưa chạy bất kỳ test nào.**

## 2. Kết quả

| Hạng mục | Kết quả (2026-11-08; chạy lại 2026-11-09 sau `36ee751`) |
|---|---|
| Toàn bộ pytest | 233 pass, 0 fail (Linux, 2026-11-09; 201 → 213 sau `36ee751` → 233 sau đợt hoàn thiện phần mềm) |
| Nghiệm thu AT-01…43 mức L | 28 PASS · 1 PARTIAL · 0 FAIL · 14 NOT RUN |
| Hai lỗi baseline của PH1 | Đã sửa và chạy lại (`C-002`; entropy test dùng giá trị đã biết) |

PARTIAL: AT-31 (thiếu kiểm tra loading), AT-32 (thiếu kiểm tra kết quả response trên màn chi tiết), AT-41 (mới kiểm liên kết nội bộ), AT-43 (chưa có detector giả). NOT RUN: các AT mức W (AT-03/04/05/16/25/26/33/34…40).

## 3. Lỗi thật phát hiện nhờ kiểm thử

- Agent và launcher dùng hai đường dẫn khác nhau cho tệp dừng (chỉ lộ khi chạy tiến trình thật).
- `edr_ctl status/stop` phụ thuộc tham số của `start`.
- `[object HTMLElement]` hiển thị trong dashboard, chỉ thấy qua ảnh chụp; nay có test chặn.
- Nhiều lỗi nhỏ khác ghi trong nhật ký phiên của `EDR_PROGRESS.md`.

## 4. Điều kết quả này KHÔNG chứng minh

- Đọc Event Log thật, `WinProcessApi`, script lab PowerShell, cấu hình Sysmon và hướng dẫn cài đặt trên Windows.
- Chất lượng phát hiện: các rule đều `synthetic_only`; không có tỷ lệ TP/FP/FN, không có số liệu hiệu năng (CPU/RAM trên VM 2 GB chưa đo).
- Khả năng phát hiện malware thật.

## 5. Tái tạo

```bash
python -m pytest -q
python scripts/acceptance/run_acceptance.py
```
