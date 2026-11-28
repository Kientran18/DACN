# Hướng dẫn kiểm tra rule Sigma trên Windows 10 VM

> Người dùng chạy, Claude **không** chạy trên VM. Chưa có kết quả nào: mọi ô kết quả trong báo cáo để trống cho tới khi có số đo thật.
> Rule Sigma là `synthetic_only`, chỉ tạo alert, không kích hoạt response. Không tắt Defender, không dùng mã độc thật.
> Tài liệu nền: `docs/implementation/SIGMA_RULES.md`, `ATOMIC_RED_TEAM_EVAL_GUIDE.md` (cách chạy atomic, giữ nguyên quy tắc an toàn ở đó).

## 1. Mục tiêu

1. **V-S1:** Sigma bật trên VM, `GET /sigma/rules` báo 28 rule đã nạp, 0 bị loại (kiểm sha256 sau khi Git checkout trên Windows).
2. **V-S2:** Chạy lại các atomic liên quan (A01–A11, C01–C02 theo `tests/e2e/atomic_expected.yaml`), mỗi test một lần, rồi so
   **số rule DACN và số rule Sigma khớp** theo từng lần chạy bằng `atomic_compare.py --sigma`.
3. **V-S3:** Mở một alert Sigma trên dashboard: nguồn "Sigma", khung "Rule Sigma" có tác giả, giấy phép, link rule gốc; chạy
   `GET /alerts/{id}/evidence` truy vết tới `raw_xml`.
4. **V-S4 (tùy chọn):** Đo số coverage gap do rule Sigma tạo trên tải lành tính 30 phút (dự phòng rủi ro INSUFFICIENT_TELEMETRY nhiều).

## 2. Chuẩn bị

```powershell
C:\dacn_venv\Scripts\Activate.ps1
cd C:\DACN
git pull --ff-only origin claude_implement
$env:PYTHONPATH = "src;src\pipeline;poc\sysmon-collector"
python -m detection.sigma list          # phải in "rejected": [] ; mã thoát 0
```

Nếu `list` báo SIG-E009 (sha256 lệch): ghi lại tên tệp và gửi; **không** tự sửa manifest.

Bật Sigma: sửa `config\sigma-rules.yaml` thành `enabled: true` (giữ các khóa khác). Snapshot VM trước khi bắt đầu.

## 3. V-S1: nạp rule

```powershell
python -m edr_ctl start --config C:\dacn_edr\edr.yaml --live
# token viewer/analyst như hướng dẫn cài đặt; $H = @{Authorization = "Bearer <token>"}
Invoke-RestMethod http://127.0.0.1:8765/sigma/rules -Headers $H | ConvertTo-Json -Depth 4 | Out-File C:\dacn_results\sigma_rules.json -Encoding utf8
```

Ghi: `enabled`, số `loaded`, số `rejected` (và mã nếu có). Cổng mặc định 8765 theo `config\edr.example.yaml`; dùng cổng trong `edr.yaml` của bạn.

## 4. V-S2: chạy lại atomic và so DACN và Sigma

1. Chạy các atomic như `ATOMIC_RED_TEAM_EVAL_GUIDE.md` mục 4 (cùng commit atomics, Attire log, `-Cleanup` sau mỗi test, mỗi test một lần).
2. Dừng hệ thống: `python -m edr_ctl stop --config C:\dacn_edr\edr.yaml`.
3. Đối chiếu (làm trên bản sao Silver; `--sigma` bật Sigma cho bản sao, không cần cấu hình core):

```powershell
python tests\e2e\atomic_compare.py --silver C:\dacn_edr\silver\endpoint_silver.duckdb --bronze C:\dacn_edr\bronze `
  --logs C:\dacn_art\logs --sigma --out C:\dacn_results\atomic_sigma_report.md --json C:\dacn_results\atomic_sigma_report.json
Get-Content -Encoding UTF8 C:\dacn_results\atomic_sigma_report.md
```

Báo cáo giữ kết luận TP/FN/FP/TN **chỉ theo rule DACN** (như các lượt trước) và thêm mục "So sánh rule DACN và rule Sigma (theo lần chạy)"
liệt kê rule nào khớp ở mỗi bên. Không bịa con số: ô nào không có dữ liệu để "-" như công cụ in.

4. Đếm alert thật theo nguồn (sau khi chạy lại core để AlertBuilder tạo alert):

```powershell
Invoke-RestMethod "http://127.0.0.1:8765/alerts?source=SIGMA&limit=200" -Headers $H | ConvertTo-Json -Depth 6 | Out-File C:\dacn_results\alerts_sigma.json -Encoding utf8
Invoke-RestMethod "http://127.0.0.1:8765/alerts?source=DACN&limit=200"  -Headers $H | ConvertTo-Json -Depth 6 | Out-File C:\dacn_results\alerts_dacn.json -Encoding utf8
```

## 5. V-S3: dashboard và truy vết

Mở `http://127.0.0.1:8765/ui/#/alerts?source=SIGMA`, chọn một alert, chụp khung "Rule Sigma" (che hostname/user trước khi gửi).
`GET /alerts/{id}/evidence` phải có trạng thái `FULL` và tham chiếu Bronze; `include_raw=true` cần quyền `raw` và có audit.

## 6. V-S4 (tùy chọn): tải lành tính

Để máy chạy tải thường 30 phút (duyệt web, mở Office/Notepad, cập nhật Windows nếu có), rồi:

```powershell
Invoke-RestMethod "http://127.0.0.1:8765/coverage-gaps?limit=200" -Headers $H | ConvertTo-Json -Depth 5 | Out-File C:\dacn_results\gaps.json -Encoding utf8
```

Đếm gap có `rule_id` bắt đầu bằng `DACN-SIG-` và alert Sigma trong khoảng đó. Đây là một quan sát trên một VM, **không** phải số đo FP.

## 7. Gửi lại

`sigma_rules.json`, `atomic_sigma_report.md`, số alert theo nguồn (đếm, không cần gửi nội dung), ảnh khung Rule Sigma đã che,
và (nếu làm) số gap/alert Sigma của V-S4. Không gửi log Attire, token, `raw_xml` hay ảnh có định danh.

## 8. Mẫu ghi kết quả (để trống tới khi có số đo)

| Mục | Kết quả | Ngày, máy, số lần |
|---|---|---|
| V-S1 loaded / rejected | | |
| V-S2 rule Sigma khớp theo atomic | | |
| V-S3 khung Rule Sigma + evidence FULL | | |
| V-S4 gap / alert Sigma trên tải lành tính | | |
