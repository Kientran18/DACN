# EDR — Hướng dẫn cài đặt và chạy toàn hệ thống (VM Windows 10 lab)

> **Trạng thái: CHƯA ĐƯỢC KIỂM CHỨNG TRÊN WINDOWS.** Các lệnh dưới đây chạy được trên Linux (nguồn giả/tệp XML). Mọi bước đánh dấu **[W]** là giả định chưa được thử trên Windows thật; PH10-T04 sẽ xác nhận. Nếu một bước lỗi, ghi lại đầu ra và gửi cho Claude.
> Chỉ dùng VM lab có snapshot sạch. Không chạy trên máy cá nhân.

## 0. Tiền điều kiện
- Windows 10 64-bit, **RAM khuyến nghị 4 GB** (VM hiện 2 GB, dưới mức khuyến nghị), 2 CPU, ≥ 20 GB trống.
- Quyền Administrator cho bước cài Sysmon và đọc Event Log; **chụp snapshot "clean" trước khi bắt đầu**.
- Python 3.11+ (bản kiểm thử trên Linux: 3.13.18; **Windows: chưa xác định**).

## 1. Lấy mã nguồn
```powershell
git clone https://github.com/Kientran18/DACN.git C:\DACN
cd C:\DACN
git checkout claude_implement
```

## 2. Cài thư viện
```powershell
python -m venv C:\dacn_venv
C:\dacn_venv\Scripts\activate
pip install -r requirements.txt
pip freeze > C:\dacn_pip_freeze.txt     # gửi lại để ghim phiên bản đã chạy được trên Windows
```
Phiên bản đã kiểm thử trên **Linux** (không đảm bảo cho Windows): duckdb 2.0.0, fastapi 0.162.2, uvicorn 0.54.0, httpx 0.28.1, pydantic 2.13.5, starlette 1.7.0, PyYAML 6.0.3, jsonschema 4.26.0, pytz 2026.6, pytest 9.2.0. `pywin32` chỉ cài trên Windows (có trong `requirements.txt`) **[W]**.

## 3. Sysmon (Administrator) **[W]**
Cài Sysmon do Microsoft Sysinternals phát hành (tải thủ công, kiểm tra chữ ký) rồi áp cấu hình của repo:
```powershell
Sysmon64.exe -accepteula -i C:\DACN\poc\sysmon-collector\configs\sysmon-config.xml
```
Cấu hình này chưa được xác thực trên máy thật (ghi trong chính tệp); chạy `Sysmon64.exe -s` để đối chiếu schema trước.

## 4. Kiểm tra môi trường (chỉ đọc) **[W]**
```powershell
python scripts\windows\verify_windows_env.py --out verify_report.json     # một lần user thường, một lần Administrator
```
Gửi `verify_report.json` cho Claude: kết quả quyết định PH2-T06 (nguồn Event Log).

## 5. Cấu hình
```powershell
mkdir C:\dacn_edr
copy config\edr.example.yaml C:\dacn_edr\edr.yaml
python -m api.auth --config C:\dacn_edr\edr.yaml --role analyst --actor <tên>     # token hiện MỘT LẦN, lưu lại
python -m api.auth --config C:\dacn_edr\edr.yaml --role approver --actor <tên>
```
Quy tắc hai người đang **bật** (`require_distinct_approver: true`): `--actor` của analyst và approver phải **khác nhau**. Demo một người dùng thì đặt `false` trong `config\response-policy.yaml`.

`config\response-policy.yaml` mặc định **dry_run**; **không đổi** trừ khi bạn chủ động chạy PH7-T10. Policy dùng biến `%TEMP%`, `%PUBLIC%`, `%SystemRoot%`, `%ProgramFiles%`, `%ProgramFiles(x86)%` (có sẵn trên Windows).

## 6. Chạy
```powershell
set PYTHONPATH=C:\DACN\src;C:\DACN\src\pipeline;C:\DACN\poc\sysmon-collector
python -m edr_ctl start --config C:\dacn_edr\edr.yaml --live       # [W] agent đọc Event Log thật
python -m edr_ctl status --config C:\dacn_edr\edr.yaml
```
Mở trình duyệt tại `http://127.0.0.1:8765/ui/`, dán token. Không bind địa chỉ khác.
Thử không cần Sysmon (file mode): `--agent-input C:\path\events.xml` thay cho `--live`; thêm cờ `--sample-data` cho `python -m core` nếu dữ liệu là mẫu để dashboard hiện biểu ngữ.
Responder (tùy chọn): đặt biến `EDR_RESPONDER_TOKEN` (token vai trò `responder`) rồi `start`; mặc định chỉ dry-run.

## 7. Chạy kịch bản mô phỏng
Xem `scripts\lab\README.md` (đọc script, chạy `-WhatIf`, rồi chạy thật) và đối chiếu bằng `tests\e2e\compare_expected.py`.

## 8. Dừng và gỡ
```powershell
python -m edr_ctl stop --config C:\dacn_edr\edr.yaml            # dừng sạch bằng tệp stop; chỉ ép kết thúc khi xác minh đúng tiến trình
Sysmon64.exe -u                                                 # gỡ Sysmon (Administrator)
rmdir /s /q C:\dacn_edr C:\dacn_venv                             # xóa dữ liệu và venv (tùy chọn); hoặc khôi phục snapshot clean
```

## 9. Kiểm thử trên Linux (không cần Windows)
```bash
pip install -r requirements.txt
python -m pytest -q            # 200+ test; một số cần node + playwright (tự bỏ qua nếu thiếu)
```

## Giới hạn đã biết
- `--live` (EventLogSource) chưa từng chạy trên Windows: có thể cần chỉnh sau khi có `verify_report.json`.
- Dừng tiến trình trên Windows: `edr_ctl` dùng tệp stop; ép kết thúc chỉ khi `--force` vì không xác minh được tên tiến trình trên Windows.
- `edr_ctl` không cài dịch vụ Windows; đóng cửa sổ/tắt máy sẽ dừng tiến trình. Khi khởi động lại, checkpoint cho phép tiếp tục (có thể trùng, Silver dedup).
