# Quy ước lưu trữ cấu hình Sysmon và script POC

## Vị trí lưu trữ

```
configs/
└── sysmon/
    ├── sysmon-config.xml      # File cấu hình Sysmon đang dùng chính thức
    └── CHANGELOG.md           # Lịch sử thay đổi config (Event ID nào thêm/bớt, vì sao)

scripts/
└── poc/
    ├── README.md              # Danh mục các script POC và mục đích của từng cái
    ├── office_spawn_powershell.ps1
    ├── temp_folder_execution.ps1
    └── registry_autorun.ps1
```

## Quy ước cho `sysmon-config.xml`

- Chỉ có **một file cấu hình chính thức** trong repo — mọi máy trong lab đều dùng chung file này.
- Mọi thay đổi (thêm Event ID, thêm rule filter/exclude) phải:
  1. Tạo nhánh `config/<mô-tả>` (ví dụ `config/add-fileCreate-event`)
  2. Cập nhật `CHANGELOG.md` kèm lý do thay đổi
  3. Mở Pull Request để review trước khi merge
- Không lưu cấu hình Sysmon rải rác trên máy cá nhân — nếu chỉnh sửa local để test, phải merge lại vào repo nếu giữ lại.

## Quy ước cho script POC (Proof of Concept / mô phỏng hành vi)

- Mỗi script POC là **một hành vi cụ thể**, đặt tên theo dạng `<hành-vi>.ps1` hoặc `.py`, ví dụ:
  - `office_spawn_powershell.ps1` — mô phỏng Word tạo tiến trình PowerShell
  - `temp_folder_execution.ps1` — mô phỏng chạy file thực thi từ thư mục Temp
- Đầu mỗi file POC phải có comment header:
  ```
  # Mục đích: ...
  # Hành vi mô phỏng theo MITRE ATT&CK: <Tactic/Technique ID nếu có>
  # Mức độ rủi ro khi chạy: vô hại (an toàn để chạy trên máy lab)
  # Cách rollback sau khi chạy: ...
  ```
- Script POC **chỉ chạy trên VM lab** (xem `docs/environment/windows-lab-environment.md`), không chạy trên máy cá nhân đang phát triển code.
- `scripts/poc/README.md` liệt kê bảng: tên script | hành vi mô phỏng | rule/feature dự kiến kích hoạt | trạng thái đã test chưa.

## Lý do tách riêng `configs/` và `scripts/poc/`

- `configs/sysmon/` là **cấu hình thu thập dữ liệu** (cái gì được log).
- `scripts/poc/` là **dữ liệu đầu vào để kiểm thử** hệ thống phát hiện (tạo ra sự kiện để hệ thống phải phát hiện).
- Tách riêng giúp review rõ ràng: thay đổi cấu hình Sysmon ảnh hưởng đến toàn bộ pipeline, còn thêm POC chỉ ảnh hưởng đến phạm vi kiểm thử.
