# Môi trường Windows Lab dùng chung

## Mục đích

Đảm bảo mọi thành viên phát triển/kiểm thử trên **cùng một cấu hình môi trường**, tránh tình trạng "chạy trên máy tôi thì được".

## Thành phần môi trường

| Thành phần | Cấu hình đề xuất | Ghi chú |
|---|---|---|
| Hệ điều hành | Windows 10/11 (64-bit) | Ghi rõ build version đang dùng chung |
| Loại máy | Máy ảo (VM) — VirtualBox hoặc VMware / Hyper-V | Không dùng máy thật để tránh rủi ro khi test hành vi độc hại mô phỏng |
| RAM / CPU | Tối thiểu 4GB RAM, 2 core | Đủ chạy Sysmon + collector + Streamlit |
| Sysmon | Phiên bản cố định (ví dụ Sysmon 15.x) | Version phải giống nhau giữa các máy để log có cùng format |
| Python | Phiên bản cố định (ví dụ 3.11) | Định nghĩa trong `requirements.txt` + `python-version` file |
| Snapshot | Chụp snapshot VM "sạch" ngay sau khi cài đặt xong | Dùng để rollback sau khi chạy POC/mô phỏng hành vi |

## Quy trình thiết lập môi trường

1. Cài Windows trên VM (bản ISO thống nhất — ghi rõ nguồn tải trong tài liệu).
2. Cài Sysmon với `configs/sysmon/sysmon-config.xml` của repo (không dùng config tự chỉnh riêng).
3. Cài Python theo `requirements.txt`.
4. Chụp **snapshot "clean state"** trước khi chạy bất kỳ script POC/mô phỏng nào.
5. Ghi lại thông tin máy (build Windows, version Sysmon, ngày tạo snapshot) vào file `docs/environment/environment-log.md`.

## Quy tắc dùng chung

- **Không sửa `sysmon-config.xml` trực tiếp trên máy** — mọi thay đổi cấu hình Sysmon phải qua Pull Request vào `configs/sysmon/`.
- **Không chạy mã độc thật** trên VM dùng chung — chỉ dùng script mô phỏng vô hại (ví dụ theo Atomic Red Team) theo đúng phạm vi đồ án.
- Sau mỗi lần chạy thử nghiệm hành vi bất thường, **rollback về snapshot sạch** trước khi bắt đầu thử nghiệm tiếp theo, tránh log bị nhiễu chéo giữa các lần test.
- Nếu môi trường lab được chia sẻ qua cloud VM (ví dụ Azure/AWS), cần thống nhất về:
  - Ai có quyền truy cập
  - Lịch dùng chung (tránh hai người chạy test cùng lúc gây log lẫn lộn)
  - Cách backup/khôi phục snapshot

## Việc cần làm để hoàn tất

- [ ] Chọn nền tảng ảo hóa (VirtualBox/VMware/Hyper-V/Cloud VM) và thống nhất trong team
- [ ] Tạo VM chuẩn + cài Sysmon + chụp snapshot sạch
- [ ] Viết `environment-log.md` ghi thông tin cấu hình đã chốt (version cụ thể)
