# Kết quả đánh giá Atomic Red Team - lần 1 (2026-11-26)

> Một Windows 10 VM, một lần chạy cho mỗi test, Defender bật. Số liệu chép từ `atomic_report.md` (do `tests/e2e/atomic_compare.py`
> sinh trên VM) và bảng Defender do người vận hành ghi. Cỡ mẫu rất nhỏ: **không** suy ra tỷ lệ phát hiện chung của DACN.
> Kỳ vọng (`tests/e2e/atomic_expected.yaml`) vẫn là đề xuất, chưa được Cyber duyệt. Không ghi hostname/username.

## Môi trường

| Mục | Giá trị |
|---|---|
| Ngày chạy (UTC) | 2026-11-26, khoảng 02:40-03:20 |
| Sysmon | v15.22, cấu hình `poc/sysmon-collector/configs/sysmon-config.xml` |
| Defender | AMProductVersion 4.18.26100.4, signature 1.463.461.0 (ghi ở chặng chuẩn bị), real-time protection bật, tamper protection bật |
| Invoke-AtomicRedTeam / powershell-yaml | 2.3.0 / 0.4.12 (PSGallery) |
| Atomics commit | a0e3f9bc69fed2fd711bd1f1aa87a40c33482fe6 (6 YAML, SHA-256 khớp) |
| DACN | `edr_ctl start --live`, response `dry_run`; commit trên VM chưa được ghi lại |
| Windows build | Windows 10 Pro, 10.0.19045 (theo output `systeminfo` của C01 lần 2) |

## Từng test

| ID | Technique | Kỳ vọng | Kết luận DACN | Rule MATCH | Telemetry quan sát (Event ID) | Defender |
|---|---|---|---|---|---|---|
| C01 | T1082 | Đối chứng | TN | - | 1, 5 | Không |
| C02 | T1059.003 | Đối chứng | TN | - | 1, 5, 11 | Không |
| A01 | T1059.001 | DET-001 MATCH | **TP** | DET-001 | 1, 5, 11, 26 | Không |
| A02 | T1059.001 | DET-001 MATCH | **Không khởi tạo được** (Defender chặn) | - | - | Có: Trojan:Win32/Powessere.K |
| A03 | T1059.001 | FN dự kiến (thiếu 4104) | **Không khởi tạo được** (Defender chặn) | - | - | Có: Trojan:PowerShell/Mimikatz.A |
| A04 | T1547.001 | DET-003 MATCH | **TP** | DET-003 | 1, 5, 12, 13 | Không |
| A05 | T1547.001 | DET-003 MATCH | **TP** | DET-003 | 1, 5, 11, 13, 26 | Không |
| A06 | T1547.001 | FN dự kiến (RunOnceEx) | FN dự kiến | - | 1, 5, 12, 13 | Không |
| A07 | T1547.001 | FN dự kiến (Sysmon không thu) | FN dự kiến | - | 1, 5, 11, 26 | Không |
| A08 | T1053.005 | DET-004 MATCH | **TP** | DET-004 | 1, 5 | Không |
| A09 | T1053.005 | DET-004 MATCH | **TP** | DET-004 | 1, 5 | Có: Trojan:Win32/Commandrob.A!ml |
| A10 | T1053.005 | FN dự kiến (không qua schtasks) | FN dự kiến | - | 1, 5, 11, 26 | Không |
| A11 | T1070.004 | FN dự kiến (chưa có rule) | FN dự kiến | - | 1, 5, 26 | Không |

Cleanup: người vận hành ghi "có" (không lỗi) cho cả 13 test.

A02 và A03: báo cáo chạy trên VM ghi `KHONG_THAY_TIEN_TRINH_GOC`, exit rỗng. Ảnh chụp cửa sổ chạy cho thấy
`Exception calling "Start" ... "Access is denied"` tại `Invoke-Process.ps1` và Defender ghi nhận mối đe dọa, tức tiến trình
`powershell.exe` của atomic không được tạo. Công cụ sau đó được sửa để tách trường hợp này thành `KHONG_KHOI_TAO_DUOC`
(log không có pid); bảng trên dùng tên mới. Hai test này không tính vào TP/FN của DACN.

## Tổng hợp (số đếm)

| Mục | Số |
|---|---|
| Test TP_EXPECTED đã chạy | 6 (A01, A02, A04, A05, A08, A09) |
| TP | 5 |
| FN | 0 |
| Không đánh giá được do Defender chặn khi tạo tiến trình | 2 (A02, A03) |
| FN dự kiến đúng như kỳ vọng | 4 (A06, A07, A10, A11) |
| MATCH ngoài dự kiến | 0 |
| Đối chứng: TN / FP | 2 / 0 |
| Không thấy tiến trình gốc (mất telemetry) | 0 |
| Defender phản ứng | 3 (A02, A03, A09) |

## Nhận xét

Quan sát:
- Với 5 test mà tiến trình chạy được và có rule tương ứng, rule mục tiêu đều MATCH trên đúng cây tiến trình của test
  (DET-001 ×1, DET-003 ×2, DET-004 ×2). Hai test đối chứng không có MATCH.
- A06 có Event 12/13 nhưng không có MATCH DET-003; A07 không có Event 13. A11 có Event 26 nhưng không có MATCH.
- A09: cả Defender (Commandrob.A!ml) lẫn DACN (DET-004) đều phát hiện; tiến trình vẫn chạy (exit 0).

Suy luận (cần xác nhận thêm):
- A06 phù hợp với khoảng trống của regex DET-003 (không nhận `RunOnceEx\...`); A07 phù hợp với việc cấu hình Sysmon không include
  `\Policies\Explorer\Run`. Cả hai là đề xuất bổ sung rule/cấu hình, cần Cyber duyệt trước khi sửa.
- A10 và A11 xác nhận giới hạn đã ghi của DET-004 (chỉ `schtasks.exe`) và DET-010 (cần đủ chuỗi tạo-chạy-xóa).

Giới hạn: một VM, mỗi test một lần, tập test do Claude chọn để khớp rule hiện có (thiên lệch về phía MATCH); không đo FP trên tải lành tính
thực tế; không đo độ trễ phát hiện. Không suy rộng thành chất lượng phát hiện chung.

## Lần 2 (2026-11-26, khoảng 07:41-07:48 UTC): sau DET-003 v2 và cấu hình Sysmon mới

Thay đổi so với lần 1 (commit `37173d1`, người dùng duyệt): DET-003 `rule_version` 2 nhận RunOnceEx; cấu hình Sysmon include
`\Policies\Explorer\Run`. Cấu hình được áp bằng `Sysmon64.exe -c` (Sysmon báo `Configuration updated.`) và kiểm tra trong output
`Sysmon64.exe -c` có cả `\CurrentVersion\Run` lẫn `\Policies\Explorer\Run`. DACN trên VM ở commit `37173d1`, `--live`, `dry_run`.
Chỉ chạy lại C01, C02, A06, A07; log lần 1 được tách sang thư mục khác.

| ID | Technique | Kỳ vọng (v2) | Kết luận DACN | Rule MATCH | Telemetry (Event ID) | Defender |
|---|---|---|---|---|---|---|
| C01 | T1082 | Đối chứng | TN | - | 1, 5 | Không |
| C02 | T1059.003 | Đối chứng | TN | - | 1, 5, 11 | Không |
| A06 | T1547.001 | DET-003 MATCH | **TP** | DET-003 | 1, 5, 12, 13 | Không |
| A07 | T1547.001 | FN dự kiến (chưa có rule) | FN dự kiến | - | 1, 5, 11, 13, 26 | Không |

Quan sát:
- A06: cùng atomic, cùng loại telemetry (12, 13) như lần 1; lần 1 (DET-003 v1) không MATCH, lần 2 (v2) MATCH.
- A07: lần 1 cây tiến trình không có Event 13; lần 2 có Event 13. Không có rule nào MATCH, đúng kỳ vọng vì DET-003 v2 chưa gồm
  `\Policies\Explorer\Run`.
- Exit code 0 cho cả 4 test; Defender không phản ứng với test nào (người vận hành kiểm tra `Get-MpThreatDetection` sau mỗi test).

Suy luận: Event 13 mới của A07 nhiều khả năng là giá trị ghi vào `\Policies\Explorer\Run` (mục include vừa thêm); báo cáo công cụ
chỉ liệt kê Event ID, không in đường dẫn khóa, nên chưa đối chiếu trực tiếp `target_object`.

Tổng hợp lần 2: TP_EXPECTED đã chạy 1 (A06), TP 1, FN 0; FN dự kiến 1 (A07); đối chứng TN 2, FP 0. Mỗi test một lần trên một VM.
