# Kết quả đánh giá Atomic Red Team - MẪU TRỐNG

> Sao chép tệp này rồi điền. Chỉ ghi điều quan sát được trên VM; ô chưa chạy để `NOT RUN`. Không ghi hostname, username, IP.
> Hướng dẫn: `ATOMIC_RED_TEAM_EVAL_GUIDE.md`. Cột "Kết luận DACN" chép từ `atomic_report.md`.

## Thông tin lần chạy

| Mục | Giá trị |
|---|---|
| Ngày chạy (UTC) | |
| Windows build | |
| Sysmon (phiên bản, tệp cấu hình) | |
| Defender (AMProductVersion, AntivirusSignatureVersion, RealTimeProtection) | |
| Invoke-AtomicRedTeam / powershell-yaml (phiên bản) | |
| Atomics commit | a0e3f9bc69fed2fd711bd1f1aa87a40c33482fe6 |
| DACN commit (`git log --oneline -1`) | |
| Chế độ DACN | `--live`, response `dry_run` |

## Từng test

| ID | Technique | Kỳ vọng | Kết luận DACN | Defender phản ứng (Có/Không/Không rõ) | ThreatName | Cleanup OK | Ghi chú |
|---|---|---|---|---|---|---|---|
| C01 | T1082 | Đối chứng | | | | | |
| C02 | T1059.003 | Đối chứng | | | | | |
| A01 | T1059.001 | DET-001 MATCH | | | | | |
| A02 | T1059.001 | DET-001 MATCH | | | | | |
| A03 | T1059.001 | FN dự kiến (thiếu 4104) | | | | | |
| A04 | T1547.001 | DET-003 MATCH | | | | | |
| A05 | T1547.001 | DET-003 MATCH | | | | | |
| A06 | T1547.001 | FN dự kiến (RunOnceEx) | | | | | |
| A07 | T1547.001 | FN dự kiến (Sysmon không thu) | | | | | |
| A08 | T1053.005 | DET-004 MATCH | | | | | |
| A09 | T1053.005 | DET-004 MATCH | | | | | |
| A10 | T1053.005 | FN dự kiến (không qua schtasks) | | | | | |
| A11 | T1070.004 | FN dự kiến (chưa có rule) | | | | | |

## Tổng hợp (chỉ điền số đếm từ báo cáo)

| Mục | Số |
|---|---|
| Test TP_EXPECTED đã chạy | |
| TP | |
| FN | |
| FN dự kiến đúng như kỳ vọng | |
| MATCH ngoài dự kiến | |
| Đối chứng: TN / FP | |
| Không thấy tiến trình gốc | |
| Defender phản ứng | |

Nhận xét (phân biệt quan sát và suy luận):
