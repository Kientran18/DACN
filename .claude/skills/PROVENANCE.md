# Nguồn gốc và rà soát bộ skill DACN

Tệp này không phải skill. Nó ghi lại cách bộ skill `dacn-*` (lần bổ sung thứ ba, gồm bốn đợt) được xây dựng (2026-11-08).

## Nguồn cộng đồng đã rà soát

Chỉ **đọc** (tải mã nguồn vào thư mục tạm ngoài repository, không chạy script, không cài plugin). Rà soát nhanh theo từng mục; chưa kiểm toán toàn bộ các kho.

| Kho | Commit đã xem | Giấy phép | Kết luận |
|---|---|---|---|
| https://github.com/anthropics/skills | `2c5958ecac7cee2b583967a2c4981d0f4a75c579` | Từng skill có LICENSE riêng (đã thấy Apache-2.0 ở `frontend-design`, `webapp-testing`); một số skill tài liệu có điều khoản riêng | **Không sao chép.** `frontend-design` thiên về thẩm mỹ, không có nội dung EDR; `webapp-testing` dựa trên Playwright và script `with_server.py` (thực thi mã) nên không phù hợp quy định "không script tự động". Chỉ dùng làm tham khảo về cấu trúc skill. |
| https://github.com/trailofbits/skills | `e4dd0bb5b15535f7c5a0834187dffba6ac37e4ff` | Tệp LICENSE gốc của kho ghi CC BY-SA 4.0 (ShareAlike) | **Không sao chép.** Đã đọc `differential-review` và `sharp-edges` để lấy ý tưởng (ưu tiên theo rủi ro, nêu giới hạn độ phủ). Các skill này khai báo `allowed-tools` (Write, Bash) và dùng agent riêng, trái với quy định không cấp quyền tự động. `dacn-security-review` được viết lại độc lập theo bất biến của DACN. Cần đọc kỹ giấy phép từng thư mục trước khi dùng nội dung nguyên văn. |
| https://github.com/ComposioHQ/awesome-claude-skills | `be2a406907dbc61b73e6827ded415c96139d13a2` | Chưa kiểm tra | **Không dùng.** Danh sách tổng hợp chủ yếu skill tổng quát và tích hợp dịch vụ; không có skill EDR/Windows/Sysmon phù hợp. |
| https://github.com/obra/superpowers | `22f0b463e7a5e579904dd6211a520321035526f7` | MIT | Đã dùng ở đợt 2 (`writing-plans`, `test-driven-development`), xem `SOURCE.md` của từng skill. |

Không rà soát được: tài liệu Claude Code Skills chính thức qua mạng (chưa truy cập trong phiên này); đặc tả frontmatter dựa trên các skill đã có trong repository và danh sách skill của session.

## Skill tự xây dựng

Dựa trên tài liệu của chính DACN (đường dẫn dẫn trong từng SKILL.md) và các chuẩn kỹ thuật được nhắc ở đó: Microsoft Sysmon và Windows Event Log (bookmark, `EvtNext`/`EvtSubscribe`), MITRE ATT&CK (Technique `Txxxx` và Detection Strategy `DETxxxx`), STRIDE, NIST SP 800-61r3, SigmaHQ, OCSF, Atomic Red Team. Các tài liệu bên ngoài này **chưa được truy cập lại** trong phiên; nội dung kỹ thuật dẫn từ tài liệu DACN đã tổng hợp các nguồn đó. Skill yêu cầu tra cứu lại nguồn gốc trước khi gán technique hoặc trích Sigma.

| Skill | Ghi chú |
|---|---|
| dacn-edr-architecture, dacn-security-threat-modeling, dacn-windows-agent, dacn-windows-integration-test, dacn-data-pipeline-storage | Đợt 1 |
| dacn-detection-engine, dacn-detection-rules-mitre, dacn-detection-validation, dacn-threat-hunting, dacn-security-review | Đợt 2 |
| dacn-alert-incident-management, dacn-response-safety, dacn-backend-api, dacn-dashboard | Đợt 3 |
| dacn-ci-cd-release, dacn-end-to-end-acceptance, dacn-performance-reliability, dacn-documentation-handover | Đợt 4 |

## Gộp skill

`dacn-data-quality-observability` được gộp vào `dacn-data-pipeline-storage` (tệp `references/data-quality-metrics.md`) vì dùng chung tài liệu nguồn và ngữ cảnh kích hoạt (validation, quarantine, lineage); tách riêng sẽ trùng lặp.

## Không có trong các skill này

Hooks, MCP server, `allowed-tools`, script thực thi, lệnh cài đặt hay tải mã.
