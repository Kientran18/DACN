# Rà soát tuần 1 đến tuần 3

Ngày rà soát: 2026-10-19. Đối chiếu main tại `b16afa779533425d16b17077b0166ead7212f5a6`, kế hoạch 12 tuần cập nhật và issue #1–#4, #6–#9, #13–#16.

## Kết luận

Đã có sản phẩm nghiên cứu, XML thật và collector file mode. Chưa nghiệm thu toàn bộ tuần 1–3 hoặc M1: cần review chuyên môn, chốt schema và bổ sung bằng chứng còn thiếu. Việc đóng issue hoặc merge PR không tự chứng minh mọi tiêu chí đã đạt.

## Phân công owner và reviewer

Owner giữ theo assignee các issue trước. Reviewer dưới đây là phân công đề xuất để nhóm xác nhận, không phải bằng chứng đã review.

| Sản phẩm | Owner | Reviewer cần xác nhận | Issue |
|---|---|---|---|
| Nghiên cứu EPP/EDR và câu hỏi bảo mật | Kientran18 | NhatHuynhHuu2005, BuiCuongTuan | #1 |
| Yêu cầu dữ liệu và backlog Data/AI | NhatHuynhHuu2005 | Kientran18, BuiCuongTuan | #2 |
| Repository, lab và conventions | BuiCuongTuan | Kientran18, NhatHuynhHuu2005 | #3 |
| Scope, phân công và backlog chung | Cả nhóm; Kientran18 tổng hợp | Cả nhóm | #4 |
| Threat Model, MITRE techniques và detection ideas | Kientran18 | NhatHuynhHuu2005, BuiCuongTuan | #7 |
| Behavior-to-Telemetry Mapping | NhatHuynhHuu2005 | Kientran18, BuiCuongTuan | #8 |
| Nguồn Windows và giới hạn thu thập | BuiCuongTuan | Kientran18, NhatHuynhHuu2005 | #9 |
| Tổng hợp tuần 2 | Cả nhóm | Cả nhóm | #6 |
| MITRE Matrix v2 và giới hạn detection | Kientran18 | NhatHuynhHuu2005, BuiCuongTuan | #14 |
| Schema v1 và mapping | NhatHuynhHuu2005 | Kientran18, BuiCuongTuan | #15 |
| Collector và mẫu thật | BuiCuongTuan | Kientran18, NhatHuynhHuu2005 | #16 |
| Tổng hợp tuần 3 | Cả nhóm | Cả nhóm | #13 |

## Nhịp planning và review đề xuất

Đầu mỗi tuần: thống nhất đầu ra, owner, reviewer, dependency và bằng chứng hoàn thành. Cuối tuần: review PR, đối chiếu DoD và ghi vấn đề chuyển tiếp. Ngày/giờ họp do nhóm xác nhận; chưa ghi nhận lịch họp đã được thống nhất hoặc cuộc họp đã diễn ra.

## Hồ sơ và bằng chứng

| Tuần | Đã có | Còn cần xác nhận |
|---|---|---|
| 1 | Scope, kiến trúc sơ bộ, nghiên cứu Cyber, đặc tả 8 nhóm dữ liệu, conventions | Phân công reviewer, lịch họp, board thực tế; liên kết bằng chứng các kết quả pipeline/test mà báo cáo cũ tuyên bố |
| 2 | 13 MITRE techniques, Threat Model, mapping và nguồn Windows | Review liên nhóm; chốt giới hạn write/rename, Event 26 và các tên trường |
| 3 | references/samples/raw, json, evidence; schema và collector | Review ma trận v2; Python live mode nếu muốn tuyên bố đã kiểm thử; giới hạn E1–E10 chưa đo đầy đủ |

## Review chờ thực hiện

| Bên xác nhận | Nội dung | Người xác nhận | Ngày | Link PR/comment | Trạng thái |
|---|---|---|---|---|---|
| Cyber | Mẫu, detection-required fields, độ phủ từng technique | Chờ Kientran18 | Chưa có | Chưa có | Chờ review |
| Data | Schema theo Event ID và mapping với JSON | Chờ NhatHuynhHuu2005 | Chưa có | Chưa có | Chờ review |
| Software | Nguồn field, config, collector và giới hạn | Chờ BuiCuongTuan | Chưa có | Chưa có | Chờ review |

## Điều kiện cập nhật DoD

Chỉ tick mục có bằng chứng. Không tự xác nhận hộ người review. Không yêu cầu code pipeline/AI hoàn chỉnh để nghiệm thu các nhiệm vụ nghiên cứu tuần 1–3. Backlog chung xem [kế hoạch 12 tuần](research-backlog-12-weeks.md); phạm vi hiện hành xem [scope](../scope/phase-1-scope.md).
