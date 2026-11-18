# Bản nháp bàn giao #40 / PR — chưa đăng

## Tiêu đề đề xuất

feat(software): bổ sung static analysis, candidate review và hồ sơ thiết kế W06–W07 (#40)

## Nội dung

Hoàn thiện phần Software của #40 trên nền `claude_implement`: bounded static extractor (SHA-256/size/byte entropy/minimal PE), versioned IOC/Whitelist/Pattern Store, Candidate Review API có role/CAS/audit, static→DetectionResult/Alert, host watermark/lateness và durable evaluation outbox phục hồi sau crash.

Bàn giao Detection Module Architecture, Rule Loading/Config Design, W06/W07 versioned JSON schemas và examples, component/sequence/state diagrams, Windows File Access/Safety Notes, test plan, PoC file lab vô hại và Designed/Tested/Future matrix. Không thay Bronze/UUID/Silver v1.1; static table là extension proposal. Không tự response từ static hit.

## Kiểm chứng

- Regression trên Windows host với fixture/local API: 259 passed, 6 skipped; chưa chạy Playwright/dashboard và Linux launcher multi-process test.
- Bộ test mới và PoC: xem `docs/research/software/w7/03-issue-40-handoff-and-review.md` để lấy kết quả cuối cùng.
- Không nhận đã kiểm chứng trên Windows10 VirtualBox/Sysmon live; signature trust provider chưa được chọn nên PoC trả UNAVAILABLE. Không có accuracy/resource benchmark.

## Review trước khi nghiệm thu

- [ ] Data: schema/result/static table/lineage, phụ thuộc DDL v1.2.
- [ ] Cyber: proposed DACN-STATIC-001, allowlist/pattern semantics, candidate policy/thresholds.
- [ ] Software: reviewer xem diff/test evidence và chấp nhận các giới hạn thiết kế/PoC.
- [ ] Liên kết commit/PR và evidence vào #40 sau khi công bố thay đổi.

Refs #40, #38, #39, #26, #29. Chưa dùng `Closes #40` khi chưa có review bắt buộc. Không merge hoặc đóng các issue phụ thuộc theo nháp này.
