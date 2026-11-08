---
name: dacn-security-threat-modeling
description: Mô hình đe dọa nhắm vào chính EDR DACN theo STRIDE. Tự dùng khi cần xác định tài sản, trust boundary, nguy cơ giả mạo hoặc sửa telemetry, rule, config, log, leo thang đặc quyền của response, và biện pháp phòng thủ cho một thiết kế. Chỉ phục vụ phòng thủ. Không dùng để rà soát một diff cụ thể (dacn-security-review).
---

# Threat modeling cho chính EDR

## Phân biệt hai loại mô hình đe dọa
- `docs/architecture/threat_model_v1.md` mô hình **mối đe dọa mà EDR phải phát hiện** trên endpoint (hành vi, theo kịch bản).
- Skill này mô hình **mối đe dọa nhắm vào chính EDR** (agent, dữ liệu, rule, response). Kiến trúc v2 mục 8.3 đã nêu các nhóm: sửa rule/config, xóa log/reset record id, thay bằng chứng, leo thang đặc quyền của response component, DoS do log volume, false positive gây response sai.

## Đọc trước
`docs/architecture/threat_model_v1.md` (assets, boundary, kịch bản), `docs/scope/phase-1-scope.md` (assets, giả định "Agent đang hoạt động bình thường"), `docs/architecture/local-edr-reference-architecture-v2.md` mục 3, 7, 8, `docs/research/cyber/w5/03-security-review-schema-quality-retention.md`, `04-telemetry-gaps-and-w06-w09-backlog.md`, ADR 0003 (raw preservation) và 0005 (quarantine).

## Quy trình
1. **Tài sản:** liệt kê từ phạm vi Phase 1 (Bronze raw, Silver, rule, signature/allowlist, audit log, quarantine file, cấu hình, quyền response).
2. **Trust boundary** theo kiến trúc v2: A (Windows host/Sysmon), B (EDR runtime: collector, pipeline, detection, response executor), C (operator/UI localhost). Với mỗi boundary ghi dữ liệu băng qua và quyền hiện có.
3. **STRIDE theo từng luồng dữ liệu** (collector→Bronze, Bronze→Silver, rule load, alert→response, UI→store, quarantine store): Spoofing (giả mạo telemetry, giả approver), Tampering (sửa Bronze/rule/config), Repudiation (thiếu audit), Information disclosure (raw XML chứa user, đường dẫn, secret trong command line), DoS (tràn log, đầy đĩa), Elevation of privilege (response executor, service quyền cao).
4. **Đánh giá rủi ro:** khả năng × tác động, kèm giả định. Tách "đã có biện pháp trong code" khỏi "đề xuất".
5. **Biện pháp phòng thủ tương ứng:** ACL NTFS tối thiểu, manifest/hash cho segment, rule có version và checksum, approval gate và audit cho response, allowlist protected path, health/heartbeat. Gắn mỗi biện pháp với module và tuần có thể làm.
6. **Rủi ro còn lại và tuyên bố giới hạn:** agent user-space dựa trên Sysmon **không** tương đương EDR kernel tamper-resistant; không tuyên bố ngược lại.

## Nguyên tắc không được vi phạm
- Chỉ phục vụ phòng thủ. Không viết exploit, không hướng dẫn vô hiệu hóa bảo vệ Windows, không thử tấn công hệ thống thật. Kịch bản mô phỏng chỉ trên VM lab đã có snapshot (`docs/research/software/w1/05-windows-lab-environment.md`).
- Không bịa lỗ hổng hay biện pháp "đã có": mỗi khẳng định về hiện trạng phải dẫn code/tài liệu. Chưa xác minh thì ghi "chưa xác minh".
- Không đưa tên máy, người dùng thật, secret từ `references/samples/` vào báo cáo.
- Thay đổi biện pháp chạm contract/identity/kiến trúc chỉ ở mức đề xuất.

## Kiểm tra kết quả
Mỗi mối đe dọa có: tài sản, boundary, loại STRIDE, bằng chứng hiện trạng, biện pháp, người sở hữu, cách kiểm thử (ví dụ drill: sửa một byte segment → phát hiện bằng hash; sửa file rule → từ chối do checksum). Không có biện pháp nào mâu thuẫn ADR Accepted.

## Đầu ra
```markdown
## Phạm vi, giả định, tài sản
## Trust boundary và luồng dữ liệu
## Bảng mối đe dọa (ID, STRIDE, tài sản, mức rủi ro, hiện trạng, biện pháp, owner)
## Rủi ro còn lại và giới hạn tuyên bố
## Kiểm thử đề xuất (an toàn, trên VM lab)
```

## Cần hỏi người dùng
Trước khi đề xuất thay đổi quyền (service account, ACL), thêm cơ chế ký/xác thực mới, hoặc mô phỏng tấn công có tác dụng phụ trên máy; trước khi ghi báo cáo vào `docs/`.

## Phối hợp với skill khác
- Trước đó: dacn-edr-architecture
- Cùng lúc: dacn-response-safety khi liên quan response
- Sau đó: dacn-security-review
