---
name: verification-before-completion
description: Kiểm chứng trước khi báo xong. Tự dùng ngay trước khi nói đã hoàn thành, đã sửa, test đã pass, và trước khi commit, push, tạo Pull Request hoặc nộp báo cáo kết quả. Bắt buộc chạy lệnh kiểm chứng mới và đọc đủ output rồi mới khẳng định. Không dùng để tìm nguyên nhân lỗi (dùng systematic-debugging).
---

# Kiểm chứng trước khi hoàn thành

## Tổng quan

**Nguyên tắc cốt lõi:** Có bằng chứng rồi mới khẳng định, luôn luôn.

**Vi phạm nội dung của quy tắc này là vi phạm tinh thần của quy tắc.**

## Quy tắc sắt

```
KHÔNG KHẲNG ĐỊNH HOÀN THÀNH KHI CHƯA CÓ BẰNG CHỨNG KIỂM CHỨNG MỚI
```

Nếu trong lượt trả lời này chưa chạy lệnh kiểm chứng, bạn không được khẳng định test đã pass.

## Quy trình kiểm tra

```
TRƯỚC KHI khẳng định bất kỳ trạng thái nào hoặc thể hiện sự hài lòng:

1. XÁC ĐỊNH: Lệnh nào chứng minh khẳng định này?
2. CHẠY: Thực thi TOÀN BỘ lệnh (mới, đầy đủ)
3. ĐỌC: Đọc toàn bộ output, kiểm tra exit code, đếm số lỗi
4. XÁC MINH: Output có xác nhận khẳng định không?
   - Nếu KHÔNG: nêu trạng thái thực tế kèm bằng chứng
   - Nếu CÓ: nêu khẳng định KÈM bằng chứng
5. CHỈ KHI ĐÓ: đưa ra khẳng định

Bỏ qua bất kỳ bước nào = không kiểm chứng mà còn khai sai.
```

## Các lỗi thường gặp

| Khẳng định | Cần có | Không đủ |
|------------|--------|----------|
| Test pass | Output lệnh test: 0 lỗi | Lần chạy trước, "chắc là pass" |
| Linter sạch | Output linter: 0 lỗi | Kiểm tra một phần, suy diễn |
| Build thành công | Lệnh build: exit 0 | Linter pass, log trông ổn |
| Lỗi đã sửa | Chạy lại đúng triệu chứng ban đầu: pass | Đã sửa code, cho rằng đã xong |
| Test hồi quy hoạt động | Đã xác nhận chu trình đỏ-xanh | Test pass đúng một lần |
| Agent hoàn thành việc | Diff thay đổi trong VCS | Agent báo "thành công" |
| Đáp ứng yêu cầu | Checklist từng mục | Test pass |

## Dấu hiệu cảnh báo: DỪNG LẠI

- Dùng các từ "chắc là", "có vẻ", "nên là", "probably", "should"
- Thể hiện hài lòng trước khi kiểm chứng ("Tốt!", "Xong!", "Hoàn hảo!")
- Chuẩn bị commit, push hoặc tạo PR mà chưa kiểm chứng
- Tin vào báo cáo thành công của agent con
- Chỉ kiểm chứng một phần
- Nghĩ "lần này thôi"
- Mọi cách diễn đạt ngụ ý thành công mà chưa chạy kiểm chứng

## Bảng phản bác lý do

| Lý do | Thực tế |
|-------|---------|
| "Chắc giờ chạy được" | Hãy CHẠY kiểm chứng |
| "Tôi khá tự tin" | Tự tin không phải bằng chứng |
| "Lần này thôi" | Không có ngoại lệ |
| "Linter đã pass" | Linter không phải trình biên dịch |
| "Agent nói thành công" | Tự kiểm chứng độc lập |
| "Kiểm tra một phần là đủ" | Kiểm tra một phần không chứng minh được gì |
| "Đổi cách nói thì quy tắc không áp dụng" | Tinh thần quan trọng hơn câu chữ |

## Mẫu áp dụng

**Test:**
```
✅ [Chạy lệnh test] [Thấy: 34/34 pass] "Toàn bộ test pass"
❌ "Chắc pass rồi" / "Có vẻ đúng"
```

**Test hồi quy (TDD đỏ-xanh):**
```
✅ Viết test → Chạy (pass) → Hoàn tác fix → Chạy (PHẢI FAIL) → Khôi phục fix → Chạy (pass)
❌ "Tôi đã viết test hồi quy" (khi chưa kiểm chứng chu trình đỏ-xanh)
```

**Build:**
```
✅ [Chạy build] [Thấy: exit 0] "Build thành công"
❌ "Linter pass" (linter không kiểm tra biên dịch)
```

**Yêu cầu:**
```
✅ Đọc lại kế hoạch → Lập checklist → Kiểm chứng từng mục → Báo cáo phần còn thiếu hoặc hoàn thành
❌ "Test pass, giai đoạn xong"
```

**Ủy quyền cho agent:**
```
✅ Agent báo thành công → Kiểm tra diff VCS → Xác minh thay đổi → Báo cáo trạng thái thực tế
❌ Tin vào báo cáo của agent
```

## Khi nào áp dụng

**LUÔN LUÔN trước khi:**
- Khẳng định thành công hoặc hoàn thành dưới bất kỳ dạng nào
- Thể hiện sự hài lòng
- Đưa ra nhận định tích cực về trạng thái công việc
- Commit, tạo Pull Request, đánh dấu task hoàn thành
- Chuyển sang task tiếp theo
- Giao việc cho agent

**Quy tắc áp dụng cho:**
- Đúng từng cụm từ
- Cách diễn đạt khác có cùng ý
- Hàm ý thành công
- Mọi cách truyền đạt cho thấy công việc đã hoàn thành hoặc đúng

## Áp dụng cho DACN

Các điều dưới đây bổ sung cho quy trình trên, theo `CLAUDE.md` của repository.

1. **Lệnh kiểm chứng.** Lấy lệnh từ `CLAUDE.md` mục 4, ví dụ:
   - `python -m pytest -q poc/sysmon-collector`
   - `python -m pytest -q tests/`
   - `python -m unittest tests.test_validator_poc_w5`
   Chạy đầy đủ, không chỉ chạy một test khi cần kiểm chứng toàn bộ.
2. **Lỗi đã ghi nhận.** `CLAUDE.md` mục 3.1 ghi hai test đang fail. Không được báo "toàn bộ test pass" nếu chưa chạy lại và đọc output. Nếu một trong hai vẫn fail, phải nêu rõ.
3. **Live mode Windows.** Chưa được kiểm chứng trên Windows host thật. Không khẳng định live mode hoạt động nếu chưa có bằng chứng từ môi trường Windows.
4. **Chu trình đỏ-xanh không dùng git để hoàn tác.** Trong repository có thay đổi chưa commit, không dùng `git checkout`, `git reset`, `git stash`, `git clean` để "revert fix". Thay vào đó:
   - Sao chép file đang sửa sang thư mục scratchpad trước khi thử nghiệm.
   - Áp dụng bước "hoàn tác" thủ công trên bản làm việc, chạy test và ghi nhận kết quả.
   - Khôi phục từ bản sao đã lưu, rồi so sánh (`diff`) để xác nhận file trở về đúng trạng thái trước thử nghiệm.
5. **Báo cáo.** Ghi rõ lệnh đã chạy, thời điểm, số test pass/fail và các test không chạy được. Không tuyên bố issue hoàn thành khi chưa có kết quả test liên quan.
6. **Không commit, push hoặc tạo Pull Request** khi người dùng chưa xem xét và đồng ý (`CLAUDE.md` mục 8.6).
