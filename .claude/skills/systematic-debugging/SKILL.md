---
name: systematic-debugging
description: Dùng khi gặp bất kỳ lỗi nào, test fail hoặc hành vi bất thường, trước khi đề xuất cách sửa. Tìm nguyên nhân gốc bằng bằng chứng trước, không sửa theo triệu chứng.
---

# Gỡ lỗi có hệ thống

## Tổng quan

**Nguyên tắc cốt lõi:** LUÔN tìm nguyên nhân gốc trước khi thử sửa. Sửa triệu chứng là thất bại.

**Vi phạm nội dung của quy trình này là vi phạm tinh thần của gỡ lỗi.**

## Quy tắc sắt

```
KHÔNG SỬA KHI CHƯA ĐIỀU TRA NGUYÊN NHÂN GỐC
```

Nếu chưa hoàn thành Giai đoạn 1, bạn không được đề xuất cách sửa.

## Khi nào dùng

Dùng cho MỌI vấn đề kỹ thuật:
- Test fail
- Lỗi xuất hiện khi chạy chương trình
- Hành vi không như mong đợi
- Vấn đề hiệu năng
- Build fail
- Lỗi tích hợp giữa các module

**Đặc biệt cần dùng khi:**
- Đang chịu áp lực thời gian
- Có cảm giác "chỉ cần một bản sửa nhanh"
- Đã thử nhiều cách sửa
- Lần sửa trước không có tác dụng
- Chưa hiểu rõ vấn đề

**Không được bỏ qua khi:**
- Vấn đề có vẻ đơn giản (lỗi đơn giản vẫn có nguyên nhân gốc)
- Đang vội (vội vàng chắc chắn làm phát sinh làm lại)
- Người dùng muốn sửa NGAY (có hệ thống vẫn nhanh hơn việc thử đi thử lại)

## Bốn giai đoạn

Bạn PHẢI hoàn thành từng giai đoạn trước khi sang giai đoạn sau.

### Giai đoạn 1: Điều tra nguyên nhân gốc

**TRƯỚC KHI thử BẤT KỲ cách sửa nào:**

1. **Đọc kỹ thông báo lỗi**
   - Không bỏ qua lỗi hay cảnh báo
   - Thông báo thường chứa sẵn gợi ý sửa
   - Đọc đầy đủ stack trace
   - Ghi lại số dòng, đường dẫn file, mã lỗi

2. **Tái hiện ổn định**
   - Có kích hoạt lại được không?
   - Các bước chính xác là gì?
   - Lỗi có xảy ra mỗi lần không?
   - Nếu không tái hiện được: thu thập thêm dữ liệu, đừng đoán

3. **Kiểm tra thay đổi gần đây**
   - Có gì thay đổi có thể gây ra lỗi?
   - Xem `git diff` và các commit gần đây (chỉ đọc, không hoàn tác)
   - Dependency mới, thay đổi cấu hình, khác biệt môi trường
   - Với DACN: đối chiếu `CLAUDE.md` mục 3.1 để biết lỗi nào đã được ghi nhận từ trước

4. **Thu thập bằng chứng ở hệ thống nhiều thành phần**

   **Khi lỗi đi qua nhiều thành phần** (ví dụ luồng Sysmon XML → collector → Bronze → adapter → validator), cần đặt điểm quan sát TRƯỚC khi đề xuất sửa:
   ```
   Với MỖI ranh giới thành phần:
     - Ghi lại dữ liệu đi vào thành phần
     - Ghi lại dữ liệu đi ra khỏi thành phần
     - Kiểm tra môi trường và cấu hình được truyền đúng
     - Kiểm tra trạng thái ở từng tầng

   Chạy một lần để thu thập bằng chứng cho thấy lỗi xảy ra ở ĐÂU
   SAU ĐÓ phân tích bằng chứng để xác định thành phần lỗi
   SAU ĐÓ điều tra sâu thành phần đó
   ```

   **Ví dụ với DACN:** dùng một script Python tạm, đặt trong scratchpad, import các hàm từ module (theo mô hình import trong `CLAUDE.md` mục 5) và in ra dữ liệu tại từng bước:
   ```python
   # Script tạm trong scratchpad, KHÔNG thêm vào repository
   import sys
   from pathlib import Path
   sys.path.insert(0, "poc/sysmon-collector")
   import bronze_contract as bc

   # iter_raw_xml_from_file tách từng <Event>...</Event> khỏi file mẫu
   raw = next(bc.iter_raw_xml_from_file(Path("references/samples/raw/raw_process_create_event1.xml")))
   rec = bc.build_bronze_record(raw, mode="file")
   print("Bronze event_data:", rec["event_data"])
   print("Lỗi schema:", bc.validate_record(rec))
   ```
   Cách này cho thấy dữ liệu đúng hay sai ở tầng nào, mà không cần sửa mã nguồn.

5. **Truy vết luồng dữ liệu**

   **Khi lỗi nằm sâu trong call stack:**
   - Giá trị sai xuất phát từ đâu?
   - Hàm nào gọi với giá trị sai?
   - Tiếp tục truy ngược đến khi tìm được nguồn gốc
   - Sửa tại nguồn, không sửa tại nơi lỗi hiện ra

### Giai đoạn 2: Phân tích mẫu

**Tìm mẫu trước khi sửa:**

1. **Tìm ví dụ đang hoạt động**
   - Tìm đoạn code tương tự đang chạy đúng trong cùng repository
   - Điều gì hoạt động tương tự với phần đang lỗi?

2. **So sánh với tham chiếu**
   - Khi áp dụng một mẫu, đọc KỸ toàn bộ tài liệu hoặc code tham chiếu
   - Không đọc lướt; hiểu mẫu đầy đủ trước khi áp dụng

3. **Xác định khác biệt**
   - Khác biệt giữa phần hoạt động và phần lỗi là gì?
   - Liệt kê MỌI khác biệt, kể cả nhỏ nhất
   - Không giả định "cái đó không ảnh hưởng"

4. **Hiểu các phụ thuộc**
   - Thành phần này cần những thành phần nào khác?
   - Cần cấu hình, môi trường, dữ liệu nào?
   - Nó giả định điều gì?

### Giai đoạn 3: Giả thuyết và kiểm thử

**Phương pháp khoa học:**

1. **Nêu một giả thuyết duy nhất**
   - Nói rõ: "Tôi cho rằng X là nguyên nhân gốc vì Y"
   - Ghi lại bằng văn bản
   - Cụ thể, không mơ hồ

2. **Kiểm thử tối thiểu**
   - Thay đổi NHỎ NHẤT có thể để kiểm tra giả thuyết
   - Một biến mỗi lần
   - Không sửa nhiều thứ cùng lúc

3. **Kiểm chứng trước khi tiếp tục**
   - Có hiệu quả không? Có → sang Giai đoạn 4
   - Không hiệu quả? Nêu giả thuyết MỚI
   - KHÔNG chồng thêm sửa đổi lên trên

4. **Khi chưa biết**
   - Nói "Tôi chưa hiểu X"
   - Không giả vờ biết
   - Hỏi người dùng hoặc tra cứu thêm

### Giai đoạn 4: Triển khai

**Sửa nguyên nhân gốc, không sửa triệu chứng:**

1. **Viết test tái hiện lỗi trước**
   - Tái hiện đơn giản nhất có thể
   - Dùng `pytest` (thư mục `poc/sysmon-collector/`) hoặc `unittest` (thư mục `tests/`), theo đúng module đang lỗi
   - PHẢI có test này trước khi sửa

2. **Áp dụng MỘT bản sửa**
   - Nhắm vào nguyên nhân gốc đã xác định
   - MỘT thay đổi mỗi lần
   - Không "tiện thể" cải tiến thêm, không refactor kèm theo
   - Không sửa nhiều module nếu không thực sự cần (`CLAUDE.md` mục 8.8)

3. **Kiểm chứng bản sửa**
   - Test vừa viết đã pass chưa?
   - Có test nào khác bị hỏng không? Chạy lại toàn bộ bộ test liên quan
   - Triệu chứng ban đầu đã biến mất chưa?
   - Dùng skill `verification-before-completion` trước khi khẳng định thành công

4. **Nếu bản sửa không có tác dụng**
   - DỪNG LẠI
   - Đếm: đã thử bao nhiêu bản sửa?
   - Nếu dưới 3: quay lại Giai đoạn 1 và phân tích lại với thông tin mới
   - **Nếu từ 3 trở lên: DỪNG và đặt câu hỏi về kiến trúc (bước 5 dưới đây)**
   - KHÔNG thử bản sửa thứ tư khi chưa thảo luận về kiến trúc

5. **Sau 3 lần sửa thất bại: đặt câu hỏi về kiến trúc**

   **Dấu hiệu của vấn đề kiến trúc:**
   - Mỗi bản sửa làm lộ ra trạng thái dùng chung, phụ thuộc hoặc vấn đề mới ở chỗ khác
   - Việc sửa đòi hỏi refactor lớn
   - Mỗi bản sửa tạo triệu chứng mới ở nơi khác

   **Hãy tự hỏi các câu hỏi nền tảng:**
   - Mẫu thiết kế này có đúng về bản chất không?
   - Có đang tiếp tục chỉ vì quán tính không?
   - Nên tái cấu trúc kiến trúc thay vì tiếp tục sửa triệu chứng?

   **Trao đổi với người dùng trước khi thử thêm bản sửa.** Đây KHÔNG phải là một giả thuyết sai, mà là kiến trúc sai. Với DACN, mọi thay đổi ảnh hưởng đến kiến trúc hoặc data contract cần được người dùng phê duyệt (`CLAUDE.md` mục 8.3, 8.13).

## Dấu hiệu cảnh báo: DỪNG và quay lại Giai đoạn 1

Nếu bạn nhận thấy mình đang nghĩ:
- "Sửa nhanh tạm thời, điều tra sau"
- "Thử đổi X xem có được không"
- "Thêm nhiều thay đổi rồi chạy test"
- "Bỏ qua test, tôi tự kiểm tra thủ công"
- "Chắc là X, để sửa cái đó"
- "Chưa hiểu hết nhưng có thể được"
- "Mẫu nói X nhưng tôi sẽ điều chỉnh khác"
- "Đây là các vấn đề chính: [liệt kê bản sửa mà chưa điều tra]"
- Đề xuất giải pháp trước khi truy vết luồng dữ liệu
- **"Thử thêm một lần nữa" (khi đã thử từ 2 lần trở lên)**
- **Mỗi bản sửa làm lộ ra vấn đề mới ở chỗ khác**

**TẤT CẢ những điều trên nghĩa là: DỪNG. Quay lại Giai đoạn 1.**

**Nếu 3 bản sửa đã thất bại:** đặt câu hỏi về kiến trúc (xem Giai đoạn 4, bước 5).

## Dấu hiệu người dùng nhắc bạn đang làm sai

- "Có phải không xảy ra à?" → bạn đã giả định mà chưa kiểm chứng
- "Làm vậy thì có cho thấy được...?" → bạn nên thu thập bằng chứng trước
- "Đừng đoán nữa" → bạn đang đề xuất sửa khi chưa hiểu
- "Phân tích kỹ hơn" → hãy xét nền tảng, không chỉ triệu chứng
- "Có vẻ bị kẹt rồi?" → cách tiếp cận hiện tại không hiệu quả

**Khi thấy những dấu hiệu này:** DỪNG. Quay lại Giai đoạn 1.

## Các lý do thường gặp

| Lý do | Thực tế |
|-------|---------|
| "Lỗi đơn giản, không cần quy trình" | Lỗi đơn giản vẫn có nguyên nhân gốc. Quy trình nhanh với lỗi đơn giản. |
| "Khẩn cấp, không có thời gian cho quy trình" | Gỡ lỗi có hệ thống NHANH HƠN việc đoán và thử. |
| "Thử cái này trước, điều tra sau" | Bản sửa đầu tiên tạo ra khuôn mẫu. Làm đúng ngay từ đầu. |
| "Sẽ viết test sau khi xác nhận bản sửa" | Bản sửa chưa kiểm thử thường không bền. Test trước mới chứng minh được. |
| "Sửa nhiều thứ cùng lúc cho nhanh" | Không biết cái nào có tác dụng. Dễ gây lỗi mới. |
| "Tài liệu dài quá, tôi sẽ tự điều chỉnh" | Hiểu một phần đảm bảo sẽ có lỗi. Đọc kỹ toàn bộ. |
| "Tôi thấy vấn đề rồi, để tôi sửa" | Thấy triệu chứng ≠ hiểu nguyên nhân gốc. |
| "Thử thêm một lần nữa" (sau 2 lần thất bại) | 3 lần thất bại = vấn đề kiến trúc. Đặt câu hỏi về mẫu thiết kế, đừng sửa thêm. |

## Tóm tắt nhanh

| Giai đoạn | Hoạt động chính | Tiêu chí hoàn thành |
|-----------|----------------|---------------------|
| **1. Nguyên nhân gốc** | Đọc lỗi, tái hiện, kiểm tra thay đổi, thu thập bằng chứng | Hiểu CÁI GÌ và TẠI SAO |
| **2. Mẫu** | Tìm ví dụ đang hoạt động, so sánh | Xác định được khác biệt |
| **3. Giả thuyết** | Nêu giả thuyết, kiểm thử tối thiểu | Xác nhận hoặc có giả thuyết mới |
| **4. Triển khai** | Viết test, sửa, kiểm chứng | Lỗi được giải quyết, test pass |

## Áp dụng cho DACN

1. **Không sửa mã nguồn khi chỉ đang điều tra.** Dùng script tạm trong scratchpad hoặc đọc code. Chỉ sửa khi đã có nguyên nhân gốc và test tái hiện.
2. **Không dùng git để hoàn tác.** Repository có thay đổi chưa commit. Không dùng `git checkout`, `git reset`, `git stash`, `git clean` để khôi phục file. Muốn so sánh với trạng thái cũ, dùng `git diff` hoặc `git show <commit>:<đường dẫn>` (chỉ đọc).
3. **Phân biệt lỗi đã biết.** `CLAUDE.md` mục 3.1 ghi hai test đang fail. Trước khi kết luận chúng vẫn còn hoặc đã hết, phải chạy lại và ghi nhận kết quả.
4. **Lỗi môi trường.** Nếu thiếu dependency (`pytest`, `jsonschema`, `duckdb`), cài đặt theo `CLAUDE.md` mục 4 và ghi rõ đã cài. Không coi lỗi thiếu thư viện là lỗi logic của code.
5. **Live mode Windows** (`--mode live`, `pywin32`) chưa có môi trường kiểm chứng. Lỗi xảy ra ở live mode phải được điều tra bằng bằng chứng từ người dùng hoặc từ log trên Windows; không suy đoán.
6. **Báo cáo.** Ghi rõ giả thuyết, bằng chứng, bản sửa (nếu có), lệnh test đã chạy và kết quả. Không khẳng định lỗi đã sửa khi chưa chạy lại đúng triệu chứng ban đầu.
