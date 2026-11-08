---
name: writing-plans
description: Lập kế hoạch triển khai. Tự dùng khi có issue, spec hoặc yêu cầu nhiều bước và cần kế hoạch trước khi sửa code - chia task nhỏ, liệt kê file cần sửa, dependency, test case, tiêu chí nghiệm thu. Chỉ lập kế hoạch, không thực thi hay commit. Không dùng cho kiến trúc tổng thể (dacn-edr-architecture) hoặc chạy trọn quy trình issue (dacn-issue-workflow).
---

# Lập kế hoạch triển khai

## Tổng quan

Viết kế hoạch triển khai cho một kỹ sư chưa từng đọc codebase này hay spec này. Họ viết code đúng chuẩn của ngôn ngữ khi đã biết chính xác interface và test cần có. Điều họ không thể tự biết là **những gì bạn đã quyết định**: file nào, tên và signature nào, giá trị nào lấy từ spec, test nào chứng minh từng task. Hãy ghi lại đúng những quyết định đó, dưới dạng các task nhỏ. DRY. YAGNI. Ưu tiên test trước (xem skill `test-driven-development`).

**Kế hoạch chỉ là tài liệu.** Skill này KHÔNG thực thi kế hoạch, KHÔNG sửa code, KHÔNG commit, KHÔNG push, KHÔNG tạo branch. Việc thực thi chỉ bắt đầu khi người dùng xem xét kế hoạch và yêu cầu rõ ràng.

**Nơi đặt kế hoạch:** mặc định trình bày ngay trong phản hồi (tiếng Việt). Chỉ ghi ra file khi người dùng yêu cầu, tại vị trí họ chỉ định. Không tự tạo thư mục `docs/superpowers/` hay bất kỳ thư mục mới nào.

## Trước khi lập kế hoạch (bắt buộc với DACN)

Theo `CLAUDE.md` mục 8 và 9, đọc trước khi viết kế hoạch:

1. Issue và acceptance criteria (đọc bằng công cụ GitHub của session, không đoán nội dung issue).
2. `README.md`, ADR liên quan trong `docs/decisions/`, data contract và schema liên quan, `docs/scope/phase-1-scope.md`.
3. Mã nguồn các module bị ảnh hưởng, và chạy lại test liên quan để biết trạng thái hiện tại (không mặc định lỗi cũ trong `CLAUDE.md` mục 3.1 còn tồn tại).

Trong kế hoạch phải tách riêng **CURRENT STATE** (đã có mã và bằng chứng) và **TARGET** (kế hoạch, chưa triển khai). Không mô tả thành phần TARGET như thể đã hoàn thành. Không coi ADR trạng thái PROPOSED là quyết định đã chốt.

## Kiểm tra phạm vi

Nếu yêu cầu bao gồm nhiều hệ thống con độc lập, đề xuất tách thành nhiều kế hoạch riêng, mỗi kế hoạch tạo ra phần mềm chạy và kiểm thử được độc lập. Nếu thay đổi chạm data contract, event identity, UUID, raw preservation hoặc quy tắc chuẩn hóa, ghi rõ đó là thay đổi cần phê duyệt liên nhóm (Software, Data, Cybersecurity) và dừng ở đề xuất, vì `CLAUDE.md` cấm tự ý thay đổi các phần này.

## Cấu trúc file

Trước khi định nghĩa task, liệt kê file sẽ tạo hoặc sửa và trách nhiệm của từng file.

- Mỗi file một trách nhiệm rõ ràng; file thay đổi cùng nhau thì ở cùng nhau.
- Với codebase hiện có, theo mẫu đang dùng. Các file Python của DACN không phải package và import bằng tên module trần (`CLAUDE.md` mục 5): không đề xuất tái cấu trúc thành package nếu issue không yêu cầu.
- Không đưa vào kế hoạch việc sửa thành phần ngoài phạm vi issue.

## Kích thước task

Một task là đơn vị nhỏ nhất có chu trình test riêng và đáng để người review chặn lại. Gộp phần cấu hình, scaffolding và tài liệu vào task cần chúng; chỉ tách khi người review có thể từ chối task này mà vẫn chấp nhận task kế bên. Mỗi task kết thúc bằng một sản phẩm kiểm thử được độc lập.

## Độ chi tiết của bước

Mỗi bước là một hành động có kết quả kiểm tra được:

- "Viết test thất bại" là một bước.
- "Chạy test để xác nhận nó thất bại" là một bước.
- "Cài đặt code tối thiểu để test pass" là một bước.
- "Chạy test và xác nhận pass" là một bước.
- "Chạy toàn bộ bộ test để kiểm tra regression" là một bước.

Bước commit **không** nằm trong kế hoạch mặc định. Chỉ thêm một dòng ghi chú cuối kế hoạch: "Commit/push/PR chỉ thực hiện khi người dùng yêu cầu", kèm gợi ý tên branch và commit message theo `docs/conventions/02-branch-convention.md` và `03-commit-convention.md`.

## Tiêu đề kế hoạch

Mọi kế hoạch bắt đầu bằng:

```markdown
# [Tên tính năng/issue] — Kế hoạch triển khai

**Issue:** [số issue và liên kết, nếu có]
**Mục tiêu:** [một câu]
**Cách tiếp cận:** [2–3 câu]
**Công nghệ:** [thư viện, công cụ liên quan; chỉ liệt kê cái đã có trong repository]
**Tài liệu gốc:** [đường dẫn spec/ADR/contract mà kế hoạch dựa vào]

## Hiện trạng (CURRENT STATE) và phần thuộc TARGET
[ngắn gọn, có dẫn chứng file/test]

## Ràng buộc toàn cục
[Yêu cầu chung lấy nguyên văn từ spec/CLAUDE.md, mỗi dòng một ý. Mọi task đều chịu các ràng buộc này.]

## Tiêu chí nghiệm thu
[Danh sách kiểm tra được, đối chiếu từng acceptance criteria của issue]

## Rủi ro và điểm cần xem xét
[Tối đa 5 dòng: input hoặc tình huống mà spec ngầm yêu cầu nhưng chưa task nào kiểm thử; dòng nào có test thì gắn test đó vào task sở hữu code.]

## Ảnh hưởng liên nhóm
[Software / Data / Cybersecurity: nhóm nào bị ảnh hưởng và vì sao; ghi "không có" nếu không]
```

## Cấu trúc task

````markdown
### Task N: [Tên thành phần]

**File:**
- Tạo: `đường/dẫn/chính/xác/file.py`
- Sửa: `đường/dẫn/file_hiện_có.py:123-145`
- Test: `tests/...` hoặc `poc/sysmon-collector/test_....py`

**Interface:**
- Dùng từ task trước: [signature chính xác]
- Cung cấp cho task sau: [tên hàm, kiểu tham số, kiểu trả về]

- [ ] **Bước 1: Viết test thất bại** — tên test và assertion dưới dạng code, kèm giá trị cụ thể từ spec
- [ ] **Bước 2: Chạy test, xác nhận thất bại**
  Chạy: `python -m pytest -q <đường dẫn test>::<tên test>`
  Kỳ vọng: FAIL với lý do cụ thể
- [ ] **Bước 3: Cài đặt `ten_ham(tham_so: Kieu) -> KieuTraVe` trong `đường/dẫn/file.py`**
  Một dòng về cách làm nếu signature và test chưa quyết định hết.
- [ ] **Bước 4: Chạy test, xác nhận pass**
- [ ] **Bước 5: Chạy toàn bộ bộ test liên quan để kiểm tra regression**
  Chạy: `python -m pytest -q poc/sysmon-collector` và `python -m pytest -q tests/` (từ thư mục gốc repository)
````

## Một bước chứa những gì

Một bước hoàn chỉnh khi người thực hiện chỉ có thể viết đúng một cách hợp lý từ nó. Đó là yêu cầu duy nhất: rõ ràng, không cần đầy đủ.

- **Bước test:** tên test và assertion dưới dạng code, kèm giá trị chính xác từ spec.
- **Bước code:** signature chính xác (tên, tham số, kiểu trả về), file chứa nó, và các giá trị cố định theo spec. Phần thân hàm chỉ xuất hiện khi thuật toán không thể suy ra từ signature và test.
- **Bước kiểm chứng:** lệnh chạy và kết quả được coi là đạt.
- **Tham chiếu task khác:** dùng khối Interface của task đó, không lặp lại code.

Những dòng không quyết định gì ("TBD", "xử lý các trường hợp biên", "thêm validation phù hợp", "viết test cho phần trên") là lỗi ngược lại. Kế hoạch dài hơn chính đoạn code mà nó mô tả thì đã viết sẵn code thay vì lập kế hoạch.

## Tự rà soát

Sau khi viết xong, đối chiếu lại với issue/spec bằng mắt nhìn mới (tự kiểm tra, không dispatch subagent):

1. **Độ phủ spec:** mỗi yêu cầu và mỗi acceptance criteria có task tương ứng chưa? Ghi các khoảng trống.
2. **Quét bước:** mỗi bước cho phép đúng một cách viết hợp lý; không bước nào chứa thân hàm mà signature và test đã xác định.
3. **Nhất quán kiểu:** tên hàm, tham số, thuộc tính ở task sau khớp với task trước.
4. **Rủi ro:** mỗi tình huống đã nêu có task kiểm thử nó.
5. **Tỷ lệ:** kế hoạch dài gấp nhiều lần spec là bản chép lại chương trình, không phải kế hoạch.
6. **Phạm vi và an toàn:** không có bước nào chạm data contract/schema/event identity khi chưa được phê duyệt, không có bước xóa, reset, ghi đè dữ liệu, và không có bước tải rồi chạy mã từ Internet.

Tìm thấy vấn đề thì sửa ngay trong kế hoạch.

## Bàn giao

Sau khi hoàn tất, trình bày kế hoạch cho người dùng và hỏi: "Kế hoạch trên đã đúng ý chưa? Tôi chỉ bắt đầu triển khai khi bạn yêu cầu." Chờ người dùng xác nhận trước khi sửa bất kỳ file nào. Không tự chọn phương thức thực thi, không dispatch subagent để thực thi, không commit, không push, không tạo Pull Request.
