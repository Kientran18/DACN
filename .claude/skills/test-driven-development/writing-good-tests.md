# Viết test tốt

**Đọc khi:** viết hoặc sửa test, thêm mock, hoặc thêm hàm helper/cleanup cho test.

Nguồn gốc và chỉnh sửa: xem `SOURCE.md` (bản gốc `writing-good-tests.md` của obra/superpowers, MIT, đã dịch và rút gọn; ví dụ TypeScript thay bằng Python).

## Tổng quan

Một test tồn tại để bắt một lỗi cụ thể. Hai nguyên tắc:

```
1. Mỗi test gọi tên được lỗi mà nó bắt
2. Mỗi test chạy code thật
```

TDD nghiêm ngặt tự tạo ra cả hai: test viết trước và đã thấy thất bại trên code thật thì đã chứng minh nó có thể thất bại; chỉ dùng mock khi dependency thật chậm hoặc nằm ngoài hệ thống.

## Nguyên tắc 1: Gọi tên lỗi

Trước khi viết thân test, trả lời: **thay đổi nào của code production sẽ làm test này thất bại, và thay đổi đó là lỗi hay là một quyết định?** Test đáng tồn tại khi bắt được: nhánh sai, thiếu tác dụng phụ, sai tham số, trường hợp biên, hoặc vi phạm hợp đồng.

**Kỳ vọng phải suy ra độc lập.** Dùng giá trị literal và fixture đã kiểm tra bằng tay; test dạng bảng với giá trị `want` literal là lựa chọn ưu tiên. Kỳ vọng được tính bởi chính code đang test sẽ pass bất kể code làm gì.

```python
# SAI: cùng một hàm tính cả hai vế, luôn đúng
expected = to_silver_input(rec)
assert to_silver_input(rec) == expected

# ĐÚNG: giá trị literal tự suy ra (ví dụ từ docs/architecture/w5/contracts/examples/)
assert to_silver_input(rec)["event_type"] == "PROCESS_START"
```

**Không viết "change detector".** Nếu chỉ một quyết định có chủ ý mới làm test fail (giá trị hằng, câu chữ thông báo, cấu trúc private) thì test sẽ kêu khi thiết kế lại và ngủ yên khi có lỗi. Kiểm thử hành vi phụ thuộc vào quyết định đó.

**Hành vi, không phải văn bản.** Assert rằng một script hay config chứa đúng một dòng chỉ chứng minh nguồn là nguồn. Chạy với input được kiểm soát và assert đầu ra, tác dụng phụ hoặc exit code.

**Code của bạn, không phải framework.** Kiểm thử hợp đồng mà code của bạn đưa ra tại ranh giới (payload, câu query, bản ghi sinh ra). Hành vi nội tại của thư viện (ví dụ `jsonschema`, `duckdb`) là việc của người bảo trì chúng; nếu hành vi thư viện làm bạn bất ngờ, viết đúng một characterization test nêu rõ giả định.

### Cổng kiểm tra

```
TRƯỚC khi viết thân test:
  Gọi tên thay đổi production làm test này thất bại.

  Không gọi được tên        → thiết kế lại quanh một hành vi quan sát được
  "Văn bản nguồn thay đổi"  → chạy artifact và assert tác dụng của nó
  Chỉ quyết định có chủ ý   → đây là change detector; kiểm thử hành vi
                              phụ thuộc vào quyết định

  Xác nhận giá trị kỳ vọng được suy ra không dùng code đang test.
```

## Nguyên tắc 2: Chạy code thật

**Mock không được phép có assertion.** Assertion trên mock pass khi mock có mặt và fail khi vắng mặt; nó không nói gì về thành phần thật. Assert hành vi thành phần thật.

**Mock ở đúng tầng.** Tìm hiểu mọi tác dụng phụ của hàm thật trước khi thay nó; mock phần chậm hoặc ở ngoài, giữ nguyên phần test phụ thuộc vào. Không chắc thì chạy test với cài đặt thật trước.

**Làm test double cụ thể.** Khi tham số, số lần gọi hay thứ tự là một phần hợp đồng thì assert chúng. Mỗi nhánh (thành công, lỗi, dữ liệu hỏng) có fixture riêng để nhánh sai không thể thỏa kỳ vọng.

**Phản chiếu dữ liệu thật đầy đủ.** Fixture phải có đủ cấu trúc như thực tế (ví dụ đủ `System` và `EventData` của một Sysmon event), không chỉ các field test đọc. Fixture thiếu field làm test pass trong khi tích hợp hỏng. Với DACN, ưu tiên fixture trong `references/samples/` hoặc `docs/architecture/w5/contracts/examples/`; không tự bịa field Sysmon (Zero Data Fabrication) và không sao chép tên máy/người dùng thật sang file mới.

**Lớp production chỉ chứa phương thức production.** Cleanup chỉ test cần thì đặt trong tiện ích test.

**Ưu tiên thành phần thật hơn mock phức tạp.** Khi phần setup mock lớn hơn logic test, chuyển sang test tích hợp với thành phần thật.

### Cổng kiểm tra

```
TRƯỚC khi thêm mock hoặc helper cho test:
  Liệt kê tác dụng phụ của hàm thật; giữ thật những gì test phụ thuộc.
  Mock phản chiếu đầy đủ cấu trúc thật.
  Phương thức chỉ test gọi thì để trong tiện ích test.
  Sắp assert trên chính mock? Bỏ mock hoặc xóa assertion đó.
```

## Kiểm tra đột biến (mutation check)

Trước khi kết thúc, tự hình dung các đột biến thực tế trong code production; mỗi đột biến cần ít nhất một test fail:

- Sai hằng số hoặc tham số
- Sai nhánh xử lý
- Thiếu thay đổi trạng thái hoặc tác dụng phụ
- Trả về rỗng hoặc mặc định
- Thiếu kiểm tra với giá trị 0, rỗng, null, không hợp lệ hoặc dữ liệu hỏng

Đột biến mà không test nào bắt được nghĩa là hành vi chưa được bảo vệ, hoặc test đang tautology. Đây là kiểm tra tư duy; **không** sửa code thật để thử đột biến trong working tree của người dùng.

## Bảng tra nhanh

| Khi bạn... | Hãy |
|---|---|
| Viết bất kỳ test nào | Gọi tên lỗi nó bắt |
| Dựng giá trị kỳ vọng | Suy ra bằng tay, không dùng code đang test |
| Test script hoặc tài liệu | Chạy nó; không grep văn bản |
| Muốn assert trên phần tử mock | Test thành phần thật, hoặc bỏ mock |
| Sắp mock một hàm | Học tác dụng phụ của nó; mock tầng chậm/ngoài |
| Thấy setup mock phình to | Chuyển sang test tích hợp với thành phần thật |

## Dấu hiệu cảnh báo

- Setup và assertion dùng cùng một đối tượng nên bảo đảm bằng nhau
- Test chỉ có thể fail do crash
- Test fail mỗi khi thay đổi có chủ ý, không bao giờ fail khi hỏng ngoài ý muốn
- Kỳ vọng bị giấu sau vòng lặp, builder hoặc helper
- Test grep văn bản nguồn
- Test tồn tại chỉ để tăng coverage mà không kiểm tra kết quả nào
- Assertion trên đối tượng mock
- Phương thức chỉ được gọi từ file test
- Phần setup mock chiếm hơn nửa test
