---
name: test-driven-development
description: Dùng khi cài đặt tính năng mới hoặc sửa lỗi trong DACN, trước khi viết code cài đặt. Phát triển theo Red → Green → Refactor với pytest/unittest, viết regression test cho lỗi đã được xác minh. Không xóa implementation hiện có và không sửa code ngoài phạm vi issue.
---

# Phát triển hướng kiểm thử (TDD)

## Tổng quan

Viết test trước. Xem nó thất bại. Viết code tối thiểu để nó pass.

**Nguyên tắc cốt lõi:** Nếu bạn chưa thấy test thất bại, bạn không biết test có kiểm tra đúng thứ cần kiểm tra hay không.

## Khi nào dùng

**Luôn dùng cho code mới hoặc thay đổi trong phạm vi issue:**
- Tính năng mới
- Sửa lỗi (viết regression test)
- Refactor có test bảo vệ
- Thay đổi hành vi

**Ngoại lệ (hỏi người dùng trước):** prototype bỏ đi, code sinh tự động, file cấu hình.

## Quy tắc chính

```
CODE MỚI HOẶC HÀNH VI MỚI PHẢI CÓ TEST THẤT BẠI TRƯỚC
```

Viết code cài đặt mới trước khi có test? Dừng lại, viết test trước, chạy test để thấy nó thất bại, rồi mới viết lại phần cài đặt tối thiểu cho hành vi đó.

### Điều chỉnh cho DACN: code đã có sẵn

Bản gốc yêu cầu xóa code viết trước test. **DACN không áp dụng điều đó**:

- **Không tự ý xóa, ghi đè hay hoàn tác implementation hiện có** (collector, adapter, validator, schema, v.v.) chỉ vì nó chưa được phát triển theo TDD. Các PoC hiện tại đã có trong repository và nhiều phần được các nhóm khác dựa vào.
- Với code đã có mà chưa có test: viết **characterization test** mô tả hành vi hiện tại (chạy, phải pass vì ghi lại hành vi thật), rồi mới thêm test thất bại cho hành vi mới/sửa lỗi.
- Nếu chính bạn lỡ viết code mới trước test trong phiên này: viết test cho nó ngay, chứng minh test có thể thất bại bằng cách tạm đổi hành vi một cách có kiểm soát **trên bản sao hoặc bằng mutation tư duy**, không dùng lệnh xóa hay reset. Cần bỏ code của chính mình thì hỏi người dùng trước.
- Không sửa code ngoài phạm vi issue. Phát hiện lỗi khác thì báo cáo, không tự sửa (`CLAUDE.md` mục 8.8).
- Không sửa test để cho test pass. Test fail là tín hiệu về code hoặc về kỳ vọng; tìm nguyên nhân gốc (xem skill `systematic-debugging`).

## Red → Green → Refactor

### RED: viết test thất bại

Viết một test nhỏ cho một hành vi.

Tốt (pytest, giá trị tự suy ra bằng tay, không dùng chính code đang test để tính kỳ vọng):

```python
def test_missing_time_created_reports_c002():
    xml = '<Event xmlns="http://schemas.microsoft.com/win/2004/08/events/event"><System><EventID>1</EventID></System></Event>'
    with pytest.raises(ValueError, match="C-002"):
        bc.build_bronze_record(xml, mode="file")
```

Yêu cầu:
- Một hành vi; tên mô tả hành vi.
- Dùng code thật, hạn chế mock (xem `writing-good-tests.md`).
- Với DACN: dùng fixture synthetic hoặc mẫu trong `references/samples/` và `docs/architecture/w5/contracts/examples/`; không sao chép tên máy hay tên người dùng thật vào test hoặc tài liệu mới (`CLAUDE.md` mục 7).

### Xác nhận RED: xem nó thất bại

**Bắt buộc, không bỏ qua.** Chạy từ thư mục gốc repository (xem `CLAUDE.md` mục 5):

```bash
python -m pytest -q poc/sysmon-collector/test_bronze_contract.py::test_collector_errors_use_reason_codes
```

Với test kiểu unittest trong `tests/`:

```bash
python -m unittest tests.test_validator_poc_w5.TestDataPipelineW05.test_01_deterministic_uuidv5_matches_w3_real_samples
```

Xác nhận:
- Test **thất bại** (không phải lỗi import/cú pháp).
- Thông báo lỗi đúng như dự kiến.
- Thất bại vì tính năng thiếu, không phải do gõ nhầm.

Test pass ngay? Bạn đang kiểm thử hành vi đã có; sửa test. Test báo lỗi (error)? Sửa lỗi rồi chạy lại cho tới khi nó thất bại đúng lý do.

### GREEN: code tối thiểu

Viết code đơn giản nhất để test pass. Không thêm tính năng, không refactor code khác, không "cải thiện" vượt quá test. Không đổi schema, field mapping, event identity hay UUID để cho test pass; đó là thay đổi data contract, cần phê duyệt liên nhóm.

### Xác nhận GREEN: xem nó pass

Xác nhận test pass, các test khác vẫn pass, đầu ra sạch. Test thất bại thì sửa code, không sửa test.

"Các test khác" nghĩa là **toàn bộ bộ test của dự án**, không chỉ file bạn viết. Trước khi coi thay đổi xong, chạy cả hai:

```bash
python -m pytest -q poc/sysmon-collector
python -m pytest -q tests/
```

Báo cáo mọi test fail theo tên, kể cả test không do bạn gây ra. Hai lỗi đã ghi trong `CLAUDE.md` mục 3.1 phải được chạy lại để xác minh, không mặc định còn tồn tại, và không được che giấu nếu còn.

### REFACTOR: dọn dẹp

Chỉ sau khi green: bỏ trùng lặp, đặt tên tốt hơn, tách hàm. Giữ test xanh, không thêm hành vi. Chú ý logic bị nhân bản có chủ ý giữa collector và `validator_poc.py` (`CLAUDE.md` mục 7): không gộp hai bản khi chưa có quyết định.

### Lặp lại

Test thất bại tiếp theo cho hành vi tiếp theo.

## Regression test cho lỗi đã xác minh

1. Tái hiện lỗi và xác minh nó có thật bằng lệnh chạy (không dựa vào ghi chú cũ).
2. Viết test thất bại nhỏ nhất mô tả hành vi đúng.
3. Xem nó thất bại đúng lý do.
4. Sửa tối thiểu trong phạm vi issue.
5. Xem test pass, rồi chạy toàn bộ bộ test.

Ví dụ lỗi đã ghi nhận (cần xác minh lại trước khi dùng): `_parse_event_element` thiếu `TimeCreated` nhưng thông báo lỗi không mang mã `C-002`. Việc nên sửa ở collector hay nới kỳ vọng ở test là quyết định liên quan data contract; nêu rõ và hỏi nếu chưa rõ.

## Test tốt

| Tiêu chí | Tốt | Xấu |
|---|---|---|
| **Nhỏ** | Một hành vi. Tên có "và"? Tách ra. | `test_validates_key_and_type_and_time` |
| **Rõ** | Tên mô tả hành vi | `test1` |
| **Thể hiện ý định** | Cho thấy API mong muốn | Che giấu code cần làm gì |

Khi viết hoặc sửa bất kỳ test nào, đọc [writing-good-tests.md](writing-good-tests.md): đặt tên "thay đổi nào của code sẽ làm test này fail", kỳ vọng suy ra độc lập, không assert trên mock, không đặt code chỉ-dành-cho-test vào lớp production.

## Cái cớ thường gặp

| Cái cớ | Thực tế |
|---|---|
| "Quá đơn giản để test" | Code đơn giản vẫn hỏng. Test mất 30 giây. |
| "Tôi sẽ test sau" | Test viết sau pass ngay, không chứng minh được gì. |
| "Đã test tay rồi" | Test tay không để lại bản ghi và không chạy lại được. |
| "Code cũ chưa có test" | Thêm characterization test cho phần bạn chạm vào, rồi tiếp tục. |
| "Khó test = thiết kế chưa rõ" | Lắng nghe test: khó test là khó dùng. |
| "Phải mock mọi thứ" | Code đang gắn quá chặt; xem xét dependency injection hoặc test tích hợp với thành phần thật. |

## Dấu hiệu cần dừng lại

- Có code cài đặt mới nhưng chưa có test
- Test pass ngay lần chạy đầu
- Không giải thích được vì sao test thất bại
- Sửa test cho khớp code thay vì ngược lại
- Đổi schema/mapping/UUID chỉ để test pass
- Đang định xóa hoặc ghi đè code hiện có để "làm lại cho đúng TDD"

Gặp một trong các dấu hiệu này: dừng, quay lại bước RED, và hỏi người dùng nếu cần xóa hay thay đổi thứ đã tồn tại.

## Danh sách kiểm tra trước khi hoàn thành

- [ ] Mỗi hàm/hành vi mới có test
- [ ] Đã thấy từng test thất bại trước khi cài đặt
- [ ] Mỗi test thất bại đúng lý do
- [ ] Code tối thiểu để test pass
- [ ] Toàn bộ `python -m pytest -q poc/sysmon-collector` và `python -m pytest -q tests/` đã chạy, kết quả (kèm thời điểm) được báo cáo
- [ ] Đầu ra sạch (không lỗi, không cảnh báo mới)
- [ ] Test dùng code thật, mock chỉ khi không tránh được
- [ ] Trường hợp biên và lỗi đã được kiểm thử
- [ ] Không thay đổi file ngoài phạm vi issue

Không đánh dấu hết được thì chưa xong. Dùng thêm skill `verification-before-completion` trước khi khẳng định hoàn thành.

## Khi bị kẹt

| Vấn đề | Cách giải |
|---|---|
| Không biết test thế nào | Viết API mong muốn, viết assertion trước, hỏi người dùng |
| Test quá phức tạp | Thiết kế quá phức tạp; đơn giản hóa interface |
| Setup quá lớn | Tách helper trong file test; vẫn phức tạp thì đơn giản hóa thiết kế |

## Phạm vi an toàn

Skill này không cho phép: commit/push/PR (chỉ khi người dùng yêu cầu), xóa hay reset file hoặc lịch sử git, cài đặt gói hay tải mã từ Internet, chạy live mode trên máy thật để "lấy dữ liệu test".
