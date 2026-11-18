# Bàn giao phiên làm việc: mô hình ML cho DACN (2026-11-18)

Mục đích: để một phiên Claude Code mới (hoặc người khác) tiếp tục ngay, không phải đọc lại hội thoại cũ.
Mọi kết luận dưới đây có nguồn là file trong repo hoặc số đo đã ghi; điều chưa kiểm chứng được đánh dấu rõ.

## 0. Đoạn mở đầu để dán vào phiên mới

> Đọc `CLAUDE.md`, rồi `docs/implementation/handover/ML_SESSION_HANDOVER.md` và `docs/implementation/ML_EMBER2024_MODELS.md`. Trả lời bằng tiếng Việt. Nhánh làm việc: `claude_implement`. Không merge vào `main`, không tạo PR, không sửa contract/schema v1.1/ADR/README/kế hoạch 12 tuần khi chưa được tôi duyệt. Không bắt đầu pha mới nếu tôi chưa nói "bắt đầu". Điểm ML không bao giờ kích hoạt response. Không bịa số liệu: số EMBER2024 không phải chất lượng phát hiện của DACN.

## 1. Dự án và quy tắc (tóm tắt, nguồn: CLAUDE.md)

- DACN: EPP/EDR cho Windows 10/11, local-first, một endpoint. Pipeline: agent → Bronze (JSONL niêm phong) → Silver (DuckDB) → detection → alert → response/API/dashboard.
- Ràng buộc người dùng đã nêu: Windows 10 VM duy nhất; response mặc định `dry-run`; không tắt Windows Defender; không dùng mã độc thật; dữ liệu mẫu phải gắn nhãn; Zero Data Fabrication; Claude không tự chạy hành động response thật hay script PowerShell lab; DDL v1.2 chỉ là đề xuất.
- Mọi phản hồi bằng tiếng Việt; giữ nguyên thuật ngữ, tên file, lệnh, code.
- Commit/push chỉ khi người dùng yêu cầu rõ. Conventional Commits, scope gợi ý `ai-scoring` cho phần ML.

## 2. Trạng thái repo

- Nhánh: `claude_implement`. Commit mới nhất đã push: `8d60e8f` `feat(ai-scoring): thêm mô hình PE tĩnh EMBER2024 (Dot_Net, Win64) ở trạng thái nháp`. Trước đó `685b3c7` (mức phần mềm).
- Commit `6f4c7e2` thêm `CLAUDE.md` (mục 2, 3.1, kết quả test) và file này; `8051f37` thêm `scripts/ml/kaggle/`; `d6ff78a` thêm bộ chấm điểm tĩnh nháp, `requirements-ml.txt` và cập nhật `CLAUDE.md`, `ML_EMBER2024_MODELS.md`. Kiểm tra bằng `git log --oneline -5`.
- Test (Linux, 2026-11-18, sau audit): `python -m pytest -q` → 260 pass, 0 fail (có `lightgbm` 4.7.0; gồm 12 test bộ chấm điểm và 6 test mô hình). Không có `lightgbm`: 254 pass, 1 skipped (`tests/detection/test_ember2024_models.py`); cả hai đều đã đo. Môi trường phiên mới có thể thiếu `duckdb`/`fastapi`/`httpx`: chạy `pip install -r requirements.txt` trước, nếu không pytest báo 15 lỗi collection (không phải lỗi mã).
- Nghiệm thu AT (2026-11-09, chưa chạy lại): 28 PASS, 1 PARTIAL, 0 FAIL, 14 NOT RUN (mức Windows). Mọi thứ trên Windows thật chưa được chạy.

## 3. Phần ML đã làm

Hướng đã chọn: **Hướng B** = bộ phân loại PE tĩnh huấn luyện trên EMBER2024 (Hugging Face `joyce8/EMBER2024`, apache-2.0; đặc trưng `thrember` feature version 3, 2568 đặc trưng; train = 52 tuần đầu, test = 12 tuần cuối; mỗi loại tệp một mô hình LightGBM).

| | Dot_Net | Win64 |
|---|---|---|
| Dòng train | 468.000 | 936.000 |
| AUC test (tách theo thời gian) | 0,9980 | 0,9989 |
| TPR @ FPR 1% | 95,9% | 98,4% |
| TPR @ FPR 0,1% | 82,9% | 93,0% |
| sha256 mô hình | `5ecd93c6…` | `5bc1fddf…` |

- Tập test cân bằng 50/50 nên precision/recall không đại diện cho môi trường thật. Ngưỡng chỉ đúng với EMBER2024.
- Vị trí: `models/ember2024/{dotnet,win64}/` (mô hình + `model_card.json` + báo cáo + cấu hình + `pip_freeze`). Chi tiết và cách nạp: `docs/implementation/ML_EMBER2024_MODELS.md`.
- Nạp qua `src/detection/ml/loader.py` cần `model_card.json` có `model_version`, `feature_schema_version` (= `thrember-v3-2568`), `artifact_file`, `artifact_sha256`, và `predictor_factory` do người dùng cấp (không pickle). Điểm phải nằm trong [0,1].
- Script train: `scripts/ml/train_ember2024.py` (`DACN_LOAI=Dot_Net|Win64`, dùng `lgb.Sequence` để giảm RAM). Không khẳng định giống từng byte lần chạy thật trên Kaggle.

## 4. Bài học khi huấn luyện trên Kaggle (đã đo hoặc quan sát)

- Kaggle chặn `git clone` từ `github.com` (mã thoát 128). HF và PyPI vào được. Cách xử lý: nhúng mã `thrember` dạng base64 trong notebook.
- Hai lỗi thư viện đã vá: `oscrypto` không nhận phiên bản OpenSSL 3.x hai chữ số (sửa regex ở cả `_libcrypto_ctypes.py` và `_libcrypto_cffi.py`; file nguồn viết `\\d` nên mẫu tìm phải khớp số dấu `\`); cần `signify==0.8.1` (bản mới làm hỏng `SignedPEFile`).
- Tập challenge không được tải nên `create_vectorized_features` báo `Did not find any .jsonl files` ở bước cuối: bỏ qua an toàn nếu 4 file `.dat` của train/test đã đủ.
- Số đo thật: Win64 tải 4,8 phút, vector hóa 37,1 phút (khoảng 643–783 mẫu/giây), train 23,4 phút, tổng 66,3 phút. Dot_Net train 9,7 phút. Đĩa trống khoảng 1 TB ở `/tmp`, RAM 31 GB, 4 CPU.
- **Win32 chưa train được.** Tập train có 3.120.000 dòng; vector hóa chạy đến 66% (2.046.094 dòng, 53 phút) thì `/tmp` chuyển sang chỉ-đọc (`OSError 30`). `/kaggle/working` vẫn ghi được. **Nguyên nhân chưa biết**; giả thuyết là file `X_train.dat` khoảng 32 GB ghi bằng `memmap` nhiều tiến trình, chưa kiểm chứng. Notebook bản mới giảm nguy cơ (lấy mẫu 1/4 train, 1/2 test, kiểm tra ghi được, chỉ thử lại khi bị kill) nhưng **chưa chạy thử trên Kaggle**. Nếu lỗi lặp lại: ghi `.dat` theo mảnh nhỏ không dùng `memmap`, hoặc thuê máy ảo theo giờ, hoặc dùng mô hình công bố sẵn `joyce8/EMBER2024-benchmark-models` (`EMBER2024_Win32.model`) làm mốc.
- `lightgbm 4.6.0` (Kaggle) và `4.7.0` (môi trường kiểm tra) nạp được file mô hình của nhau.

## 5. Chưa có / chưa được duyệt

- Bộ chấm điểm tĩnh: **đã có bản nháp** `src/detection/ml/static_scorer.py` (chạy theo yêu cầu; chỉ đọc tệp trong `allowed_dirs`, chọn mô hình theo header PE, nạp qua loader, lỗi ⇒ `INSUFFICIENT_TELEMETRY` kèm `reason`; kết quả nội bộ `StaticScoreResult`, chưa phải `DetectionResult`; `threshold` mặc định `None`). Mô tả: `ML_EMBER2024_MODELS.md` mục 5.1. **Chưa nối vào Detection Engine, chưa lưu kết quả.** Đường trích đặc trưng `thrember` thật **chưa được chạy** ở đâu (test dùng extractor/predictor giả); `thrember` không có trên PyPI (kiểm tra 2026-11-18). Chưa đo thời gian mỗi tệp/RAM; `max_bytes` 64 MiB là giá trị tạm; chưa có giới hạn thời gian trích đặc trưng; Win32 ⇒ `NO_MODEL_FOR_KIND`.
- Ngưỡng cho DACN phải đo trên tệp lành tính của VM; thời gian mỗi tệp và RAM trên VM 2 GB chưa đo. Chưa có phép đo ML nào trên Windows.
- `DetectionResult`, hợp đồng dữ liệu của điểm ML, phạm vi "static scoring" cần Cyber/Data duyệt. Tệp không đọc được ⇒ `INSUFFICIENT_TELEMETRY`.
- Đã quyết định: `lightgbm` và phụ thuộc ML nằm ở `requirements-ml.txt` (tùy chọn), **không** thêm vào `requirements.txt`. Cài `thrember` từ GitHub theo hướng dẫn EMBER2024 (chưa thử trên Windows; `oscrypto` từng lỗi với OpenSSL 3.x trên Kaggle).
- Win32 và các loại khác (APK, ELF, PDF) chưa huấn luyện.
- Hướng A (mô hình hành vi trên Silver/`gold_process_features`) chờ dữ liệu lành tính từ VM và hợp đồng đặc trưng ML-T01 từ nhóm Data (backlog ML-T01..T07 trong `docs/implementation/EDR_TASK_BACKLOG.md`).
- Phần việc ngoài ML người dùng phải tự làm trên Windows VM: xem `docs/implementation/EDR_INSTALL_GUIDE.md` và `docs/implementation/handover/USER_GUIDE.md`.

## 6. Những việc tiếp theo khả dĩ (chỉ làm khi người dùng chọn)

1. Commit `CLAUDE.md` và tài liệu bàn giao này (người dùng chưa yêu cầu).
2. Bộ chấm điểm tĩnh: cài `thrember` và chạy thử trên tệp lành tính của VM để đo thời gian/RAM và đặt ngưỡng (người dùng chạy trên Windows); xin Cyber/Data duyệt dạng `DetectionResult`, cách kích hoạt (theo sự kiện hay theo yêu cầu) và nơi lưu điểm trước khi nối vào engine.
3. Chạy lại Win32 với notebook bản mới, hoặc dùng mô hình công bố sẵn làm mốc.
4. (Đã xong) Quyết định `lightgbm`: dùng `requirements-ml.txt`.
5. Hướng A khi có dữ liệu VM.

## 7. Nơi chứa các thứ không nằm trong repo

- Kết quả Kaggle gốc: thư mục `D:\DACN\New folder` trên máy người dùng (ngoài tầm với của phiên cloud).
- Notebook Kaggle: `scripts/ml/kaggle/` (có README ghi trạng thái từng notebook). Notebook Win32 bản mới **chưa chạy thành công trên Kaggle**; Win64 chạy thật bằng phiên bản đầu, bản trong repo chưa chạy lại. Phần train chính cũng có ở `scripts/ml/train_ember2024.py`.
- Thư mục làm việc tạm của phiên cũ (dữ liệu EMBER2024 Dot_Net, venv) là thư mục tạm, **không bền**; không dựa vào nó.
- Môi trường phiên cloud: `git push` tới `origin` hoạt động; `curl` tới `github.com` bị 403 (dùng `raw.githubusercontent.com` hoặc HF để tải).
