# Mô hình PE tĩnh EMBER2024 (Dot_Net, Win64) — trạng thái NHÁP

> **Trạng thái:** `DRAFT_CHUA_DUYET`. Chưa được Cyber hoặc Data duyệt; chưa nối vào Detection Engine; không kích hoạt response.
> Số liệu bên dưới **chỉ phản ánh dữ liệu EMBER2024**, **không phải chất lượng phát hiện của DACN**.

## 1. Đây là gì

Hai bộ phân loại LightGBM nhị phân (độc hại / lành tính) cho tệp PE tĩnh, huấn luyện trên tập công khai EMBER2024 (Hugging Face `joyce8/EMBER2024`, apache-2.0; bài báo arXiv 2506.05074). Mỗi loại tệp có một mô hình riêng, theo cách tác giả EMBER2024 làm.

| Thư mục | Loại tệp | Số dòng train | File mô hình |
|---|---|---|---|
| `models/ember2024/dotnet/` | .NET | 468.000 | `ember2024_dotnet.txt` |
| `models/ember2024/win64/` | PE 64-bit | 936.000 | `ember2024_win64.txt` |

Win32 **chưa** huấn luyện (lần chạy trên Kaggle bị hệ tệp chuyển sang chỉ-đọc giữa chừng).

Mỗi thư mục gồm: mô hình dạng text của LightGBM, `model_card.json`, `report_*.json`, `lgbm_config.json`, `pip_freeze_*.txt`.

## 2. Cách huấn luyện (để tái lập)

- Đặc trưng: gói `thrember` (feature version 3, 2568 đặc trưng, trích bằng `pefile`).
- Tách dữ liệu: train = 52 tuần đầu, test = 12 tuần cuối của EMBER2024 (tách theo thời gian). Validation = 10% ngẫu nhiên của train.
- Cấu hình: `lgbm_config.json` (500 vòng, learning rate 0,1, 64 lá, `min_data_in_leaf` 100, `is_unbalance`).
- Script: `scripts/ml/train_ember2024.py` (đặt `DACN_LOAI=Dot_Net` hoặc `Win64`). Chạy bằng `lgb.Sequence` để giảm RAM (Dot_Net đo được đỉnh khoảng 8 GB, so với khoảng 13 GB của `thrember.train_model`).
- Môi trường chạy thật: Kaggle CPU, Python 3.13, `lightgbm 4.6.0` (xem `pip_freeze_*.txt`). Script trong repo là dạng gần nhất với lần chạy; không đảm bảo byte-giống-byte (bản Kaggle nhúng sẵn mã `thrember` vì Kaggle không clone được github).
- Kỳ vọng tái lập: cùng seed và cùng dữ liệu cho kết quả gần giống, không cam kết giống tuyệt đối khi đổi phiên bản `lightgbm`.

## 3. Kết quả trên EMBER2024

| | Dot_Net | Win64 |
|---|---|---|
| AUC test (tách theo thời gian) | 0,9980 | 0,9989 |
| TPR khi FPR = 1% | 95,9% | 98,4% |
| TPR khi FPR = 0,1% | 82,9% | 93,0% |
| Ngưỡng ứng với FPR = 0,1% (trên EMBER2024) | 0,998 | 0,976 |
| Số mẫu test | 120.000 | 240.000 |

Điều cần đọc đúng:
- Tập test **cân bằng 50/50**. Precision và recall ở ngưỡng 0,5 sẽ **không** giữ nguyên khi tệp độc hại hiếm như trên máy thật.
- AUC trên validation ngẫu nhiên cao hơn AUC test tách theo thời gian (Win64 khoảng 0,9999 so với 0,9989): mô hình kém đi nhẹ với mẫu mới hơn.
- Ngưỡng ở bảng chỉ đúng với EMBER2024. Ngưỡng cho DACN phải đo trên tệp lành tính của VM.

## 4. Cách nạp (qua `src/detection/ml/loader.py`)

`loader.py` không giải tuần tự hóa (không pickle); bạn cung cấp `predictor_factory`:

```python
import lightgbm as lgb, numpy as np
from pathlib import Path
from detection.ml.loader import load_model

def factory(path):
    booster = lgb.Booster(model_file=str(path))
    return lambda f: float(booster.predict(np.asarray(f["x"], dtype=np.float32).reshape(1, -1))[0])

m = load_model(Path("models/ember2024/win64"), expected_feature_schema_version="thrember-v3-2568",
               predictor_factory=factory)
```

`f["x"]` là vector 2568 đặc trưng do `thrember.PEFeatureExtractor().feature_vector(bytes)` trả về. Loader từ chối model khi thiếu/hỏng `model_card.json`, sai `feature_schema_version` hoặc sai sha256.

Test: `tests/detection/test_ember2024_models.py` (cần `lightgbm`; thiếu thì bỏ qua). Lệnh: `python -m pytest -q tests/detection/test_ember2024_models.py`.

## 5. Chưa có và chưa được duyệt

- **Bộ chấm điểm tĩnh:** đã có bản NHÁP chạy theo yêu cầu ở `src/detection/ml/static_scorer.py` (mục 5.1). Chưa nối vào Detection Engine, chưa lưu kết quả, chưa có đường trích đặc trưng thật được chạy (xem `thrember` bên dưới).
- **Ngưỡng cho DACN** đo trên tệp lành tính của VM; thời gian mỗi tệp và RAM trên VM 2 GB chưa đo. Mọi số đo trên Windows chưa có.
- Win32, mô hình khác (APK, ELF, PDF) chưa huấn luyện.
- `DetectionResult`, hợp đồng dữ liệu của điểm ML và phạm vi "static scoring" cần Cyber/Data duyệt.
- Tệp không đọc được hoặc loại không hỗ trợ ⇒ `INSUFFICIENT_TELEMETRY`, không điền điểm giả.
- Điểm ML chỉ để tăng rủi ro, **không kích hoạt response**.
- Phụ thuộc ML nằm ở `requirements-ml.txt` (tùy chọn, không thuộc `requirements.txt`). `thrember` **không có trên PyPI** (kiểm tra 2026-11-18): phải cài từ GitHub, chưa thử trên Windows VM; `oscrypto` từng lỗi với OpenSSL 3.x trên Kaggle.

### 5.1. Bộ chấm điểm tĩnh (NHÁP)

- Dùng: `PYTHONPATH=src python -m detection.ml.static_scorer <file> --allow-dir <thư mục>`; hoặc `StaticScorer(StaticScorerConfig(...)).score_file(path)`.
- Chỉ đọc tệp trong `allowed_dirs` (mặc định rỗng = từ chối), kiểm tra sau `resolve()`; không thực thi tệp; giới hạn `max_bytes` (64 MiB là giá trị tạm, chưa đo trên VM).
- Chọn mô hình theo header PE: có CLR → `dotnet`; PE32+ → `win64`; PE32 → `win32` (chưa có mô hình ⇒ `NO_MODEL_FOR_KIND`).
- Không chấm được ⇒ `INSUFFICIENT_TELEMETRY` kèm `reason` (`DIR_NOT_ALLOWED`, `FILE_UNREADABLE`, `FILE_TOO_LARGE`, `NOT_PE`, `NO_MODEL_FOR_KIND`, `MODEL_REJECTED`, `DEPENDENCY_MISSING`, `FEATURE_EXTRACTION_FAILED`, `FEATURE_DIM_MISMATCH`, `SCORING_FAILED`); không điền điểm giả.
- Kết quả là dataclass nội bộ `StaticScoreResult`, **chưa phải `DetectionResult`**; `triggers_response` luôn `False`; `threshold` mặc định `None` (chưa có ngưỡng cho DACN).
- Test: `tests/detection/test_static_scorer.py` dùng PE synthetic, bộ trích đặc trưng và predictor giả (không cần `lightgbm`/`thrember`). Chưa kiểm chứng đường `thrember` thật và chưa đo thời gian/RAM trên VM.
- Chưa quyết định (cần Cyber/Data duyệt): dạng `DetectionResult`, kích hoạt theo sự kiện hay theo yêu cầu, nơi lưu điểm.

## 6. Nguồn và giấy phép

- Dữ liệu và mã đặc trưng: EMBER2024 / `thrember` (FutureComputing4AI), giấy phép apache-2.0. Mô hình tham chiếu công bố sẵn của tác giả: `joyce8/EMBER2024-benchmark-models` (không dùng ở đây).
- Không có mã độc thật trong repo; dữ liệu train không được đưa vào repo.
