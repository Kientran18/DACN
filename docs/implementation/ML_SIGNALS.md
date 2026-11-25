# Tín hiệu AI/ML hỗ trợ phát hiện bất thường (ML_STATIC, ML_BEHAVIOR)

> Trạng thái (2026-11-25): **NHÁP, tắt mặc định**, có test trên Linux với dữ liệu synthetic (PE synthetic, extractor/predictor giả, Silver synthetic). **Không có số liệu chất lượng phát hiện của DACN** (chưa có dữ liệu có nhãn). Tín hiệu ML chỉ góp vào điểm rủi ro ([RISK_SCORING.md](RISK_SCORING.md)), **không tạo alert, không kích hoạt response**. Chưa chạy trên Windows 10 VM.

## 1. Kiến trúc

```
Silver (Event 1, Event 3) ──► detection/ml/behavior.py  (độ hiếm hành vi) ─┐
Silver Event 1 + tệp trong allowed_dirs ──► detection/ml/static_signal.py ──┼─► _ml_signals ──► risk/service.py ──► API/Dashboard
                                   (bọc static_scorer.py, EMBER2024 nháp) ─┘          (bảng nội bộ, không thuộc DDL)
detection/ml/runner.py: đọc config/ml-detectors.yaml, chạy sau mỗi vòng core (nếu bật); lỗi ML không làm hỏng vòng phát hiện
```

- `signals.py` (`MLSignalStore`) ghi tín hiệu theo dạng: `SCORED` thì phải có `score ∈ [0,1]`; `INSUFFICIENT_TELEMETRY` thì phải có `reason` và `score = NULL`. Không điền điểm giả. Ghi idempotent theo khóa `(detector, model_version, hostname, process_guid)`.
- Cấu hình `config/ml-detectors.yaml` mặc định đặt `enabled: false` cho cả hai detector; loader từ chối khóa thừa. Trạng thái bật/tắt hiển thị ở `/risk/config` và `/health` (`core.ml`).

## 2. ML_STATIC: nối `static_scorer` (EMBER2024) vào luồng

- Chỉ chấm ảnh tiến trình (Silver Event 1) có đường dẫn nằm trong `static_pe.allowed_dirs`, ví dụ thư mục lab. Ngoài phạm vi thì không chấm, và risk ghi `NOT_SCORED`.
- Hàm chấm byte **hiện tại** trên đĩa. Nếu Silver có `file_sha256` khác hash hiện tại thì ghi `INSUFFICIENT_TELEMETRY / HASH_MISMATCH_CURRENT_BYTES`, không gán điểm của tệp khác cho sự kiện cũ. Nếu Silver không có hash thì explanation ghi `identity: CURRENT_BYTES_ONLY`.
- Thiếu `lightgbm` hoặc `thrember` cho ra `INSUFFICIENT_TELEMETRY / DEPENDENCY_MISSING`. Các lý do khác giữ nguyên như `static_scorer` (`NOT_PE`, `NO_MODEL_FOR_KIND` cho Win32, `FILE_TOO_LARGE`…).
- Mỗi vòng chấm tối đa 200 tệp. Con số này là giá trị tạm, chưa đo I/O trên VM.
- Số AUC 0,998 và 0,999 của mô hình EMBER2024 **đo trên EMBER2024, không phải chất lượng phát hiện của DACN** ([ML_EMBER2024_MODELS.md](ML_EMBER2024_MODELS.md)).

## 3. ML_BEHAVIOR: detector độ hiếm hành vi (`behavior.py`)

### 3.1. Vì sao chọn thống kê độ hiếm thay vì Isolation Forest

- **Giải thích được theo từng đặc trưng.** Detector chỉ ra giá trị nào hiếm, đã gặp bao nhiêu lần trong baseline và lấy từ sự kiện nào (`source_event_ids`). Isolation Forest chỉ cho một điểm tổng hợp; muốn giải thích phải thêm SHAP hoặc công cụ tương tự.
- **Không thêm phụ thuộc.** Viết thuần Python, không cần scikit-learn, nên `requirements-ml.txt` không đổi.
- **Không pickle.** Baseline lưu bằng JSON và được kiểm sha256 qua `load_model()` dùng chung.
- **Hợp với dữ liệu hiện có:** một endpoint, ít sự kiện, đặc trưng chủ yếu là dữ liệu phân loại (đường dẫn, cặp cha–con, cổng).
- Isolation Forest để lại cho giai đoạn sau, khi đã có Gold/feature số (tần suất theo cửa sổ, đếm kết nối) và dữ liệu baseline đủ lớn.

### 3.2. Feature contract `dacn-behavior-rarity/1`

| Đặc trưng | Nguồn (bảng, Event ID, cột) | Trọng số | Ý nghĩa |
|---|---|---|---|
| `parent_child_pair` | `silver_process_events`, 1, `parent_image`, `image_path` | 1.0 | cặp `cha.exe>con.exe` (basename, chữ thường) |
| `image_path` | `silver_process_events`, 1, `image_path` | 1.0 | tiến trình mới trên máy |
| `image_user` | `silver_process_events`, 1, `image_path`, `user_name` | 0.5 | ảnh tiến trình chạy dưới người dùng lạ |
| `network_dest_port` | `silver_network_events`, 3, `image_path`, `dest_port` | 1.0 | cặp `tên.exe:cổng` của kết nối mạng do tiến trình tạo |

Mỗi đặc trưng của một tiến trình mang `values`, `source_event_ids` và `missing` (cột nào thiếu). Đặc trưng thiếu dữ liệu không được điền mà bị loại khỏi mẫu số. Nếu không có đặc trưng nào thì kết quả là `INSUFFICIENT_TELEMETRY / NO_FEATURES`.

### 3.3. Công thức

```
độ_hiếm(giá trị)    = 1 / (1 + số lần gặp trong baseline)          (chưa gặp → 1.0)
độ_hiếm(đặc trưng)  = max theo các giá trị của tiến trình
điểm                = Σ w_i · độ_hiếm_i / Σ w_i   (chỉ trên đặc trưng có dữ liệu)
```

**Hiếm không có nghĩa là độc hại.** Phần mềm mới cài, bản cập nhật hay công cụ quản trị dùng một lần đều hiếm. Vì vậy điểm này chỉ góp tối đa 12/100 vào điểm rủi ro.

### 3.4. Tách train và score, chống rò rỉ

```bash
# Dừng core trước: DuckDB chỉ cho một tiến trình ghi. Cửa sổ train phải là khoảng thời gian người dùng tin là bình thường.
PYTHONPATH=src python -m detection.ml.behavior train --db <EDR_HOME>/silver/endpoint_silver.duckdb \
  --since 2026-11-20T00:00:00+00:00 --until 2026-11-24T00:00:00+00:00 \
  --out <EDR_HOME>/models/behavior-v1 --model-version behavior-v1 [--min-processes 200]
PYTHONPATH=src python -m detection.ml.behavior score --db <EDR_HOME>/silver/endpoint_silver.duckdb --model-dir <EDR_HOME>/models/behavior-v1
```

- Lệnh `train` mở DB ở chế độ chỉ đọc. Nếu số tiến trình dưới `--min-processes` (mặc định 200, giá trị tạm), lệnh **từ chối** với `BASELINE_TOO_SMALL`.
- `score` và runner chỉ chấm tiến trình có Event 1 **sau** `trained_until` ghi trong `model_card.json`, nên không chấm lại dữ liệu đã dùng để train.
- `model_card.json` ghi `status: DRAFT_UNVALIDATED`, cửa sổ train, số tiến trình và ghi chú giới hạn. Card không chứa số liệu độ chính xác và không chứa hostname.
- `baseline.json` chỉ lưu sha256 (rút gọn 32 ký tự hex) của giá trị, không lưu đường dẫn hay tên người dùng dạng rõ. Tuy vậy đây vẫn là dữ liệu dẫn xuất từ telemetry nội bộ: **không commit vào repo**.
- Muốn bật trong core: đặt `behavior.enabled: true` và `behavior.model_dir` trong `config/ml-detectors.yaml` (hoặc truyền `--ml-config <tệp>` cho `python -m core`).

## 4. Kiểm thử (2026-11-25, Linux)

| Tệp | Nội dung |
|---|---|
| `tests/detection/test_ml_signals.py` | Ràng buộc SCORED/INSUFFICIENT, idempotent, từ chối detector lạ, NaN |
| `tests/detection/test_behavior_rarity.py` | Feature contract, `source_event_ids`, từ chối baseline nhỏ, baseline không chứa giá trị rõ, tiến trình hiếm có điểm cao hơn, đặc trưng thiếu không bị bịa, artifact bị sửa thì từ chối, không chấm dữ liệu train, CLI |
| `tests/detection/test_ml_runner.py` | Cấu hình mặc định tắt, từ chối khóa lạ, chỉ chấm `allowed_dirs`, hash lệch, `DEPENDENCY_MISSING`, lỗi mô hình không làm hỏng core, trạng thái hiện ở `status()` |

## 5. Chưa có / chưa được chứng minh

- Chưa chạy trên Windows VM; chưa đo thời gian chấm, RAM, I/O.
- Chưa có dữ liệu có nhãn nên **không có** precision, recall hay FPR. Không được trích dẫn điểm ML như bằng chứng.
- Chưa có ngưỡng: điểm ML không tạo alert. Có tạo alert ML hay không do Cyber quyết định.
- Đường `thrember` thật chưa chạy (`thrember` không có trên PyPI).
- Baseline học một lần và không tự cập nhật, nên trôi theo thời gian (concept drift). Chưa có quy trình train lại định kỳ.
- Kẻ tấn công có thể "đầu độc" baseline nếu máy đã bị xâm nhập trong cửa sổ train. Người dùng phải chọn cửa sổ train mà mình tin là sạch.
