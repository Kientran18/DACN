# Notebook Kaggle huấn luyện EMBER2024

Mục đích: huấn luyện mô hình PE tĩnh (LightGBM, CPU) trên Kaggle. Kết quả chỉ phản ánh EMBER2024, **không phải** chất lượng phát hiện của DACN. Mô tả mô hình: `docs/implementation/ML_EMBER2024_MODELS.md`.

| Notebook | Làm gì | Trạng thái kiểm chứng |
|---|---|---|
| `dacn_ember2024_train_kaggle.ipynb` | Một ô duy nhất, mặc định `Dot_Net` (đổi `LOAI` ở đầu ô). Đã dùng để train Dot_Net | Chạy thật trên Kaggle (Dot_Net) |
| `dacn_ember2024_win64_kaggle.ipynb` | Train Win64 rồi gom kết quả thành `dacn_ml_bundle_win64.zip` (mô hình, `model_card.json` nháp, báo cáo, log) | Win64 chạy thật bằng **phiên bản đầu** (chưa có lấy mẫu và kiểm tra chỉ-đọc). Bản trong repo là bản đã sửa; thuật toán và cấu hình giữ nguyên, nhưng **bản sửa chưa chạy lại trên Kaggle** |
| `dacn_ember2024_win32_kaggle.ipynb` | Như trên cho Win32; lấy mẫu 1/4 train và 1/2 test để giảm khối lượng ghi | **Chưa chạy thành công trên Kaggle.** Bản cũ hỏng vì `/tmp` thành chỉ-đọc ở khoảng 66% vector hóa (nguyên nhân chưa biết); bản này chưa chạy thử |

Cách dùng: import vào Kaggle (File → Import Notebook), bật Internet và để Accelerator = None, chạy (nên Save & Run All), tải zip hoặc file ở tab Output.

Khác với `scripts/ml/train_ember2024.py` (cần cài sẵn `thrember`), các notebook này **nhúng** mã `thrember` (Apache-2.0, FutureComputing4AI/EMBER2024) dạng base64, vì Kaggle không clone được từ `github.com`. Mọi notebook đều giải nén bản nhúng vào `/tmp/thrember_src`.

Bản `all` (Dot_Net + Win64 trong một lần chạy) đã bị thay bằng các notebook riêng nên không đưa vào repo.
