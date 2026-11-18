# =====================================================================
# DACN - Train mô hình PE tĩnh trên EMBER2024 (LightGBM, CPU)
# MỘT FILE, CHẠY MỘT LẦN. Chạy lại được: bước nào xong rồi sẽ tự bỏ qua.
# Kết quả chỉ phản ánh dữ liệu EMBER2024, KHÔNG phải chất lượng phát hiện của DACN.
# =====================================================================
import os, sys, io, re, json, time, base64, tarfile, shutil, hashlib, platform, subprocess, importlib.util

# ------------------------- CẤU HÌNH -------------------------
LOAI           = os.environ.get("DACN_LOAI", "Dot_Net")   # "Dot_Net" | "Win64" (Win32 quá nặng cho Kaggle)
MAX_TRAIN_ROWS = int(os.environ["DACN_MAX_ROWS"]) if os.environ.get("DACN_MAX_ROWS") else None   # vd 400000 nếu hết RAM
NUM_ITER       = 500
MIN_FREE_GB    = {"Dot_Net": 20, "Win64": 45, "Win32": 80}.get(LOAI, 45)
# Lấy mẫu theo chu kỳ khi vector hóa: giữ 1 dòng trong mỗi k dòng của từng tuần (giữ nguyên tỷ lệ nhãn và phân bố thời gian).
# Win32 mặc định 1/4 train, 1/2 test để giảm khối lượng ghi file .dat (~32 GB -> ~8 GB). Đặt 1 để dùng đủ dữ liệu.
THIN_TRAIN = int(os.environ.get("DACN_THIN_TRAIN", {"Win32": 4}.get(LOAI, 1)))
THIN_TEST  = int(os.environ.get("DACN_THIN_TEST",  {"Win32": 2}.get(LOAI, 1)))
# Chỉ dùng khi kiểm thử cục bộ (Kaggle không cần đặt):
WORK = os.environ.get("DACN_WORK", "/kaggle/working")
DATA = os.environ.get("DACN_DATA", f"/tmp/data/{LOAI.lower().replace('_', '')}")
NUM_ITER = int(os.environ.get("DACN_ITER", NUM_ITER))
SKIP_PIP = os.environ.get("DACN_SKIP_PIP") == "1"
MIN_FREE_GB = int(os.environ.get("DACN_MIN_FREE", MIN_FREE_GB))
# ------------------------------------------------------------
TEN = LOAI.lower().replace("_", "")
T0 = time.time()

def log(msg): print(f"[{(time.time()-T0)/60:6.1f} phút] {msg}", flush=True)
def sh(c, n=2500):
    r = subprocess.run(c, shell=True, capture_output=True, text=True)
    print((r.stdout + r.stderr)[-n:], flush=True)
def step(name):
    log(f"=== {name} ===")

os.makedirs(WORK, exist_ok=True)
os.makedirs(DATA, exist_ok=True)

# ---------------- Bước 1: tài nguyên + mạng ----------------
step("1/8 Kiểm tra tài nguyên và mạng")
sh("df -h " + WORK + " " + os.path.dirname(DATA) + "; free -g; nproc; python --version")
free_gb = shutil.disk_usage(os.path.dirname(DATA)).free / 1e9
log(f"Đĩa trống ở {os.path.dirname(DATA)}: {free_gb:.0f} GB (cần tối thiểu ~{MIN_FREE_GB} GB cho {LOAI})")
if free_gb < MIN_FREE_GB:
    raise SystemExit(f"Không đủ đĩa cho {LOAI}. Dừng sớm để khỏi tải dở.")
def writable(d):
    try:
        probe = os.path.join(d, ".probe"); open(probe, "w").write("x"); os.remove(probe); return True
    except OSError as e:
        log(f"KHÔNG GHI ĐƯỢC vào {d}: {e}"); return False
if not (writable(DATA) and writable(WORK)):
    raise SystemExit("Hệ tệp đang chỉ-đọc hoặc đầy: hãy RESTART phiên Kaggle rồi chạy lại. (Hệ tệp không ghi được)")
for h in ("huggingface.co", "pypi.org"):
    sh("curl -sS -m 10 -o /dev/null -w '" + h + ": HTTP %{http_code}' https://" + h + " 2>&1 | tail -1")

# ---------------- Bước 2: cài thư viện + thrember nhúng sẵn ----------------
step("2/8 Cài thư viện và nạp thrember (nhúng sẵn, không cần github)")
THREMBER_B64 = ""   # Bản Kaggle nhúng mã thrember (Apache-2.0, FutureComputing4AI/EMBER2024) dạng base64 tại đây vì Kaggle không clone được github.
                    # Bản này dùng gói đã cài: pip install git+https://github.com/FutureComputing4AI/EMBER2024.git
src_dir = "/tmp/thrember_src"
os.makedirs(src_dir, exist_ok=True)
if THREMBER_B64:
    with tarfile.open(fileobj=io.BytesIO(base64.b64decode(THREMBER_B64)), mode="r:gz") as t:
        try:
            t.extractall(src_dir, filter="data")
        except TypeError:                   # Python cũ chưa có tham số filter
            t.extractall(src_dir)
    if src_dir not in sys.path:
        sys.path.insert(0, src_dir)
if not SKIP_PIP:
    sh('pip install -q "signify==0.8.1" "pefile>=2024.8.26" "polars>=1.8.2" "huggingface_hub>=0.32.4" '
       'tqdm matplotlib lightgbm scikit-learn 2>&1 | tail -5')

# Vá oscrypto (OpenSSL 3.x: số vá 2 chữ số làm hỏng nhận dạng phiên bản)
base = os.path.dirname(importlib.util.find_spec("oscrypto").origin)
PAT = re.compile(r"\((\\+)d(\\+)\.(\\+)d(\\+)\.(\\+)d\[a-z\]\*\)")
def _fix(m):
    g = m.groups()
    return "(" + g[0] + "d+" + g[1] + "." + g[2] + "d+" + g[3] + "." + g[4] + "d+[a-z]*)"
for name in ("_libcrypto_ctypes.py", "_libcrypto_cffi.py"):
    fp = os.path.join(base, "_openssl", name)
    if os.path.exists(fp):
        s = open(fp).read()
        s2, n = PAT.subn(_fix, s)
        if n:
            open(fp, "w").write(s2)
        log(f"oscrypto {name}: đã vá {n} chỗ")

import numpy as np
import lightgbm as lgb
import thrember
from sklearn.metrics import roc_auc_score, precision_score, recall_score
NDIM = thrember.PEFeatureExtractor().dim
log(f"thrember nạp OK, số đặc trưng = {NDIM} (kỳ vọng 2568)")
assert NDIM == 2568, "Số đặc trưng khác 2568: sai phiên bản feature"

# ---------------- Bước 3: cấu hình LightGBM ----------------
step("3/8 Cấu hình LightGBM")
cfg = {"objective":"binary","task":"train","boosting":"gbdt","num_iterations":NUM_ITER,"learning_rate":0.1,
 "max_depth":-1,"num_leaves":64,"tree_learner":"serial","num_threads":0,"device_type":"cpu","seed":0,
 "min_data_in_leaf":100,"min_sum_hessian_in_leaf":0.001,"bagging_fraction":0.9,"bagging_freq":1,
 "bagging_seed":0,"feature_fraction":0.9,"feature_fraction_bynode":0.9,"feature_fraction_seed":0,
 "first_metric_only":True,"max_delta_step":0,"lambda_l1":0,"lambda_l2":1.0,"verbosity":-1,
 "is_unbalance":True,"sigmoid":1.0,"boost_from_average":True,"metric":["auc","binary_logloss","binary_error"]}
json.dump(cfg, open(f"{WORK}/lgbm_config.json", "w"), indent=1)

# ---------------- Bước 4+5: tải và vector hóa (bỏ qua nếu đã đủ) ----------------
def dat_ok():
    try:
        for sub in ("train", "test"):
            y = os.path.getsize(f"{DATA}/y_{sub}.dat")
            x = os.path.getsize(f"{DATA}/X_{sub}.dat")
            if y == 0 or y % 4 or x != (y // 4) * NDIM * 4:
                return False
        return True
    except OSError:
        return False

if dat_ok():
    step("4-5/8 Dữ liệu đã vector hóa sẵn: bỏ qua tải và vector hóa")
else:
    def raw_files(sub):
        return sorted(f for f in os.listdir(DATA) if f.endswith(f"_{LOAI}_{sub}.jsonl"))
    marker = f"{DATA}/.thinned_{THIN_TRAIN}_{THIN_TEST}"
    if not (raw_files("train") and raw_files("test")):
        step("4/8 Tải dữ liệu train + test (tự giải nén)")
        t = time.time()
        thrember.download_dataset(DATA, split="train", file_type=LOAI)
        thrember.download_dataset(DATA, split="test", file_type=LOAI)
        log(f"Tải xong sau {(time.time()-t)/60:.1f} phút")
        if os.path.exists(marker):
            os.remove(marker)
    else:
        log("Đã có sẵn file jsonl thô: bỏ qua tải")
    if not os.path.exists(marker):
        def thin(fp, k):
            tmp, kept = fp + ".tmp", 0
            with open(fp, "r") as fin, open(tmp, "w") as fout:
                for i, line in enumerate(fin):
                    if i % k == 0:
                        fout.write(line); kept += 1
            os.replace(tmp, fp)
            return kept
        for sub, k in (("train", THIN_TRAIN), ("test", THIN_TEST)):
            if k > 1:
                tot = sum(thin(os.path.join(DATA, f), k) for f in raw_files(sub))
                log(f"Lấy mẫu 1/{k} tập {sub}: còn {tot} dòng")
        open(marker, "w").write("ok")
    step("5/8 Vector hóa (chậm: vài chục phút)")
    t = time.time()
    try:
        thrember.create_vectorized_features(DATA)
    except ValueError as e:
        log(f"Bỏ qua lỗi tập challenge (không tải tập này): {e}")
    except OSError as e:
        raise RuntimeError(f"Lỗi ghi đĩa khi vector hóa: {e}. Nếu là 'Read-only file system': RESTART phiên Kaggle và thử lại (Hệ tệp không ghi được).") from e
    if not dat_ok():
        raise RuntimeError("Vector hóa không tạo đủ/đúng file .dat cho train và test")
    log(f"Vector hóa xong sau {(time.time()-t)/60:.1f} phút")
    for fn in os.listdir(DATA):
        if fn.endswith(".jsonl"):
            os.remove(os.path.join(DATA, fn))
sh(f"ls -la {DATA}/*.dat")

# ---------------- Bước 6: train tiết kiệm RAM ----------------
step("6/8 Train (lgb.Sequence, đọc theo lô từ memmap)")
y_all = np.fromfile(f"{DATA}/y_train.dat", dtype=np.int32)
Xm = np.memmap(f"{DATA}/X_train.dat", dtype=np.float32, mode="r").reshape(-1, NDIM)
keep = np.flatnonzero(y_all != -1)
perm = np.random.default_rng(0).permutation(keep)
nv = int(len(perm) * 0.1)
va_idx, tr_idx = np.sort(perm[:nv]), np.sort(perm[nv:])
if MAX_TRAIN_ROWS and len(tr_idx) > MAX_TRAIN_ROWS:
    tr_idx = np.sort(np.random.default_rng(1).choice(tr_idx, size=MAX_TRAIN_ROWS, replace=False))
log(f"Dòng train={len(tr_idx)}, val={len(va_idx)}, bỏ qua chưa gán nhãn={int((y_all==-1).sum())}; "
    f"tỷ lệ độc hại train={float(y_all[tr_idx].mean()):.3f}")

class Seq(lgb.Sequence):
    def __init__(self, idx):
        self.idx, self.batch_size = idx, 20000
    def __len__(self):
        return len(self.idx)
    def __getitem__(self, i):
        if isinstance(i, slice):
            return np.asarray(Xm[self.idx[i]])
        return np.asarray(Xm[self.idx[i]]).astype(np.float64)

cat = [2, 3, 4, 5, 6, 701, 702]
t = time.time()
tr = lgb.Dataset(Seq(tr_idx), label=y_all[tr_idx], categorical_feature=cat,
                 params={"max_bin": 255, "bin_construct_sample_cnt": 50000})
va = lgb.Dataset(Seq(va_idx), label=y_all[va_idx], reference=tr, categorical_feature=cat)
booster = lgb.train(cfg, tr, valid_sets=[va], valid_names=["val"],
                    callbacks=[lgb.log_evaluation(25)])
train_min = (time.time() - t) / 60
log(f"Train xong sau {train_min:.1f} phút")
model_path = f"{WORK}/ember2024_{TEN}.txt"
booster.save_model(model_path)

# ---------------- Bước 7: đánh giá trên tập test (12 tuần cuối) ----------------
step("7/8 Đánh giá trên tập test (tách theo thời gian)")
Xt = np.memmap(f"{DATA}/X_test.dat", dtype=np.float32, mode="r").reshape(-1, NDIM)
yt = np.fromfile(f"{DATA}/y_test.dat", dtype=np.int32)
idx = np.flatnonzero(yt != -1)
p = np.concatenate([booster.predict(np.asarray(Xt[idx[i:i+50000]])) for i in range(0, len(idx), 50000)])
y = yt[idx]
auc = float(roc_auc_score(y, p))
res = {"auc_test": auc, "n_test": int(len(y)), "ty_le_doc_hai_test": float(y.mean())}
for fpr in (0.01, 0.001):
    thr = float(np.quantile(p[y == 0], 1 - fpr))
    res[f"thr_fpr_{fpr}"] = thr
    res[f"tpr_tai_fpr_{fpr}"] = float((p[y == 1] >= thr).mean())
res["precision_thr0.5"] = float(precision_score(y, p >= 0.5))
res["recall_thr0.5"] = float(recall_score(y, p >= 0.5))
log("Kết quả: " + json.dumps(res, ensure_ascii=False))

# ---------------- Bước 8: kiểm tra nạp lại + báo cáo ----------------
step("8/8 Kiểm tra nạp lại mô hình, ghi báo cáo")
b2 = lgb.Booster(model_file=model_path)
chk = np.asarray(Xt[idx[:2000]])
assert np.allclose(b2.predict(chk), booster.predict(chk), atol=1e-9), "Mô hình nạp lại cho kết quả khác"
assert 0.0 <= float(p.min()) and float(p.max()) <= 1.0, "Điểm ngoài [0,1]"
log("Nạp lại OK; điểm nằm trong [0,1]")

import importlib.metadata as md_
def _v(n):
    try: return md_.version(n)
    except Exception: return None
rep = {
    "loai_file": LOAI, "nguon_du_lieu": "HF joyce8/EMBER2024 (apache-2.0)", "feature_version": "thrember feature version 3, 2568 dac trung",
    "n_train": int(len(tr_idx)), "n_val": int(len(va_idx)), "num_iterations": NUM_ITER,
    "lay_mau_theo_chu_ky": {"train_1_tren": THIN_TRAIN, "test_1_tren": THIN_TEST},
    "train_phut": round(train_min, 2), "tong_phut": round((time.time() - T0) / 60, 1),
    "sha256_model": hashlib.sha256(open(model_path, "rb").read()).hexdigest(),
    "danh_gia": res,
    "phien_ban": {"python": platform.python_version(), "lightgbm": _v("lightgbm"), "numpy": _v("numpy"),
                  "pefile": _v("pefile"), "signify": _v("signify"), "polars": _v("polars"),
                  "scikit-learn": _v("scikit-learn")},
    "luu_y": "Chỉ phản ánh EMBER2024 (test tách theo thời gian). Không phải chất lượng phát hiện của DACN; ngưỡng cho DACN phải đo trên tệp lành tính của VM.",
}
json.dump(rep, open(f"{WORK}/report_{TEN}.json", "w"), indent=1, ensure_ascii=False)
sh(f"{sys.executable} -m pip freeze 2>/dev/null | grep -iE 'lightgbm|numpy|pefile|polars|scikit-learn|signify|oscrypto|huggingface' > {WORK}/pip_freeze_{TEN}.txt")
print(json.dumps(rep, indent=1, ensure_ascii=False))
sh(f"ls -la {WORK}")
log("XONG. Tải về từ tab Output: ember2024_%s.txt, report_%s.json, lgbm_config.json, pip_freeze_%s.txt" % (TEN, TEN, TEN))
