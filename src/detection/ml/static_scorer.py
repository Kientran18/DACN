"""Bộ chấm điểm PE tĩnh (NHÁP, chạy theo yêu cầu). Chưa nối vào Detection Engine, chưa lưu kết quả.

- Chỉ đọc tệp trong thư mục cho phép; không thực thi tệp; không pickle.
- Chọn mô hình theo header PE (không theo phần mở rộng): có CLR -> dotnet; PE32+ -> win64; PE32 -> win32 (chưa có mô hình).
- Mọi trường hợp không chấm được -> status INSUFFICIENT_TELEMETRY kèm reason, KHÔNG điền điểm giả.
- Điểm chỉ để tăng rủi ro, `triggers_response` luôn False. Số EMBER2024 không phải chất lượng phát hiện của DACN.
- `threshold` mặc định None: chưa có ngưỡng cho DACN (phải đo trên tệp lành tính của VM)."""
from __future__ import annotations

import argparse
import hashlib
import json
import os
import struct
import sys
from dataclasses import asdict, dataclass, field
from pathlib import Path
from typing import Callable, Mapping, Optional, Sequence

from .loader import LoadedModel, ModelError, load_model

SCHEMA = "thrember-v3-2568"
NDIM = 2568
SCORED, INSUFFICIENT = "SCORED", "INSUFFICIENT_TELEMETRY"
KIND_TO_DIR = {"dotnet": "dotnet", "win64": "win64"}   # win32 chưa có mô hình
DEFAULT_MAX_BYTES = 64 * 1024 * 1024                    # giá trị tạm, chưa đo trên VM


@dataclass(frozen=True)
class StaticScoreResult:
    status: str
    reason: Optional[str] = None
    path: Optional[str] = None
    sha256: Optional[str] = None
    file_kind: Optional[str] = None
    score: Optional[float] = None
    model_version: Optional[str] = None
    feature_schema_version: Optional[str] = None
    over_threshold: Optional[bool] = None   # None khi chưa có ngưỡng
    triggers_response: bool = False         # luôn False theo thiết kế
    note: str = "ML score; chỉ tăng rủi ro, không kích hoạt response; mô hình nháp chưa được duyệt"


@dataclass
class StaticScorerConfig:
    allowed_dirs: Sequence[Path] = field(default_factory=tuple)
    models_root: Path = Path("models/ember2024")
    max_bytes: int = DEFAULT_MAX_BYTES
    threshold: Optional[float] = None


def classify_pe(data: bytes) -> Optional[str]:
    """Trả 'dotnet' | 'win64' | 'win32' hoặc None nếu không phải PE hợp lệ. Chỉ đọc header bằng struct."""
    try:
        if data[:2] != b"MZ":
            return None
        (pe_off,) = struct.unpack_from("<I", data, 0x3C)
        if pe_off + 24 > len(data) or data[pe_off:pe_off + 4] != b"PE\0\0":
            return None
        (size_opt,) = struct.unpack_from("<H", data, pe_off + 20)
        opt = pe_off + 24
        if size_opt < 2 or opt + size_opt > len(data):
            return None
        (magic,) = struct.unpack_from("<H", data, opt)
        if magic not in (0x10B, 0x20B):
            return None
        dirs_off = opt + (96 if magic == 0x10B else 112)
        clr = False
        if dirs_off + 4 <= opt + size_opt and dirs_off + 4 <= len(data):
            (n_dirs,) = struct.unpack_from("<I", data, dirs_off)
            clr_off = dirs_off + 4 + 14 * 8
            if n_dirs > 14 and clr_off + 8 <= opt + size_opt and clr_off + 8 <= len(data):
                rva, size = struct.unpack_from("<II", data, clr_off)
                clr = rva != 0 and size != 0
        if clr:
            return "dotnet"
        return "win64" if magic == 0x20B else "win32"
    except struct.error:
        return None


def _default_extractor() -> Callable[[bytes], Sequence[float]]:
    import thrember  # nạp lazy: không bắt buộc khi chạy EDR
    ext = thrember.PEFeatureExtractor()
    return ext.feature_vector


def _default_predictor_factory(path: Path):
    import lightgbm as lgb
    import numpy as np
    booster = lgb.Booster(model_file=str(path))
    return lambda f: float(booster.predict(np.asarray(f["x"], dtype=np.float32).reshape(1, -1))[0])


class StaticScorer:
    def __init__(self, config: StaticScorerConfig, *,
                 extractor: Optional[Callable[[bytes], Sequence[float]]] = None,
                 predictor_factory: Optional[Callable[[Path], Callable[[Mapping[str, object]], float]]] = None):
        self.cfg = config
        self._extractor = extractor
        self._factory = predictor_factory or _default_predictor_factory
        self._models: dict[str, LoadedModel] = {}

    def _insufficient(self, reason: str, **kw) -> StaticScoreResult:
        return StaticScoreResult(status=INSUFFICIENT, reason=reason, **kw)

    def _allowed(self, p: Path) -> bool:
        for d in self.cfg.allowed_dirs:
            try:
                p.relative_to(Path(d).resolve())
                return True
            except ValueError:
                continue
        return False

    def score_file(self, path: str | os.PathLike) -> StaticScoreResult:
        raw = str(path)
        try:
            p = Path(path).resolve(strict=True)
        except (OSError, RuntimeError):
            return self._insufficient("FILE_UNREADABLE", path=raw)
        if not self._allowed(p):                       # kiểm tra sau resolve: chặn traversal và symlink thoát thư mục
            return self._insufficient("DIR_NOT_ALLOWED", path=raw)
        try:
            with open(p, "rb") as fh:
                if not os.path.isfile(p) or os.fstat(fh.fileno()).st_size > self.cfg.max_bytes:
                    return self._insufficient("FILE_TOO_LARGE" if p.is_file() else "FILE_UNREADABLE", path=raw)
                data = fh.read(self.cfg.max_bytes + 1)
        except OSError:
            return self._insufficient("FILE_UNREADABLE", path=raw)
        if len(data) > self.cfg.max_bytes:
            return self._insufficient("FILE_TOO_LARGE", path=raw)
        sha = hashlib.sha256(data).hexdigest()
        kind = classify_pe(data)
        if kind is None:
            return self._insufficient("NOT_PE", path=raw, sha256=sha)
        if kind not in KIND_TO_DIR:
            return self._insufficient("NO_MODEL_FOR_KIND", path=raw, sha256=sha, file_kind=kind)
        try:
            model = self._model(kind)
        except ModelError:
            return self._insufficient("MODEL_REJECTED", path=raw, sha256=sha, file_kind=kind)
        except ImportError:
            return self._insufficient("DEPENDENCY_MISSING", path=raw, sha256=sha, file_kind=kind)
        try:
            if self._extractor is None:
                self._extractor = _default_extractor()
            vec = list(self._extractor(data))
        except ImportError:
            return self._insufficient("DEPENDENCY_MISSING", path=raw, sha256=sha, file_kind=kind)
        except Exception:
            return self._insufficient("FEATURE_EXTRACTION_FAILED", path=raw, sha256=sha, file_kind=kind)
        if len(vec) != NDIM:
            return self._insufficient("FEATURE_DIM_MISMATCH", path=raw, sha256=sha, file_kind=kind)
        try:
            r = model.score({"x": vec})
        except Exception:                               # kể cả ModelError (điểm ngoài [0,1])
            return self._insufficient("SCORING_FAILED", path=raw, sha256=sha, file_kind=kind)
        over = None if self.cfg.threshold is None else r.score >= self.cfg.threshold
        return StaticScoreResult(status=SCORED, path=raw, sha256=sha, file_kind=kind, score=r.score,
                                 model_version=r.model_version, feature_schema_version=r.feature_schema_version,
                                 over_threshold=over)

    def _model(self, kind: str) -> LoadedModel:
        if kind not in self._models:
            self._models[kind] = load_model(Path(self.cfg.models_root) / KIND_TO_DIR[kind],
                                            expected_feature_schema_version=SCHEMA,
                                            predictor_factory=self._factory)
        return self._models[kind]


def main(argv: Optional[Sequence[str]] = None) -> int:
    ap = argparse.ArgumentParser(description="Chấm điểm PE tĩnh theo yêu cầu (NHÁP, không kích hoạt response)")
    ap.add_argument("file")
    ap.add_argument("--allow-dir", action="append", default=[], help="thư mục được phép đọc (lặp lại được); mặc định từ chối tất cả")
    ap.add_argument("--models-root", default="models/ember2024")
    ap.add_argument("--max-bytes", type=int, default=DEFAULT_MAX_BYTES)
    ap.add_argument("--threshold", type=float, default=None, help="chưa có ngưỡng cho DACN; để trống")
    a = ap.parse_args(argv)
    cfg = StaticScorerConfig(allowed_dirs=[Path(d) for d in a.allow_dir], models_root=Path(a.models_root),
                             max_bytes=a.max_bytes, threshold=a.threshold)
    print(json.dumps(asdict(StaticScorer(cfg).score_file(a.file)), ensure_ascii=False, indent=2))
    return 0


if __name__ == "__main__":
    sys.exit(main())
