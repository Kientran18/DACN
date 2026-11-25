"""Nối static_scorer (EMBER2024, NHÁP) thành nguồn tín hiệu ML_STATIC tùy chọn, tắt mặc định.

- Chỉ chấm ảnh tiến trình (Silver Event 1) nằm trong `allowed_dirs` của scorer; ngoài phạm vi thì không chấm.
- Chấm byte HIỆN TẠI trên đĩa: nếu Silver có file_sha256 mà khác hash hiện tại -> INSUFFICIENT_TELEMETRY
  (HASH_MISMATCH_CURRENT_BYTES), không gán điểm của tệp khác cho sự kiện cũ.
- Không chấm được (thiếu lightgbm/thrember, không phải PE, chưa có mô hình Win32...) -> INSUFFICIENT_TELEMETRY + reason.
- Chỉ góp vào điểm rủi ro; KHÔNG tạo alert, KHÔNG kích hoạt response."""
from __future__ import annotations

import os
from typing import Optional

from .signals import INSUFFICIENT, SCORED, MLSignalStore
from .static_scorer import SCORED as SCORER_OK, StaticScorer

DETECTOR = "ML_STATIC"
SIGNAL_VERSION = "ember2024-draft/thrember-v3-2568"   # khóa idempotent; model_version thật nằm trong explanation


def _inside(path: str, dirs) -> bool:
    p = os.path.normcase(os.path.abspath(path))
    for d in dirs:
        base = os.path.normcase(os.path.abspath(str(d)))
        if p.startswith(base.rstrip("\\/") + os.sep):
            return True
    return False


def score_static_signals(con, scorer: StaticScorer, store: MLSignalStore, *, limit: Optional[int] = 200) -> dict:
    out = {"scored": 0, "insufficient": 0, "skipped_existing": 0}
    dirs = list(scorer.cfg.allowed_dirs)
    if not dirs:
        return out
    rows = con.execute("select event_id, hostname, process_guid, timestamp, image_path, file_sha256 "
                       "from silver_process_events where sysmon_event_id = 1 and process_guid is not null "
                       "and image_path is not null order by timestamp, event_id").fetchall()
    done = 0
    for eid, host, guid, ts, path, sha in rows:
        if not _inside(path, dirs):
            continue
        if store.has(DETECTOR, SIGNAL_VERSION, host, guid):
            out["skipped_existing"] += 1
            continue
        if limit is not None and done >= limit:
            break                                   # giới hạn mỗi vòng: đọc tệp tốn I/O
        done += 1
        res = scorer.score_file(path)
        common = dict(hostname=host, process_guid=guid, source_event_ids=[eid], observed_at=ts,
                      model_version=SIGNAL_VERSION, feature_schema_version=res.feature_schema_version)
        if res.status == SCORER_OK and sha and sha.lower() != (res.sha256 or "").lower():
            store.record(DETECTOR, INSUFFICIENT, reason="HASH_MISMATCH_CURRENT_BYTES", **common)
            out["insufficient"] += 1
        elif res.status == SCORER_OK:
            store.record(DETECTOR, SCORED, score=res.score, **common, explanation={
                "model_version": res.model_version, "file_kind": res.file_kind, "sha256": res.sha256,
                "identity": "HASH_VERIFIED" if sha else "CURRENT_BYTES_ONLY", "over_threshold": res.over_threshold,
                "note": res.note + "; số EMBER2024 không phải chất lượng phát hiện của DACN"})
            out["scored"] += 1
        else:
            store.record(DETECTOR, INSUFFICIENT, reason=res.reason or "UNKNOWN", **common)
            out["insufficient"] += 1
    return out
