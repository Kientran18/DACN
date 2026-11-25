"""Detector bất thường hành vi theo ĐỘ HIẾM (ML_BEHAVIOR) — NHÁP, tắt mặc định, giải thích được.

Ý tưởng (UEBA tối giản, thống kê tần suất): học baseline tần suất của vài đặc trưng hành vi từ Silver trên chính
endpoint trong một cửa sổ "bình thường" do người dùng chọn; khi chấm, giá trị chưa gặp/hiếm gặp có độ hiếm cao.
  độ_hiếm(giá trị) = 1 / (1 + số lần gặp trong baseline)      (0 lần -> 1.0)
  độ_hiếm(đặc trưng) = max theo các giá trị của tiến trình
  điểm = Σ w_i · độ_hiếm_i / Σ w_i  (chỉ trên đặc trưng CÓ dữ liệu; thiếu thì liệt kê, không điền)
Không thêm phụ thuộc (thuần Python). Không pickle: baseline lưu JSON, chỉ chứa sha256 của giá trị (không lưu
đường dẫn/tên người dùng dạng rõ). Điểm chỉ góp vào điểm rủi ro; KHÔNG tạo alert, KHÔNG kích hoạt response.
CHƯA có dữ liệu có nhãn của DACN: không công bố độ chính xác; "hiếm" ≠ "độc hại" (phần mềm mới cài cũng hiếm).

Feature contract (phiên bản FEATURE_SCHEMA_VERSION): xem FEATURES; mỗi giá trị mang `source_event_ids`."""
from __future__ import annotations

import argparse
import hashlib
import json
import sys
from collections import Counter
from datetime import datetime, timezone
from pathlib import Path
from typing import Dict, List, Mapping, Optional, Sequence

from .interface import AnomalyResult
from .loader import ModelError, load_model
from .signals import INSUFFICIENT, SCORED, MLSignalStore

DETECTOR = "ML_BEHAVIOR"
FEATURE_SCHEMA_VERSION = "dacn-behavior-rarity/1"
ARTIFACT = "baseline.json"
FEATURES: Dict[str, dict] = {
    "parent_child_pair": {"source_table": "silver_process_events", "sysmon_event_ids": [1],
                          "columns": ["parent_image", "image_path"], "weight": 1.0,
                          "description": "cặp tên tệp cha>con (basename, chữ thường)"},
    "image_path": {"source_table": "silver_process_events", "sysmon_event_ids": [1], "columns": ["image_path"],
                   "weight": 1.0, "description": "đường dẫn ảnh tiến trình (chữ thường): tiến trình mới trên máy"},
    "image_user": {"source_table": "silver_process_events", "sysmon_event_ids": [1],
                   "columns": ["image_path", "user_name"], "weight": 0.5,
                   "description": "cặp ảnh tiến trình|người dùng (chữ thường)"},
    "network_dest_port": {"source_table": "silver_network_events", "sysmon_event_ids": [3],
                          "columns": ["image_path", "dest_port"], "weight": 1.0,
                          "description": "cặp tên tệp:cổng đích của kết nối mạng do tiến trình tạo (max theo kết nối)"},
}


def _base(p: Optional[str]) -> Optional[str]:
    if not p:
        return None
    return str(p).replace("/", "\\").rsplit("\\", 1)[-1].lower() or None


def _h(v: str) -> str:
    return hashlib.sha256(v.encode("utf-8")).hexdigest()[:32]


def _empty(missing: List[str]) -> dict:
    return {"values": [], "source_event_ids": [], "missing": missing}


# -- trích đặc trưng từ Silver --------------------------------------------------------------------------
def _rows(con, sql, params):
    cur = con.execute(sql, params)
    cols = [c[0] for c in cur.description]
    return [dict(zip(cols, r)) for r in cur.fetchall()]


def _window(since, until):
    cond, p = [], []
    if since is not None:
        cond.append("timestamp >= ?"); p.append(since)
    if until is not None:
        cond.append("timestamp <= ?"); p.append(until)
    return ("".join(" and " + c for c in cond)), p


def extract_features(con, since: Optional[datetime] = None, until: Optional[datetime] = None) -> List[dict]:
    """Một vector cho mỗi (hostname, process_guid) có Event 1 trong cửa sổ [since, until] theo thời gian dữ liệu."""
    w, p = _window(since, until)
    procs = _rows(con, "select event_id, hostname, process_guid, timestamp, image_path, parent_image, user_name "
                       "from silver_process_events where sysmon_event_id = 1 and process_guid is not null" + w +
                  " order by timestamp, event_id", p)
    nets: Dict[tuple, List[dict]] = {}
    for n in _rows(con, "select event_id, hostname, process_guid, image_path, dest_port from silver_network_events "
                        "where sysmon_event_id = 3 and process_guid is not null" + w + " order by timestamp, event_id", p):
        nets.setdefault((n["hostname"], n["process_guid"]), []).append(n)
    out = []
    for r in procs:
        f: Dict[str, dict] = {}
        img, parent, user = (r["image_path"] or "").lower() or None, _base(r["parent_image"]), r["user_name"]
        f["image_path"] = ({"values": [img], "source_event_ids": [r["event_id"]], "missing": []} if img
                           else _empty(["image_path"]))
        miss = [k for k, v in (("parent_image", parent), ("image_path", img)) if not v]
        f["parent_child_pair"] = (_empty(miss) if miss else
                                  {"values": [f"{parent}>{_base(img)}"], "source_event_ids": [r["event_id"]], "missing": []})
        miss = [k for k, v in (("image_path", img), ("user_name", user)) if not v]
        f["image_user"] = (_empty(miss) if miss else
                           {"values": [f"{img}|{str(user).lower()}"], "source_event_ids": [r["event_id"]], "missing": []})
        conns = [n for n in nets.get((r["hostname"], r["process_guid"]), []) if n["dest_port"] is not None]
        if conns:
            vals, ids = [], []
            for n in conns:
                v = f"{_base(n['image_path']) or _base(img) or '?'}:{int(n['dest_port'])}"
                if v not in vals:
                    vals.append(v)
                ids.append(n["event_id"])
            f["network_dest_port"] = {"values": vals, "source_event_ids": ids, "missing": []}
        else:
            f["network_dest_port"] = _empty(["network_event"])
        out.append({"hostname": r["hostname"], "process_guid": r["process_guid"], "observed_at": r["timestamp"],
                    "process_event_id": r["event_id"], "features": f})
    return out


# -- train / lưu / nạp -----------------------------------------------------------------------------------
def train(vectors: Sequence[dict], *, min_processes: int = 200) -> dict:
    """Baseline = đếm tần suất (theo sha256 của giá trị). Baseline quá nhỏ -> từ chối, không sinh mô hình."""
    if len(vectors) < min_processes:
        raise ValueError(f"BASELINE_TOO_SMALL: {len(vectors)} tiến trình < {min_processes}")
    counts = {name: Counter() for name in FEATURES}
    for v in vectors:
        for name in FEATURES:
            for val in set(v["features"][name]["values"]):
                counts[name][_h(val)] += 1
    return {"feature_schema_version": FEATURE_SCHEMA_VERSION, "n_processes": len(vectors),
            "counts": {k: dict(sorted(c.items())) for k, c in counts.items()}}


def save_model(model: dict, out_dir: Path, *, model_version: str, trained_since: datetime, trained_until: datetime) -> Path:
    if trained_since.tzinfo is None or trained_until.tzinfo is None or trained_until <= trained_since:
        raise ValueError("cửa sổ train phải có múi giờ và trained_until > trained_since")
    d = Path(out_dir)
    d.mkdir(parents=True, exist_ok=True)
    art = d / ARTIFACT
    art.write_text(json.dumps(model, sort_keys=True), encoding="utf-8")
    card = {"model_version": model_version, "feature_schema_version": FEATURE_SCHEMA_VERSION, "detector": DETECTOR,
            "artifact_file": ARTIFACT, "artifact_sha256": hashlib.sha256(art.read_bytes()).hexdigest(),
            "algorithm": "frequency-rarity baseline (thống kê tần suất, không học có giám sát)",
            "features": FEATURES, "n_processes": model["n_processes"],
            "trained_since": trained_since.isoformat(), "trained_until": trained_until.isoformat(),
            "created_at": datetime.now(timezone.utc).isoformat(), "status": "DRAFT_UNVALIDATED",
            "note": "Chưa có dữ liệu có nhãn của DACN: không có số liệu chất lượng phát hiện. Hiếm không có nghĩa là "
                    "độc hại. Điểm chỉ góp vào điểm rủi ro, không kích hoạt response. Baseline chứa sha256 của giá "
                    "trị lấy từ telemetry: coi là dữ liệu nội bộ, không commit."}
    (d / "model_card.json").write_text(json.dumps(card, ensure_ascii=False, indent=2), encoding="utf-8")
    return d


class BehaviorRarityDetector:
    """Theo giao diện MLDetector: score(features) -> AnomalyResult | None (None = không có đặc trưng nào)."""

    def __init__(self, model: dict):
        if model.get("feature_schema_version") != FEATURE_SCHEMA_VERSION or set(model.get("counts", {})) != set(FEATURES):
            raise ModelError("baseline không khớp feature contract")
        self.model, self.card = model, {}

    def __call__(self, features: Mapping[str, object]) -> float:      # cho loader.LoadedModel
        r = self.score(features)
        if r is None:
            raise ModelError("không có đặc trưng nào")
        return r.score

    def score(self, features: Mapping[str, object]) -> Optional[AnomalyResult]:
        per, missing, num, den = {}, {}, 0.0, 0.0
        for name, spec in FEATURES.items():
            f = features.get(name) or _empty(["absent"])
            if not f["values"]:
                missing[name] = list(f.get("missing") or ["no_value"])
                continue
            best = None
            for val in f["values"]:
                c = int(self.model["counts"][name].get(_h(val), 0))
                r = 1.0 / (1.0 + c)
                if best is None or r > best["rarity"]:
                    best = {"value": val, "baseline_count": c, "rarity": round(r, 6)}
            best.update(weight=spec["weight"], source_event_ids=list(f["source_event_ids"]))
            per[name] = best
            num += spec["weight"] * best["rarity"]
            den += spec["weight"]
        if den == 0:
            return None
        expl = {"features": per, "missing": missing, "baseline_processes": self.model["n_processes"],
                "formula": "Σ w·(1/(1+count)) / Σ w trên đặc trưng có dữ liệu",
                "caveat": "hiếm ≠ độc hại; mô hình nháp chưa hiệu chỉnh"}
        return AnomalyResult(score=round(num / den, 6), feature_schema_version=FEATURE_SCHEMA_VERSION,
                             model_version=self.card.get("model_version", "unknown"),
                             explanation=json.dumps(expl, ensure_ascii=False))


def load_behavior_model(model_dir: Path) -> BehaviorRarityDetector:
    """Kiểm model_card + sha256 artifact qua loader chung; đọc JSON (không pickle/eval)."""
    holder = {}

    def factory(path: Path):
        try:
            data = json.loads(Path(path).read_text(encoding="utf-8"))
        except (OSError, ValueError) as exc:
            raise ModelError("baseline hỏng") from exc
        holder["d"] = BehaviorRarityDetector(data)
        return holder["d"]

    loaded = load_model(Path(model_dir), expected_feature_schema_version=FEATURE_SCHEMA_VERSION, predictor_factory=factory)
    det = holder["d"]
    det.card = loaded.card
    return det


# -- chấm và ghi tín hiệu -----------------------------------------------------------------------------------
def score_signals(con, det: BehaviorRarityDetector, store: MLSignalStore, *, since: Optional[datetime] = None) -> dict:
    """Chấm tiến trình có Event 1 SAU cửa sổ train (chống rò rỉ train/score). Idempotent theo (model, chủ thể)."""
    start = since or datetime.fromisoformat(det.card["trained_until"])
    mv = det.card["model_version"]
    out = {"scored": 0, "insufficient": 0, "skipped_existing": 0}
    for v in extract_features(con, since=start):
        if v["observed_at"] <= start:
            continue
        if store.has(DETECTOR, mv, v["hostname"], v["process_guid"]):
            out["skipped_existing"] += 1
            continue
        r = det.score(v["features"])
        ids = sorted({v["process_event_id"], *[e for f in v["features"].values() for e in f["source_event_ids"]]})
        common = dict(hostname=v["hostname"], process_guid=v["process_guid"], source_event_ids=ids,
                      observed_at=v["observed_at"], model_version=mv, feature_schema_version=FEATURE_SCHEMA_VERSION)
        if r is None:
            store.record(DETECTOR, INSUFFICIENT, reason="NO_FEATURES", **common)
            out["insufficient"] += 1
        else:
            store.record(DETECTOR, SCORED, score=r.score, explanation=json.loads(r.explanation), **common)
            out["scored"] += 1
    return out


def _aware(s: str) -> datetime:
    dt = datetime.fromisoformat(s.replace("Z", "+00:00"))
    if dt.tzinfo is None:
        raise argparse.ArgumentTypeError("thời gian phải có múi giờ, ví dụ 2026-11-20T00:00:00+00:00")
    return dt


def main(argv: Optional[Sequence[str]] = None) -> int:
    import duckdb
    from common.console import force_utf8_stdio
    force_utf8_stdio()
    ap = argparse.ArgumentParser(prog="detection.ml.behavior",
                                 description="Detector độ hiếm hành vi (NHÁP; không kích hoạt response). "
                                             "Dừng core trước khi chạy: DuckDB chỉ cho một tiến trình ghi.")
    sub = ap.add_subparsers(dest="cmd", required=True)
    t = sub.add_parser("train", help="học baseline từ Silver trong cửa sổ được coi là bình thường")
    t.add_argument("--db", required=True)
    t.add_argument("--since", required=True, type=_aware)
    t.add_argument("--until", required=True, type=_aware)
    t.add_argument("--out", required=True)
    t.add_argument("--model-version", required=True)
    t.add_argument("--min-processes", type=int, default=200, help="giá trị tạm, chưa hiệu chỉnh")
    s = sub.add_parser("score", help="chấm tiến trình sau cửa sổ train, ghi _ml_signals")
    s.add_argument("--db", required=True)
    s.add_argument("--model-dir", required=True)
    a = ap.parse_args(argv)
    if a.cmd == "train":
        con = duckdb.connect(a.db, read_only=True)
        try:
            model = train(extract_features(con, since=a.since, until=a.until), min_processes=a.min_processes)
        finally:
            con.close()
        save_model(model, Path(a.out), model_version=a.model_version, trained_since=a.since, trained_until=a.until)
        print(json.dumps({"model_dir": str(a.out), "n_processes": model["n_processes"]}, ensure_ascii=False))
        return 0
    det = load_behavior_model(Path(a.model_dir))
    con = duckdb.connect(a.db)
    try:
        print(json.dumps(score_signals(con, det, MLSignalStore(con)), ensure_ascii=False))
    finally:
        con.close()
    return 0


if __name__ == "__main__":
    sys.exit(main())
