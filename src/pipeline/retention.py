"""Retention DRY-RUN (PH3-T09): chỉ LẬP BÁO CÁO những gì sẽ được dọn; KHÔNG xóa/ghi bất kỳ tệp hay dòng nào.
Ngưỡng do người dùng quyết định (không có mặc định ngầm). Một segment Bronze chỉ là ứng viên khi:
  - đã seal quá `raw_days` ngày (theo `sealed_at` trong manifest), và
  - không có sự kiện nào của nó là bằng chứng của alert chưa đóng (evidence hold: NEW/TRIAGED/INVESTIGATING/CONFIRMED).
Sau khi xóa, resolver sẽ báo RAW_EXPIRED cho các sự kiện đó (đã có trong evidence.py)."""
from __future__ import annotations

import argparse
import json
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Dict, List, Optional

OPEN_STATUSES = ("NEW", "TRIAGED", "INVESTIGATING", "CONFIRMED")


def _sealed_at(manifest_path: Path) -> Optional[datetime]:
    try:
        v = json.loads(manifest_path.read_text(encoding="utf-8"))["sealed_at"]
        return datetime.fromisoformat(v.replace("Z", "+00:00"))
    except (OSError, KeyError, ValueError):
        return None


def plan_retention(bronze_dir: Path, con, *, raw_days: int, now: Optional[datetime] = None) -> Dict:
    if raw_days is None or raw_days < 1:
        raise ValueError("raw_days phải >= 1 do người dùng chọn")
    now = now or datetime.now(timezone.utc)
    cutoff = now - timedelta(days=raw_days)
    held = {r[0] for r in con.execute(
        "select distinct l.bronze_segment from silver_event_lineage l join "
        "(select unnest(contributing_event_ids) as eid from alerts where status in (%s)) a on a.eid = l.event_id"
        % ",".join("?" * len(OPEN_STATUSES)), list(OPEN_STATUSES)).fetchall()}
    candidates: List[dict] = []
    kept: List[dict] = []
    unknown: List[dict] = []
    for seg in sorted(Path(bronze_dir).glob("seg-*.jsonl")):
        mp = seg.with_suffix(".manifest.json")
        at = _sealed_at(mp) if mp.exists() else None
        size = seg.stat().st_size
        if at is None:
            unknown.append({"segment": seg.name, "reason": "thiếu hoặc hỏng manifest: không xác định tuổi, KHÔNG dọn"})
        elif at > cutoff:
            kept.append({"segment": seg.name, "reason": "còn trong thời hạn", "sealed_at": at.isoformat()})
        elif seg.name in held:
            kept.append({"segment": seg.name, "reason": "EVIDENCE_HOLD: là bằng chứng của alert chưa đóng", "sealed_at": at.isoformat()})
        else:
            candidates.append({"segment": seg.name, "sealed_at": at.isoformat(), "bytes": size,
                               "effect": "evidence của alert đã đóng sẽ hiện RAW_EXPIRED"})
    return {"dry_run": True, "generated_at_utc": now.isoformat(), "raw_days": raw_days, "cutoff_utc": cutoff.isoformat(),
            "would_delete": candidates, "would_delete_bytes": sum(c["bytes"] for c in candidates),
            "kept": kept, "unknown": unknown,
            "note": "Báo cáo dry-run. Không có tệp nào bị xóa. Silver không bị dọn."}


def main(argv=None) -> int:
    from common.config import load_config
    from pipeline.silver_store import SilverStore
    ap = argparse.ArgumentParser(prog="pipeline.retention")
    ap.add_argument("--config", type=Path)
    ap.add_argument("--raw-days", type=int, required=True, help="ngưỡng do người dùng quyết định")
    ap.add_argument("--out", type=Path)
    a = ap.parse_args(argv)
    cfg = load_config(a.config)
    store = SilverStore(cfg.silver_db)
    rep = plan_retention(cfg.bronze_dir, store.con, raw_days=a.raw_days)
    text = json.dumps(rep, ensure_ascii=False, indent=2)
    if a.out:
        a.out.write_text(text, encoding="utf-8")
    print(text)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
