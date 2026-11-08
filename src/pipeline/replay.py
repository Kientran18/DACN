"""Dựng lại Silver từ Bronze vào file MỚI (PH3-T05). Không sửa Bronze, không ghi đè."""
from __future__ import annotations

import argparse
import uuid
from pathlib import Path

from .silver_store import SilverStore


def replay(bronze_dir: Path, target: Path) -> dict:
    target = Path(target)
    if target.exists():
        raise FileExistsError(f"không ghi đè Silver có sẵn: {target.name}")
    st = SilverStore(target)
    try:
        results = st.ingest_dir(Path(bronze_dir), run_id="replay-" + uuid.uuid4().hex[:8])
    finally:
        st.close()
    total = {k: sum(r[k] for r in results) for k in ("read", "inserted", "duplicates", "quarantined")}
    return {"segments": len(results), **total}


def main(argv=None) -> int:
    ap = argparse.ArgumentParser(prog="pipeline replay")
    ap.add_argument("--from-bronze", type=Path, required=True)
    ap.add_argument("--to", type=Path, required=True)
    a = ap.parse_args(argv)
    print(replay(a.from_bronze, a.to))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
