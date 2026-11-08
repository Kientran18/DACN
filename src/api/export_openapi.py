"""Xuất openapi.json (PH8-T09)."""
from __future__ import annotations

import json
from pathlib import Path


def export(app, out: Path) -> None:
    Path(out).write_text(json.dumps(app.openapi(), ensure_ascii=False, indent=2), encoding="utf-8")
