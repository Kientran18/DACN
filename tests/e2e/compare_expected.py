"""So sánh kết quả phát hiện thực tế với kỳ vọng kịch bản (PH5-T03).

  python tests/e2e/compare_expected.py --manifest lab_run_X.json --silver silver.duckdb \
      [--bronze DIR] [--ioc ioc.yaml] [--out report.md]

Trạng thái: PASS / FAIL / NOT RUN / OBSERVED. Không suy ra điều chưa chạy; kịch bản không có trong manifest = NOT RUN.
Chạy được trên fixture lưu sẵn (Linux) và trên dữ liệu VM.
"""
from __future__ import annotations

import argparse
import base64
import binascii
import json
import re
import sys
from pathlib import Path
from typing import Dict, List, Set

import yaml

ROOT = Path(__file__).resolve().parents[2]
for _p in (ROOT / "src", ROOT / "src" / "pipeline", ROOT / "poc" / "sysmon-collector"):
    if str(_p) not in sys.path:
        sys.path.insert(0, str(_p))

from detection.engine import DetectionEngine  # noqa: E402
from detection.ioc import IocStore  # noqa: E402
from pipeline.silver_store import SilverStore  # noqa: E402

SCENARIOS = Path(__file__).with_name("scenarios.yaml")
TEXT_COLS = {
    "silver_process_events": ["command_line", "image_path", "parent_command_line"],
    "silver_file_events": ["file_path", "image_path"],
    "silver_registry_events": ["target_object", "details", "image_path"],
    "silver_network_events": ["image_path", "dns_query_name"],
}
B64 = re.compile(r"[A-Za-z0-9+/]{16,}={0,2}")


def _contains_marker(text, marker: str) -> bool:
    if not text:
        return False
    if marker.lower() in str(text).lower():
        return True
    for tok in B64.findall(str(text)):          # EncodedCommand: UTF-16LE base64
        try:
            if marker.lower() in base64.b64decode(tok + "=" * (-len(tok) % 4)).decode("utf-16-le", "ignore").lower():
                return True
        except (binascii.Error, ValueError):
            continue
    return False


def marker_events(con, marker: str) -> Dict[str, int]:
    """event_id -> sysmon_event_id cho mọi hàng Silver có marker."""
    found: Dict[str, int] = {}
    for table, cols in TEXT_COLS.items():
        cur = con.execute(f"select event_id, sysmon_event_id, {', '.join(cols)} from {table}")
        for row in cur.fetchall():
            if any(_contains_marker(v, marker) for v in row[2:]):
                found[row[0]] = row[1]
    return found


def stored_results(con) -> List[dict]:
    return [json.loads(r[0]) for r in con.execute("select result from _detection_results").fetchall()]


def evaluate(spec: dict, sid: str, entry, con, results, ioc_given: bool) -> dict:
    row = {"scenario": sid, "title": spec["title"], "status": "", "expected": "", "observed": "",
           "telemetry": "", "note": spec.get("notes", "")}
    if entry is None or entry.get("status") != "ok":
        row["status"] = "NOT RUN"
        row["note"] = f"manifest: {entry['status']}" if entry else "không có trong manifest"
        return row
    ev = marker_events(con, entry["marker"])
    seen = sorted({s for s in ev.values()})
    row["telemetry"] = ",".join(map(str, seen)) or "(không có)"
    if spec.get("observe_only"):
        row["status"] = "OBSERVED"
        row["observed"] = f"sự kiện marker: {len(ev)}; người vận hành ghi: EDR / Defender / không ai"
        return row
    if spec.get("requires_ioc") and not ioc_given:
        row["status"], row["note"] = "NOT RUN", "cần --ioc (ioc_candidate của lần chạy)"
        return row
    problems = []
    for need in spec.get("expect_telemetry", []):
        if need not in seen:
            problems.append(f"thiếu telemetry Event {need}")
    for gone in spec.get("absent_telemetry", []):
        if gone in seen:
            problems.append(f"Event {gone} vẫn xuất hiện: tiền điều kiện kịch bản không đúng")
    exp_parts, obs_parts = [], []
    for rule, allowed in spec.get("expected", {}).items():
        outs = {r["outcome"] for r in results if r["rule_id"] == rule and set(r["contributing_event_ids"]) & set(ev)}
        exp_parts.append(f"{rule}: {'/'.join(allowed)}")
        obs_parts.append(f"{rule}: {'/'.join(sorted(outs)) or 'NONE'}")
        ok = (not outs and "NONE" in allowed) or (outs and outs <= set(allowed))
        if not ok:
            problems.append(f"{rule} quan sát {sorted(outs) or 'NONE'}, kỳ vọng {allowed}")
    row["expected"], row["observed"] = "; ".join(exp_parts), "; ".join(obs_parts)
    row["status"] = "FAIL" if problems else "PASS"
    if problems:
        row["note"] = " | ".join(problems)
    return row


def compare(manifest: dict, silver: Path, bronze: Path = None, ioc: Path = None, scenarios: Path = SCENARIOS):
    spec = yaml.safe_load(Path(scenarios).read_text(encoding="utf-8"))["scenarios"]
    st = SilverStore(silver)
    if bronze:
        st.ingest_dir(bronze, run_id="compare")
    DetectionEngine(st.con, ioc=IocStore(ioc) if ioc else IocStore()).run()
    results = stored_results(st.con)
    by_id = {s["id"]: s for s in manifest.get("scenarios", [])}
    rows = [evaluate(sp, sid, by_id.get(sid), st.con, results, ioc is not None) for sid, sp in spec.items()]
    st.close()
    return rows


def to_markdown(rows: List[dict], run_id: str) -> str:
    out = [f"# Đối chiếu kịch bản — run `{run_id}`", "",
           "| Kịch bản | Trạng thái | Kỳ vọng | Quan sát | Telemetry (Event ID) | Ghi chú |", "|---|---|---|---|---|---|"]
    for r in rows:
        out.append(f"| {r['scenario']} {r['title']} | **{r['status']}** | {r['expected']} | {r['observed']} | "
                   f"{r['telemetry']} | {r['note']} |")
    n = {k: sum(r['status'] == k for r in rows) for k in ("PASS", "FAIL", "NOT RUN", "OBSERVED")}
    out += ["", f"Tổng: {n}. Cỡ mẫu = số kịch bản đã chạy; không suy rộng. Cột 'ai phát hiện' do người vận hành điền."]
    return "\n".join(out) + "\n"


def main(argv=None) -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--manifest", type=Path, required=True)
    ap.add_argument("--silver", type=Path, required=True)
    ap.add_argument("--bronze", type=Path)
    ap.add_argument("--ioc", type=Path)
    ap.add_argument("--out", type=Path)
    a = ap.parse_args(argv)
    manifest = json.loads(a.manifest.read_text(encoding="utf-8-sig"))
    rows = compare(manifest, a.silver, a.bronze, a.ioc)
    md = to_markdown(rows, manifest.get("run_id", "?"))
    (a.out.write_text(md, encoding="utf-8") if a.out else print(md))
    return 1 if any(r["status"] == "FAIL" for r in rows) else 0


if __name__ == "__main__":
    raise SystemExit(main())
