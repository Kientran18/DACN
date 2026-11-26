"""Đối chiếu log Invoke-AtomicRedTeam với kết quả phát hiện của DACN, theo cây tiến trình (ProcessGuid).

  python tests/e2e/atomic_compare.py --silver <silver.duckdb> --logs <thư mục/tệp log> [--logs ...]
      [--expected tests/e2e/atomic_expected.yaml] [--out report.md] [--json report.json]

Cách gán: mỗi lần chạy trong log (Attire JSON hoặc CSV mặc định) cho pid của tiến trình mà Invoke-AtomicTest khởi tạo
(cmd.exe hoặc powershell.exe) và thời điểm chạy. Công cụ tìm Event 1 có cùng pid trong cửa sổ thời gian đó (tiến trình
gốc), lấy toàn bộ con cháu qua parent_guid, gom mọi event Silver của cây tiến trình, rồi giao với
contributing_event_ids trong _detection_results. Không gán theo cửa sổ thời gian thuần túy.

An toàn: làm việc trên BẢN SAO Silver (không ghi vào DB core). Không đưa hostname, username, IP, PATH, command line,
stdout/stderr vào kết quả; stderr chỉ dùng để bật cờ gợi ý "Defender/AMSI có thể đã chặn".
Không suy ra điều chưa chạy: test không có trong log là NOT RUN. Cột Defender do người vận hành xác nhận.
"""
from __future__ import annotations

import argparse
import csv
import io
import json
import shutil
import sys
import tempfile
from collections import defaultdict
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Dict, Iterable, List, Optional

import yaml

ROOT = Path(__file__).resolve().parents[2]
for _p in (ROOT / "src", ROOT / "src" / "pipeline", ROOT / "poc" / "sysmon-collector"):
    if str(_p) not in sys.path:
        sys.path.insert(0, str(_p))

from detection.engine import DetectionEngine  # noqa: E402
from pipeline.silver_store import SilverStore  # noqa: E402

EXPECTED = Path(__file__).with_name("atomic_expected.yaml")
CATEGORIES = ("TP_EXPECTED", "FN_NO_RULE", "FN_NO_TELEMETRY", "CONTROL")
VERDICTS = ("TP", "FN", "FN_DU_KIEN", "MATCH_NGOAI_DU_KIEN", "TN", "FP", "KHONG_THAY_TIEN_TRINH_GOC",
            "KHONG_KHOI_TAO_DUOC")
TABLES = ("silver_process_events", "silver_file_events", "silver_registry_events", "silver_network_events")
TOL = timedelta(seconds=5)                 # lệch đồng hồ giữa log ART và Sysmon UtcTime (cùng máy)
CSV_DEFAULT_SPAN = timedelta(seconds=125)  # CSV chỉ có thời điểm bắt đầu; Invoke-AtomicTest timeout mặc định 120 s
DEFENDER_PATTERNS = ("malicious content", "blocked by your antivirus", "scriptcontainedmaliciouscontent",
                     "contains a virus", "potentially unwanted software")


# ---------------------------------------------------------------- đọc log

def _parse_time(s) -> Optional[datetime]:
    if not s:
        return None
    s = str(s).strip().lstrip("+")             # -UFormat '+%Y-...' của PowerShell có thể giữ dấu '+'
    if s.endswith("Z"):
        s = s[:-1] + "+00:00"
    dt = datetime.fromisoformat(s)
    return dt if dt.tzinfo else dt.replace(tzinfo=timezone.utc)


def _read_text(p: Path) -> str:
    raw = p.read_bytes()
    if raw[:2] in (b"\xff\xfe", b"\xfe\xff"):
        return raw.decode("utf-16")
    return raw.decode("utf-8-sig", errors="replace")


def _int(v) -> Optional[int]:
    try:
        return int(v)
    except (TypeError, ValueError):
        return None


def _run(technique, guid, order, start, stop, pid, exit_code, is_timeout, defender_hint, source) -> dict:
    return {"technique": str(technique or ""), "guid": str(guid or "").lower(), "order": _int(order),
            "start": start, "stop": stop, "pid": _int(pid), "exit_code": _int(exit_code),
            "is_timeout": bool(is_timeout), "defender_hint": bool(defender_hint), "source": source}


def _load_attire(p: Path) -> List[dict]:
    data = json.loads(_read_text(p))
    runs = []
    for proc in data.get("procedures") or []:
        pid_ = proc.get("procedure-id") or {}
        for step in proc.get("steps") or []:
            text = " ".join(str(o.get("content") or "") for o in step.get("output") or []).lower()
            runs.append(_run(proc.get("mitre-technique-id"), pid_.get("id"), proc.get("order"),
                             _parse_time(step.get("time-start")), _parse_time(step.get("time-stop")),
                             step.get("process-id"), step.get("exit-code"), step.get("is-timeout"),
                             any(k in text for k in DEFENDER_PATTERNS), p.name))
    return runs


def _load_csv(p: Path) -> List[dict]:
    runs = []
    for row in csv.DictReader(io.StringIO(_read_text(p))):
        runs.append(_run(row.get("Technique"), row.get("GUID"), row.get("Test Number"),
                         _parse_time(row.get("Execution Time (UTC)")), None, row.get("ProcessId"),
                         row.get("ExitCode"), False, False, p.name))
    return runs


def load_runs(paths: Iterable) -> List[dict]:
    files: List[Path] = []
    for p in map(Path, paths):
        if p.is_dir():
            files += sorted(x for x in p.iterdir() if x.suffix.lower() in (".json", ".csv"))
        else:
            files.append(p)
    runs: List[dict] = []
    for f in files:
        runs += _load_csv(f) if f.suffix.lower() == ".csv" else _load_attire(f)
    return sorted(runs, key=lambda r: (r["start"] or datetime.min.replace(tzinfo=timezone.utc)))


# ---------------------------------------------------------------- đối chiếu

def _seed(con, run: dict):
    if run["pid"] is None or run["start"] is None:
        return None
    lo = run["start"] - TOL
    hi = (run["stop"] or run["start"] + CSV_DEFAULT_SPAN) + TOL
    rows = con.execute("select process_guid, timestamp, image_path from silver_process_events "
                       "where sysmon_event_id = 1 and pid = ? and timestamp between ? and ?",
                       [run["pid"], lo, hi]).fetchall()
    if not rows:
        return None
    return min(rows, key=lambda r: abs((r[1] - run["start"]).total_seconds()))


def _children_index(con) -> Dict[str, List[str]]:
    idx: Dict[str, List[str]] = defaultdict(list)
    for guid, parent in con.execute("select process_guid, parent_guid from silver_process_events "
                                    "where sysmon_event_id = 1 and parent_guid is not null").fetchall():
        idx[parent].append(guid)
    return idx


def _lineage(seed_guid: str, children: Dict[str, List[str]]) -> List[str]:
    seen, todo = {seed_guid}, [seed_guid]
    while todo:
        for c in children.get(todo.pop(), []):
            if c not in seen:
                seen.add(c)
                todo.append(c)
    return sorted(seen)


def _events(con, guids: List[str]) -> Dict[str, int]:
    out: Dict[str, int] = {}
    for t in TABLES:
        for eid, sid in con.execute(f"select event_id, sysmon_event_id from {t} where list_contains(?, process_guid)",
                                    [guids]).fetchall():
            out[eid] = sid
    return out


def _verdict(category: str, started: bool, seed_found: bool, target: List[str], matched: List[str]) -> str:
    if not started:                        # log không có pid: Invoke-AtomicTest không tạo được tiến trình
        return "KHONG_KHOI_TAO_DUOC"
    if not seed_found:
        return "KHONG_THAY_TIEN_TRINH_GOC"
    if category == "TP_EXPECTED":
        return "TP" if set(target) & set(matched) else "FN"
    if category == "CONTROL":
        return "FP" if matched else "TN"
    return "MATCH_NGOAI_DU_KIEN" if matched else "FN_DU_KIEN"


def _coverage(con) -> dict:
    lo, hi = con.execute("select min(timestamp), max(timestamp) from silver_process_events").fetchone()
    return {"min": lo.astimezone(timezone.utc).isoformat() if lo else None,
            "max": hi.astimezone(timezone.utc).isoformat() if hi else None, "_max_dt": hi}


def _evaluate(con, runs: List[dict], expected: dict) -> dict:
    spec = {x["guid"].lower(): x for x in expected["tests"]}
    cov = _coverage(con)
    children = _children_index(con)
    results = [json.loads(r[0]) for r in con.execute("select result from _detection_results").fetchall()]
    rows, unknown, attempts = [], [], defaultdict(int)
    for run in runs:
        sp = spec.get(run["guid"])
        if sp is None:
            unknown.append({"technique": run["technique"], "guid": run["guid"]})
            continue
        attempts[sp["id"]] += 1
        seed = _seed(con, run)
        guids = _lineage(seed[0], children) if seed else []
        ev = _events(con, guids) if guids else {}
        outcomes: Dict[str, set] = defaultdict(set)
        for r in results:
            if set(r.get("contributing_event_ids") or []) & set(ev):
                outcomes[r["rule_id"]].add(r["outcome"])
        matched = sorted(rid for rid, o in outcomes.items() if "MATCH" in o)
        seen = sorted(set(ev.values()))
        rows.append({
            "id": sp["id"], "attempt": attempts[sp["id"]], "technique": sp["technique"], "guid": sp["guid"],
            "name": sp.get("name", ""), "category": sp["category"], "target_rules": list(sp.get("target_rules") or []),
            "start": run["start"].isoformat() if run["start"] else None,
            "stop": run["stop"].isoformat() if run["stop"] else None,
            "pid": run["pid"], "exit_code": run["exit_code"], "is_timeout": run["is_timeout"],
            "exec_failed": bool(run["is_timeout"] or run["pid"] is None or (run["exit_code"] not in (None, 0))),
            "defender_hint": run["defender_hint"], "seed_found": seed is not None,
            "seed_image": (str(seed[2]).replace("/", "\\").rsplit("\\", 1)[-1] if seed and seed[2] else None),
            "after_silver_end": bool(run["start"] and (cov["_max_dt"] is None or run["start"] > cov["_max_dt"])),
            "lineage_size": len(guids), "telemetry": seen,
            "missing_telemetry": [e for e in sp.get("expect_telemetry", []) if e not in seen] if seed else [],
            "matched_rules": matched, "outcomes": {k: sorted(v) for k, v in sorted(outcomes.items())},
            "verdict": _verdict(sp["category"], run["pid"] is not None, seed is not None, sp.get("target_rules") or [], matched),
        })
    run_ids = {r["id"] for r in rows}
    not_run = [x["id"] for x in expected["tests"] if x["id"] not in run_ids]
    cov.pop("_max_dt")
    return {"atomics_commit": expected.get("atomics_commit"), "silver_coverage": cov, "runs": rows, "not_run": not_run,
            "unknown_runs": unknown, "by_technique": _summary(rows, expected, not_run)}


def _summary(rows: List[dict], expected: dict, not_run: List[str]) -> List[dict]:
    order, out = [], {}
    for x in expected["tests"]:
        if x["technique"] not in out:
            order.append(x["technique"])
            out[x["technique"]] = {"technique": x["technique"], "runs": 0, **{v: 0 for v in VERDICTS},
                                   "NOT_RUN": 0, "EXEC_FAILED": 0, "DEFENDER_HINT": 0}
        if x["id"] in not_run:
            out[x["technique"]]["NOT_RUN"] += 1
    for r in rows:
        s = out[r["technique"]]
        s["runs"] += 1
        s[r["verdict"]] += 1
        s["EXEC_FAILED"] += r["exec_failed"]
        s["DEFENDER_HINT"] += r["defender_hint"]
    return [out[t] for t in order]


def compare(runs: List[dict], silver: Path, expected=EXPECTED, bronze: Optional[Path] = None) -> dict:
    """Luôn làm việc trên bản sao tạm của Silver: chạy DetectionEngine để kết quả cập nhật mà không ghi vào DB core.
    bronze: thư mục Bronze; segment đã niêm phong mà core chưa nạp (ví dụ dừng core ngay sau khi agent niêm phong lúc dừng)
    được nạp vào BẢN SAO trước khi đối chiếu. Idempotent theo ledger: segment đã nạp được bỏ qua."""
    if not isinstance(expected, dict):
        expected = yaml.safe_load(Path(expected).read_text(encoding="utf-8"))
    silver = Path(silver)
    if not silver.exists():
        raise FileNotFoundError(f"không thấy Silver: {silver}")
    with tempfile.TemporaryDirectory(prefix="dacn_atomic_") as tmp:
        try:
            for src in (silver, silver.with_name(silver.name + ".wal")):
                if src.exists():
                    shutil.copy2(src, Path(tmp) / src.name)
        except OSError as exc:
            raise RuntimeError("không sao chép được Silver (core còn đang chạy?): dừng core rồi chạy lại") from exc
        st = SilverStore(Path(tmp) / silver.name)
        try:
            if bronze:
                st.ingest_dir(Path(bronze), run_id="atomic_compare")
            DetectionEngine(st.con).run()
            return _evaluate(st.con, runs, expected)
        finally:
            st.close()


# ---------------------------------------------------------------- báo cáo

def to_markdown(rep: dict) -> str:
    out = ["# Đánh giá Atomic Red Team - đối chiếu với DACN", "",
           f"Atomics commit: `{rep.get('atomics_commit')}`. Gán theo cây tiến trình (pid + thời điểm -> ProcessGuid -> con cháu).",
           "Báo cáo không chứa hostname, username, IP, command line hay stdout. Cột Defender do người vận hành xác nhận "
           "(cờ 'gợi ý' chỉ dựa trên stderr).",
           f"Silver có dữ liệu Event 1/5 từ {rep['silver_coverage']['min']} đến {rep['silver_coverage']['max']} (UTC).", ""] + (
           ["**Cảnh báo:** có lần chạy bắt đầu SAU dữ liệu cuối của Silver (" +
            ", ".join(r["id"] for r in rep["runs"] if r["after_silver_end"]) +
            "): core có thể chưa nạp Bronze. Chạy lại công cụ với `--bronze <thư mục bronze>`.", ""]
           if any(r["after_silver_end"] for r in rep["runs"]) else []) + [
           "| ID | Lần | Technique | Loại kỳ vọng | Rule mục tiêu | Rule MATCH | Kết luận | Telemetry | Thiếu telemetry | "
           "Exit | Gợi ý Defender (stderr) | Defender (người vận hành) |",
           "|---|---|---|---|---|---|---|---|---|---|---|---|"]
    for r in rep["runs"]:
        out.append(f"| {r['id']} | {r['attempt']} | {r['technique']} | {r['category']} | "
                   f"{', '.join(r['target_rules']) or '-'} | {', '.join(r['matched_rules']) or '-'} | **{r['verdict']}** | "
                   f"{','.join(map(str, r['telemetry'])) or '-'} | {','.join(map(str, r['missing_telemetry'])) or '-'} | "
                   f"{'-' if r['exit_code'] is None else r['exit_code']}{' (timeout)' if r['is_timeout'] else ''} | {'có' if r['defender_hint'] else '-'} |  |")
    out += ["", "## Theo technique (đếm số lần chạy, không phải tỷ lệ)", "",
            "| Technique | Lần chạy | TP | FN | FN dự kiến | MATCH ngoài dự kiến | FP | TN | Không thấy tiến trình gốc | "
            "Không khởi tạo được | NOT RUN | Exit≠0 | Gợi ý Defender |", "|---|---|---|---|---|---|---|---|---|---|---|---|---|"]
    for s in rep["by_technique"]:
        out.append(f"| {s['technique']} | {s['runs']} | {s['TP']} | {s['FN']} | {s['FN_DU_KIEN']} | "
                   f"{s['MATCH_NGOAI_DU_KIEN']} | {s['FP']} | {s['TN']} | {s['KHONG_THAY_TIEN_TRINH_GOC']} | {s['KHONG_KHOI_TAO_DUOC']} | "
                   f"{s['NOT_RUN']} | {s['EXEC_FAILED']} | {s['DEFENDER_HINT']} |")
    tp = sum(s["TP"] for s in rep["by_technique"])
    fn = sum(s["FN"] for s in rep["by_technique"])
    out += ["", f"Test kỳ vọng phát hiện (TP_EXPECTED) đã chạy: TP = {tp}, FN = {fn}. "
            "Cỡ mẫu = số lần chạy ở trên, một VM, một lần đo; không suy rộng thành tỷ lệ phát hiện chung.",
            f"NOT RUN: {', '.join(rep['not_run']) or '(không có)'}.",
            f"Lần chạy không có trong bảng kỳ vọng: {len(rep['unknown_runs'])}."]
    return "\n".join(out) + "\n"


def main(argv=None) -> int:
    for s in (sys.stdout, sys.stderr):        # Windows: stdout qua ống dẫn dùng cp1252
        if hasattr(s, "reconfigure"):
            s.reconfigure(encoding="utf-8", errors="replace")
    ap = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    ap.add_argument("--silver", type=Path, required=True)
    ap.add_argument("--logs", type=Path, action="append", required=True, help="tệp .json/.csv hoặc thư mục chứa chúng")
    ap.add_argument("--expected", type=Path, default=EXPECTED)
    ap.add_argument("--bronze", type=Path, help="thư mục Bronze; nạp segment core chưa nạp vào bản sao Silver")
    ap.add_argument("--out", type=Path)
    ap.add_argument("--json", type=Path)
    a = ap.parse_args(argv)
    try:
        rep = compare(load_runs(a.logs), a.silver, a.expected, a.bronze)
    except (FileNotFoundError, RuntimeError) as exc:
        print(str(exc), file=sys.stderr)
        return 2
    md = to_markdown(rep)
    if a.out:
        a.out.write_text(md, encoding="utf-8")
    else:
        print(md)
    if a.json:
        a.json.write_text(json.dumps(rep, ensure_ascii=False, indent=2), encoding="utf-8")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
