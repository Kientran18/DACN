"""Chạy bộ nghiệm thu AT-01..AT-43 (PH11-T01/T04).

Trạng thái KHÔNG được điền bằng tay: suy ra từ kết quả pytest thật.
  PASS     mọi test liệt kê đều đạt và catalog không khai báo khoảng trống (gaps)
  PARTIAL  các test đạt nhưng catalog ghi rõ phần Expected chưa được phủ
  FAIL     có test fail/error, hoặc test liệt kê không tồn tại (không được coi là PASS)
  NOT RUN  mức W (cần Windows VM thật) hoặc chưa có test
Mức bằng chứng L = Linux + dữ liệu mẫu/giả lập; không thay cho kiểm chứng trên Windows.

Dùng:  python scripts/acceptance/run_acceptance.py [--out DIR]
"""
from __future__ import annotations

import argparse
import datetime as dt
import json
import platform
import re
import subprocess
import sys
from pathlib import Path

import yaml

ROOT = Path(__file__).resolve().parents[2]
CATALOG = ROOT / "tests" / "acceptance" / "at_catalog.yaml"


class _Collect:
    def __init__(self) -> None:
        self.results: dict[str, str] = {}
        self.durations: dict[str, float] = {}

    def pytest_runtest_logreport(self, report) -> None:  # noqa: ANN001
        nid = report.nodeid
        if report.when == "call":
            self.results[nid] = report.outcome
        elif report.outcome == "failed":  # setup/teardown lỗi
            self.results[nid] = "error"
        elif report.when == "setup" and report.outcome == "skipped":
            self.results[nid] = "skipped"
        self.durations[nid] = self.durations.get(nid, 0.0) + report.duration


def check_doc_links() -> tuple[bool, str]:
    bad: list[str] = []
    n = 0
    for md in sorted((ROOT / "docs" / "implementation").rglob("*.md")):
        for m in re.finditer(r"\[[^\]]*\]\(([^)\s]+)\)", md.read_text(encoding="utf-8")):
            tgt = m.group(1)
            if tgt.startswith(("http://", "https://", "mailto:", "#")):
                continue
            n += 1
            p = (md.parent / tgt.split("#")[0]).resolve()
            if not p.exists():
                bad.append(f"{md.relative_to(ROOT)} -> {tgt}")
    return (not bad, f"{n} liên kết tương đối đã kiểm tra; hỏng: {bad or 'không'}")


def match(nid_run: str, wanted: str) -> bool:
    base = nid_run.split("[")[0] if "[" in nid_run else nid_run
    return nid_run == wanted or base == wanted or nid_run.startswith(wanted + "::") or (
        "::" not in wanted and nid_run.startswith(wanted + "::")) or nid_run.startswith(wanted + "[")


def git(*a: str) -> str:
    try:
        return subprocess.run(["git", *a], cwd=ROOT, capture_output=True, text=True, check=True).stdout.strip()
    except Exception:  # noqa: BLE001
        return "UNKNOWN"


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--out", default=str(ROOT / "docs" / "implementation" / "acceptance"))
    args = ap.parse_args()
    cat = yaml.safe_load(CATALOG.read_text(encoding="utf-8"))

    import pytest

    files = sorted({w.split("::")[0] for a in cat.values() for w in a.get("tests", [])})
    col = _Collect()
    t0 = dt.datetime.now(dt.timezone.utc)
    rc = pytest.main(["-q", "-p", "no:cacheprovider", *files], plugins=[col])
    t1 = dt.datetime.now(dt.timezone.utc)

    rows = []
    for at, a in cat.items():
        level = a["level"]
        row = {"id": at, "req": a["req"], "level": level, "goal": a["goal"], "pre": a["pre"],
               "steps": a["steps"], "expected": a["expected"], "limits": a.get("limits", ""),
               "gaps": a.get("gaps", ""), "tests": [], "actual": ""}
        if level == "W":
            row.update(status="NOT RUN", actual="Cần Windows 10 VM thật; Claude không chạy được.")
        elif a.get("check") == "doc_links":
            ok, msg = check_doc_links()
            st = "FAIL" if not ok else ("PARTIAL" if a.get("gaps") else "PASS")
            row.update(status=st, actual=msg)
        else:
            outs, missing = [], []
            for w in a["tests"]:
                hits = [(n, o) for n, o in col.results.items() if match(n, w)]
                if not hits:
                    missing.append(w)
                outs.extend(hits)
            row["tests"] = [{"node": n, "outcome": o} for n, o in outs]
            bad = [n for n, o in outs if o != "passed"]
            if missing or bad or not outs:
                row.update(status="FAIL", actual=f"không đạt: {bad}; không tìm thấy: {missing}")
            else:
                row.update(status="PARTIAL" if a.get("gaps") else "PASS",
                           actual=f"{len(outs)} test pytest đạt, 0 lỗi")
        rows.append(row)

    counts: dict[str, int] = {}
    for r in rows:
        counts[r["status"]] = counts.get(r["status"], 0) + 1
    meta = {
        "run_utc": t0.strftime("%Y-%m-%dT%H:%M:%SZ"), "duration_s": round((t1 - t0).total_seconds(), 1),
        "commit": git("rev-parse", "--short", "HEAD"), "dirty": bool(git("status", "--porcelain")),
        "python": platform.python_version(), "os": f"{platform.system()} {platform.release()}",
        "evidence_level": "L (Linux, dữ liệu synthetic/giả lập); W (Windows) chưa chạy",
        "pytest_exit_code": int(rc), "counts": counts,
        "packages": _pkgs(),
    }
    out = Path(args.out)
    out.mkdir(parents=True, exist_ok=True)
    (out / "acceptance_results.json").write_text(json.dumps({"meta": meta, "results": rows}, ensure_ascii=False, indent=2), encoding="utf-8")
    (out / "ACCEPTANCE_REPORT.md").write_text(render(meta, rows), encoding="utf-8")
    (out / "WINDOWS_ACCEPTANCE_CHECKLIST.md").write_text(render_windows(rows), encoding="utf-8")
    print(json.dumps(counts, ensure_ascii=False))
    return 0 if counts.get("FAIL", 0) == 0 else 1


def _pkgs() -> dict[str, str]:
    from importlib import metadata
    out = {}
    for p in ("pytest", "duckdb", "fastapi", "uvicorn", "httpx", "pydantic", "PyYAML", "jsonschema"):
        try:
            out[p] = metadata.version(p)
        except metadata.PackageNotFoundError:
            out[p] = "N/A"
    return out


def render(meta: dict, rows: list[dict]) -> str:
    c = meta["counts"]
    L = ["# EDR — Báo cáo nghiệm thu (sinh tự động)", "",
         "> Sinh bởi `scripts/acceptance/run_acceptance.py`; **không chỉnh tay**. Trạng thái suy ra từ kết quả pytest.",
         "> Mức bằng chứng `L` = Linux + dữ liệu synthetic/giả lập, **không thay cho kiểm chứng trên Windows VM**.", "",
         "## Môi trường chạy", "",
         f"- Thời điểm (UTC): {meta['run_utc']} · thời lượng: {meta['duration_s']} s",
         f"- Commit: `{meta['commit']}`" + (" (cây làm việc có thay đổi chưa commit)" if meta["dirty"] else ""),
         f"- Python {meta['python']} · {meta['os']}",
         "- Thư viện: " + ", ".join(f"{k} {v}" for k, v in meta["packages"].items()),
         f"- Mức bằng chứng: {meta['evidence_level']}", "",
         "## Tổng hợp", "", "| Trạng thái | Số AT |", "|---|---|"]
    for s in ("PASS", "PARTIAL", "FAIL", "NOT RUN"):
        L.append(f"| {s} | {c.get(s, 0)} |")
    L += ["", "PARTIAL = test đạt nhưng catalog ghi rõ phần Expected chưa được phủ tự động.", "",
          "## Chi tiết", ""]
    for r in rows:
        L += [f"### {r['id']} · {r['req']} · mức {r['level']} · **{r['status']}**", "",
              f"- **Mục tiêu:** {r['goal']}",
              f"- **Preconditions:** {r['pre']}",
              "- **Steps:** " + "; ".join(f"{i}. {s}" for i, s in enumerate(r["steps"], 1)),
              f"- **Expected:** {r['expected']}",
              f"- **Actual:** {r['actual']}"]
        if r["tests"]:
            L.append("- **Evidence (pytest node):**")
            L += [f"  - `{t['node']}` → {t['outcome']}" for t in r["tests"]]
        if r["gaps"]:
            L.append(f"- **Chưa phủ:** {r['gaps']}")
        if r["limits"]:
            L.append(f"- **Known limitations:** {r['limits']}")
        L.append("")
    return "\n".join(L)


def render_windows(rows: list[dict]) -> str:
    L = ["# Danh sách nghiệm thu trên Windows VM (người dùng chạy — PH11-T02)", "",
         "> Sinh tự động từ `tests/acceptance/at_catalog.yaml`. Claude **không** chạy được các mục này. "
         "Người dùng chạy trên VM lab (snapshot `clean`), điền cột Actual/Status rồi gửi lại cùng đầu ra lệnh.",
         "> Chỉ điền `PASS` khi có đầu ra/ảnh chụp làm bằng chứng. Che tên máy, tên người dùng trước khi gửi.",
         "> Chạy trước: `python scripts/windows/verify_windows_env.py` và làm theo `EDR_INSTALL_GUIDE.md`.", ""]
    for r in rows:
        if r["level"] != "W":
            continue
        L += [f"## {r['id']} · {r['goal']}", "",
              f"- Preconditions: {r['pre']}",
              "- Steps:"] + [f"  {i}. {s}" for i, s in enumerate(r["steps"], 1)] + [
              f"- Expected: {r['expected']}",
              "- Actual: _(điền)_", "- Status: PASS / FAIL / NOT RUN _(chọn)_",
              "- Evidence: _(lệnh, đầu ra, ảnh chụp đã che định danh)_",
              f"- Known limitations: {r['limits'] or '—'}", ""]
    return "\n".join(L)


if __name__ == "__main__":
    sys.exit(main())
