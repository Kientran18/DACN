"""Báo cáo đối soát hạng mục 11 (docs/architecture/w8): kênh Windows Defender + PowerShell 4104 trên VM.

  python tests/e2e/w8_channel_report.py --silver <silver.duckdb> [--bronze <thư mục Bronze>] [--since <ISO+TZ>]
      [--out r.md] [--json r.json]

--since (ví dụ 2026-11-29T01:00:00+00:00): liệt kê riêng alert và sự kiện Defender từ thời điểm này (lần đầu bật kênh, agent
đọc cả lịch sử log nên có alert của sự kiện cũ).

CHỈ ĐỌC: làm việc trên BẢN SAO tạm của Silver (dừng core trước để sao chép được). Có --bronze thì nạp segment đã niêm
phong mà core chưa nạp vào bản sao, rồi chạy DetectionEngine + dựng alert trên bản sao.

Báo cáo KHÔNG chứa hostname, tên người dùng, SID, đường dẫn, command line, văn bản script hay tên tệp bị phát hiện. Chỉ có
số đếm, Event ID, mã lỗi, rule_id, thời điểm, nhãn nối tiến trình, TÊN TỆP ẢNH (basename, ví dụ powershell.exe) của ứng viên,
và các trường phân loại của Defender (Threat Name, Category, Action, Source, Severity).
Mọi con số là quan sát của MỘT lần chạy; không phải tỷ lệ phát hiện hay tỷ lệ FP.
"""
from __future__ import annotations

import argparse
import json
import shutil
import sys
import tempfile
from collections import Counter, defaultdict
from pathlib import Path
from typing import Dict, Optional

ROOT = Path(__file__).resolve().parents[2]
for _p in (ROOT / "src", ROOT / "src" / "pipeline", ROOT / "poc" / "sysmon-collector"):
    if str(_p) not in sys.path:
        sys.path.insert(0, str(_p))

import windows_channels as wc  # noqa: E402
from alerts.builder import build_from_results  # noqa: E402
from alerts.process_link import link_defender, link_powershell  # noqa: E402
from alerts.store import AlertStore  # noqa: E402
from detection.engine import DetectionEngine  # noqa: E402
from detection.loader import load_rules  # noqa: E402
from pipeline.silver_store import SilverStore  # noqa: E402

DEF_T, PS_T = "silver_defender_events", "silver_powershell_scriptblock_events"
NEW_RULES = ("DACN-DET-201", "DACN-DET-202", "DACN-DET-203", "DACN-DET-204")


def channel_of_segment(name: str) -> str:
    """Tên segment -> kênh. Sysmon không có tiền tố (giữ tên cũ); kênh khác: seg-<slug>-<thời điểm>-<n>.jsonl."""
    for ch in wc.CHANNEL_SOURCES:
        if not wc.is_sysmon(ch) and name.startswith(f"seg-{wc.channel_slug(ch)}-"):
            return ch
    return next(c for c in wc.CHANNEL_SOURCES if wc.is_sysmon(c))


def _basename(p) -> Optional[str]:
    return str(p).replace("/", "\\").rsplit("\\", 1)[-1].lower() if p else None


def _tables(con) -> set:
    return {r[0] for r in con.execute("select table_name from information_schema.tables").fetchall()}


def bronze_summary(bronze: Path) -> Dict:
    """Đếm bản ghi trong segment đã niêm phong theo kênh; kiểm tra `source` khớp kênh (kênh mới không được là SYSMON)."""
    per = defaultdict(lambda: {"sealed_segments": 0, "records": 0, "source_values": Counter(), "channel_mismatch": 0})
    for seg in sorted(Path(bronze).glob("seg-*.jsonl")):
        ch = channel_of_segment(seg.name)
        p = per[ch]
        p["sealed_segments"] += 1
        with seg.open(encoding="utf-8") as fh:
            for line in fh:
                if not line.strip():
                    continue
                rec = json.loads(line)
                p["records"] += 1
                p["source_values"][str(rec.get("source"))] += 1
                if wc.canonical_channel(str(rec.get("channel", ""))) != ch:
                    p["channel_mismatch"] += 1
    open_parts = len(list(Path(bronze).glob("seg-*.jsonl.part")))
    out = {ch: {**v, "source_values": dict(v["source_values"])} for ch, v in per.items()}
    return {"channels": out, "open_part_files": open_parts}


def ledger_summary(con) -> Dict:
    per = defaultdict(lambda: Counter())
    for seg, status, read, ins, dup, quar in con.execute(
            "select segment, status, records_read, inserted, duplicates, quarantined from _ingest_ledger").fetchall():
        c = per[channel_of_segment(seg)]
        c["segments_" + str(status)] += 1
        c["records_read"] += read or 0
        c["inserted"] += ins or 0
        c["duplicates"] += dup or 0
        c["quarantined"] += quar or 0
    out = {}
    for ch, c in per.items():
        d = dict(c)
        d["balanced"] = c["records_read"] == c["inserted"] + c["duplicates"] + c["quarantined"]
        out[ch] = d
    return out


def silver_summary(con) -> Dict:
    have = _tables(con)
    out: Dict = {"defender_by_event_id": {}, "powershell": None}
    if DEF_T in have:
        out["defender_by_event_id"] = {str(k): v for k, v in con.execute(
            f"select windows_event_id, count(*) from {DEF_T} group by 1 order by 1").fetchall()}
        out["defender_resource_types"] = {str(k): v for k, v in con.execute(
            f"select coalesce(resource_type, '(không có tiền tố)'), count(*) from {DEF_T} group by 1 order by 1").fetchall()}
    if PS_T in have:
        rows, blocks, multi = con.execute(
            f"select count(*), count(distinct (hostname, script_block_id)), "
            f"count(distinct (hostname, script_block_id)) filter (where message_total > 1) from {PS_T}").fetchone()
        complete = con.execute("select count(*) from v_powershell_scriptblocks_complete").fetchone()[0] \
            if "v_powershell_scriptblocks_complete" in have else None
        levels = {str(k): v for k, v in con.execute(f"select level, count(*) from {PS_T} group by 1 order by 1").fetchall()}
        out["powershell"] = {"rows_4104": rows, "script_blocks": blocks, "multi_part_blocks": multi,
                             "complete_blocks_view": complete, "rows_by_level": levels,
                             "max_part_chars": con.execute(f"select max(length(script_block_text)) from {PS_T}").fetchone()[0]}
    out["dlq_by_error_code"] = {k: v for k, v in con.execute(
        "select error_code, count(*) from silver_quarantine_dlq group by 1 order by 2 desc").fetchall()}
    return out


def alert_summary(con) -> Dict:
    have = _tables(con)
    if "alerts" not in have:
        return {"alerts": []}
    rows = con.execute("select rule_id, detection_source, severity, count(*) from alerts group by 1, 2, 3 order by 1, 3").fetchall()
    out = {"alerts": [{"rule_id": r, "detection_source": s, "severity": sev, "count": n} for r, s, sev, n in rows]}
    out["new_rule_alerts_total"] = sum(n for r, _, _, n in rows if r in NEW_RULES)
    out["alerts_with_process_guid_new_rules"] = con.execute(
        "select count(*) from alerts where rule_id in (?, ?, ?, ?) and process_guid is not null", list(NEW_RULES)).fetchone()[0]
    if "response_actions" in have:
        out["response_actions"] = {f"{m}/{s}": n for m, s, n in con.execute(
            "select requested_mode, status, count(*) from response_actions group by 1, 2").fetchall()}
    if "audit_log" in have:
        out["audit_raw_views"] = {a: n for a, n in con.execute(
            "select action, count(*) from audit_log where action in ('SCRIPT_RAW_VIEW', 'EVIDENCE_RAW_VIEW') group by 1").fetchall()}
    return out


def since_summary(con, since: str) -> Dict:
    """Alert và sự kiện Defender có thời điểm >= since (thời điểm sự kiện, không phải lúc nạp)."""
    have = _tables(con)
    out: Dict = {"since": since, "alerts": [], "defender_events": []}
    if "alerts" in have:
        out["alerts"] = [{"rule_id": r, "severity": sev, "detection_source": s, "first_seen_utc": f, "events": n}
                         for r, sev, s, f, n in con.execute(
                             "select rule_id, severity, detection_source, first_seen_utc, len(contributing_event_ids) "
                             "from alerts where first_seen_utc >= ?::timestamptz order by first_seen_utc limit 200",
                             [since]).fetchall()]
    if DEF_T in have:
        out["defender_events"] = [dict(zip(("timestamp", "windows_event_id", "threat_name", "category_name", "severity_name",
                                            "action_name", "source_name", "resource_type"), r)) for r in con.execute(
            f"select timestamp, windows_event_id, threat_name, category_name, severity_name, action_name, source_name, "
            f"resource_type from {DEF_T} where timestamp >= ?::timestamptz order by timestamp limit 200", [since]).fetchall()]
    if PS_T in have:
        out["powershell_rows"] = con.execute(f"select count(*) from {PS_T} where timestamp >= ?::timestamptz", [since]).fetchone()[0]
    return out


def link_summary(con) -> Dict:
    """Nhãn nối tiến trình cho MỌI sự kiện 4104 (một lần mỗi block+PID) và Defender 1116/1117. Kiểm tra giả định
    'PID của 4104 là powershell.exe': với block UNIQUE, ảnh ứng viên phải là ảnh PowerShell."""
    have = _tables(con)
    out: Dict = {}
    if PS_T in have:
        conf, images, no_ps_proc = Counter(), Counter(), 0
        rows = con.execute(f"select hostname, script_block_id, writer_process_id, min(timestamp) from {PS_T} "
                           f"group by 1, 2, 3").fetchall()
        for host, _sbid, pid, ts in rows:
            link = link_powershell(con, {"hostname": host, "writer_process_id": pid, "timestamp": ts})
            conf[link["confidence"]] += 1
            for c in link["candidates"]:
                images[_basename(c["image_path"])] += 1
            if link["confidence"] == "NONE" and pid is not None:
                # PID có Event 1 với ảnh KHÁC PowerShell trong 24 giờ? -> bác bỏ giả định PID = powershell.exe
                other = con.execute(
                    "select count(*) from silver_process_events where hostname = ? and sysmon_event_id = 1 and pid = ? "
                    "and timestamp <= ? and timestamp >= ? - interval 24 hour", [host, pid, ts, ts]).fetchone()[0]
                no_ps_proc += bool(other)
        out["powershell_blocks"] = {"total": len(rows), "by_confidence": dict(conf), "candidate_images": dict(images),
                                    "none_but_pid_has_other_image": no_ps_proc}
    if DEF_T in have:
        by = Counter()
        cur = con.execute(f"select * from {DEF_T} where windows_event_id in (1116, 1117)")
        cols = [c[0] for c in cur.description]
        for r in cur.fetchall():
            for link in link_defender(con, dict(zip(cols, r))):
                by[f"{link['method']}:{link['confidence']}"] += 1
        out["defender_1116_1117"] = dict(by)
    return out


def build_report(silver: Path, bronze: Optional[Path] = None, since: Optional[str] = None) -> Dict:
    silver = Path(silver)
    if not silver.exists():
        raise FileNotFoundError(f"không thấy Silver: {silver}")
    rep: Dict = {"kind": "W8_CHANNEL_REPORT", "note": "Quan sát một lần chạy; không phải tỷ lệ phát hiện/FP. Không chứa định danh."}
    if bronze:
        rep["bronze"] = bronze_summary(Path(bronze))
    with tempfile.TemporaryDirectory(prefix="dacn_w8_") as tmp:
        try:
            for src in (silver, silver.with_name(silver.name + ".wal")):
                if src.exists():
                    shutil.copy2(src, Path(tmp) / src.name)
        except OSError as exc:
            raise RuntimeError("không sao chép được Silver (core còn đang chạy?): dừng core rồi chạy lại") from exc
        st = SilverStore(Path(tmp) / silver.name)
        try:
            rep["alerts_in_core_db"] = alert_summary(st.con)
            if bronze:
                newly = st.ingest_dir(Path(bronze), run_id="w8_channel_report")
                rep["segments_ingested_by_report"] = sum(1 for r in newly if r.get("status") == "INGESTED")
                rules = load_rules()
                build_from_results(AlertStore(st.con), rules, DetectionEngine(st.con, rules=rules).run(), st.con)
                rep["alerts_after_report_ingest"] = alert_summary(st.con)
            rep["ledger"] = ledger_summary(st.con)
            rep["silver"] = silver_summary(st.con)
            rep["process_links"] = link_summary(st.con)
            if since:
                rep["since"] = since_summary(st.con, since)
        finally:
            st.close()
    return rep


def to_markdown(rep: Dict) -> str:
    out = ["# Báo cáo đối soát kênh Defender/PowerShell (hạng mục 11)", "", f"> {rep['note']}", ""]
    for key in ("bronze", "segments_ingested_by_report", "ledger", "silver", "alerts_in_core_db",
                "alerts_after_report_ingest", "process_links", "since"):
        if key in rep:
            out += [f"## {key}", "", "```json", json.dumps(rep[key], ensure_ascii=False, indent=2, default=str), "```", ""]
    return "\n".join(out)


def main(argv=None) -> int:
    ap = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    ap.add_argument("--silver", required=True)
    ap.add_argument("--bronze")
    ap.add_argument("--since", help="ISO 8601 có múi giờ, ví dụ 2026-11-29T01:00:00+00:00")
    ap.add_argument("--out")
    ap.add_argument("--json")
    a = ap.parse_args(argv)
    rep = build_report(Path(a.silver), Path(a.bronze) if a.bronze else None, a.since)
    md = to_markdown(rep)
    if a.out:
        Path(a.out).write_text(md, encoding="utf-8")
    if a.json:
        Path(a.json).write_text(json.dumps(rep, ensure_ascii=False, indent=2, default=str), encoding="utf-8")
    if not a.out:
        sys.stdout.write(md)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
