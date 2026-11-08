"""DetectionResult -> alert / coverage gap (PH6-T02). MATCH mới tạo alert; INSUFFICIENT_TELEMETRY chỉ là khoảng hở."""
from __future__ import annotations

from typing import Dict, Iterable

BUCKET_SECONDS = 600   # cửa sổ dedup nhóm: giá trị tạm, chưa hiệu chỉnh


def _first_event(con, event_id: str):
    for t in ("silver_process_events", "silver_file_events", "silver_registry_events", "silver_network_events"):
        cur = con.execute(f"select * from {t} where event_id=?", [event_id])
        cols = [c[0] for c in cur.description]
        r = cur.fetchone()
        if r:
            return dict(zip(cols, r))
    return None


def build_from_results(store, rules: Dict[str, dict], results: Iterable, con) -> dict:
    out = {"alerts": [], "gaps": [], "suppressed": 0, "skipped": 0}
    for r in results:
        rule = rules[r.rule_id]
        ev = _first_event(con, r.contributing_event_ids[0]) if r.contributing_event_ids else None
        if r.outcome == "INSUFFICIENT_TELEMETRY":
            out["gaps"].append(store.add_gap(
                detection_dedup_key=r.dedup_key, rule_id=r.rule_id, rule_version=r.rule_version,
                hostname=ev["hostname"] if ev else None, contributing_event_ids=r.contributing_event_ids,
                missing_fields=r.missing_fields, coverage_status=r.coverage_status))
            continue
        if r.outcome != "MATCH" or ev is None:
            out["skipped"] += 1      # PENDING_LATE_EVENTS / NO_MATCH: chưa phải alert
            continue
        if store.exists_dedup(r.dedup_key):
            continue   # đã xử lý (replay-safe)
        bucket = int(ev["timestamp"].timestamp() // BUCKET_SECONDS)
        gkey = f"{r.rule_id}|{ev['hostname']}|{ev.get('process_guid')}|{bucket}"
        existing = store.find_group(gkey)
        if existing:
            store.bump(existing, ev["timestamp"], r.contributing_event_ids)
            out["suppressed"] += 1
            continue
        mitre = rule.get("mitre_technique_ids") if rule.get("mitre_basis") else None
        out["alerts"].append(store.insert_alert(
            detection_dedup_key=r.dedup_key, group_key=gkey, first_seen_utc=ev["timestamp"], last_seen_utc=ev["timestamp"],
            detection_source="IOC" if rule["type"] == "ioc" else "RULE", rule_id=r.rule_id,
            rule_version=r.rule_version, rule_name=rule["name"], severity=r.severity, severity_reason=r.severity_reason,
            mitre_technique_ids=mitre, hostname=ev["hostname"], process_guid=ev.get("process_guid"),
            image_path=ev.get("image_path"), command_line=ev.get("command_line"), user_name=ev.get("user_name"),
            contributing_event_ids=r.contributing_event_ids, matched_fields=r.matched_fields,
            missing_fields=r.missing_fields, coverage_status=r.coverage_status))
    return out
