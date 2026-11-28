"""Gom thành phần rủi ro theo chủ thể (process_guid hoặc host trong cửa sổ thời gian dữ liệu) và chấm điểm.

CHỈ ĐỌC: không ghi DB, không tạo alert, không gọi response. Tính lại mỗi lần truy vấn (không lưu điểm, nên điểm
không cũ đi khi alert đổi trạng thái hay allowlist đổi). Chi phí tăng theo số alert: đủ cho MVP một endpoint,
hiệu năng chưa đo trên VM.

Nguồn:
- alerts (v1.2 đề xuất): RULE / CORRELATION (rule type correlation) / IOC / STATIC (DACN-STATIC-001) /
  EXTERNAL_AV (detection_source EXTERNAL_*, ví dụ Defender DACN-DET-201/202; không có process_guid nên chỉ vào chủ thể host)
- _ml_signals (nếu bảng tồn tại): ML_STATIC / ML_BEHAVIOR; INSUFFICIENT_TELEMETRY chỉ vào `not_evaluated`
- coverage_gaps: chỉ liệt kê ở `data_gaps`, KHÔNG cộng điểm (thiếu dữ liệu không phải bằng chứng đe dọa)
- allowlist hash cục bộ (IocStore) theo file_sha256 của Event 1 của tiến trình; trạng thái candidate static."""
from __future__ import annotations

import json
from datetime import datetime, timedelta
from typing import Dict, List, Mapping, Optional

from .config import LEVELS, ML_CATEGORIES, RiskConfig
from .scoring import Component, score_components

STATIC_RULE_ID = "DACN-STATIC-001"
_SILVER = ("silver_process_events", "silver_file_events", "silver_registry_events", "silver_network_events")
_EXCLUDED_ALERT = {"FALSE_POSITIVE": "analyst đã đánh dấu alert là FALSE_POSITIVE"}
_EXCLUDED_CANDIDATE = {"ALLOWLISTED": "candidate static đã được duyệt ALLOWLISTED",
                       "REJECTED": "candidate static đã bị REJECTED khi duyệt"}


def _iso(v):
    return v.isoformat() if hasattr(v, "isoformat") else v


class RiskService:
    def __init__(self, con, rules: Dict[str, dict], cfg: RiskConfig, *, ioc=None,
                 ml_enabled: Optional[Mapping[str, bool]] = None):
        self.con, self.rules, self.cfg, self.ioc = con, rules, cfg, ioc
        self.ml_enabled = {k: bool((ml_enabled or {}).get(k, False)) for k in ML_CATEGORIES}

    # -- truy vấn -------------------------------------------------------------------------
    def _table_exists(self, name: str) -> bool:
        return bool(self.con.execute("select 1 from information_schema.tables where table_name=?", [name]).fetchone())

    def _rows(self, sql: str, params=()) -> List[dict]:
        cur = self.con.execute(sql, list(params))
        cols = [c[0] for c in cur.description]
        return [dict(zip(cols, r)) for r in cur.fetchall()]

    def _alerts(self, hostname=None, guid=None) -> List[dict]:
        sql, p, cond = ("select alert_id, rule_id, rule_version, rule_name, detection_source, severity, status, hostname,"
                        " process_guid, last_seen_utc, matched_fields, coverage_status from alerts"), [], []
        if hostname is not None:
            cond.append("hostname=?"); p.append(hostname)
        if guid is not None:
            cond.append("process_guid=?"); p.append(guid)
        return self._rows(sql + (" where " + " and ".join(cond) if cond else ""), p)

    def _signals(self, hostname=None, guid=None) -> List[dict]:
        if not self._table_exists("_ml_signals"):
            return []
        sql, p, cond = "select * from _ml_signals", [], []
        if hostname is not None:
            cond.append("hostname=?"); p.append(hostname)
        if guid is not None:
            cond.append("process_guid=?"); p.append(guid)
        return self._rows(sql + (" where " + " and ".join(cond) if cond else ""), p)

    def _candidate_states(self) -> Dict[str, str]:
        if not self._table_exists("static_candidates"):
            return {}
        out = {}
        for state, ids in self.con.execute("select state, alert_ids from static_candidates").fetchall():
            for aid in json.loads(ids or "[]"):
                out[aid] = state
        return out

    def _allowlisted_guids(self, guids) -> Dict[str, str]:
        if not self.ioc or not getattr(self.ioc, "allow", None) or not guids:
            return {}
        rows = self.con.execute("select distinct process_guid, lower(file_sha256) from silver_process_events "
                                "where list_contains(?, process_guid) and file_sha256 is not null", [list(guids)]).fetchall()
        return {g: f"hash ảnh tiến trình ({h[:12]}…) nằm trong allowlist cục bộ" for g, h in rows if h in self.ioc.allow}

    def _event_index(self, event_ids) -> Dict[str, tuple]:
        if not event_ids:
            return {}
        out = {}
        for t in _SILVER:
            for eid, host, guid, ts in self.con.execute(
                    f"select event_id, hostname, process_guid, timestamp from {t} where list_contains(?, event_id)",
                    [list(event_ids)]).fetchall():
                out[eid] = (host, guid, ts)
        return out

    def _gaps(self, hostname) -> List[dict]:
        rows = self._rows("select gap_id, rule_id, rule_version, hostname, contributing_event_ids, missing_fields, "
                          "coverage_status from coverage_gaps" + (" where hostname=?" if hostname else ""),
                          [hostname] if hostname else [])
        idx = self._event_index({e for r in rows for e in (r["contributing_event_ids"] or [])})
        for r in rows:
            r["missing_fields"] = json.loads(r["missing_fields"]) if isinstance(r["missing_fields"], str) else r["missing_fields"]
            evs = [idx[e] for e in (r["contributing_event_ids"] or []) if e in idx]
            r["process_guids"] = sorted({e[1] for e in evs if e[1]})
            r["observed_at"] = max((e[2] for e in evs), default=None)
        return rows

    # -- dựng thành phần --------------------------------------------------------------------
    def _category(self, a: dict) -> str:
        if a["rule_id"] == STATIC_RULE_ID:
            return "STATIC"
        if (a["detection_source"] or "").startswith("EXTERNAL_"):
            return "EXTERNAL_AV"
        if a["detection_source"] == "SIGMA" or (self.rules.get(a["rule_id"]) or {}).get("type") == "sigma":
            return "SIGMA"
        if a["detection_source"] == "IOC" or (self.rules.get(a["rule_id"]) or {}).get("type") == "ioc":
            return "IOC"
        if (self.rules.get(a["rule_id"]) or {}).get("type") == "correlation":
            return "CORRELATION"
        return "RULE"

    def _build(self, alerts: List[dict], signals: List[dict]):
        cand = self._candidate_states() if any(a["rule_id"] == STATIC_RULE_ID for a in alerts) else {}
        allow = self._allowlisted_guids({a["process_guid"] for a in alerts if a["process_guid"]}
                                        | {s["process_guid"] for s in signals if s["process_guid"]})
        comps, insufficient = [], []
        for a in alerts:
            cat = self._category(a)
            excl = _EXCLUDED_ALERT.get(a["status"], "")
            if not excl and cat == "STATIC":
                excl = _EXCLUDED_CANDIDATE.get(cand.get(a["alert_id"]), "")
            comps.append(Component(category=cat, ref_type="alert", ref_id=a["alert_id"],
                                   label=f"{a['rule_id']} v{a['rule_version']} {a['rule_name']}", severity=a["severity"],
                                   included=not excl, exclude_reason=excl,
                                   allowlist_reason=allow.get(a["process_guid"], ""), observed_at=a["last_seen_utc"],
                                   hostname=a["hostname"], process_guid=a["process_guid"],
                                   details={"status": a["status"], "coverage_status": a["coverage_status"]}))
        for s in signals:
            if s["detector"] not in ML_CATEGORIES or not self.ml_enabled[s["detector"]]:
                continue        # detector đang tắt: tín hiệu cũ (nếu có) không được tính
            if s["status"] != "SCORED":
                insufficient.append({"source": s["detector"], "reason": s["reason"], "signal_id": s["signal_id"]})
                continue
            expl = json.loads(s["explanation"]) if isinstance(s["explanation"], str) else (s["explanation"] or {})
            comps.append(Component(category=s["detector"], ref_type="ml_signal", ref_id=s["signal_id"],
                                   label=f"{s['detector']} model {s['model_version']}", ml_score=s["score"],
                                   allowlist_reason=allow.get(s["process_guid"], ""), observed_at=s["observed_at_utc"],
                                   hostname=s["hostname"], process_guid=s["process_guid"],
                                   details={"model_version": s["model_version"],
                                            "feature_schema_version": s["feature_schema_version"],
                                            "source_event_ids": list(s["source_event_ids"] or []), "explanation": expl}))
        return comps, insufficient

    def _not_evaluated(self, comps, insufficient) -> List[dict]:
        out = []
        for det in ML_CATEGORIES:
            if not self.ml_enabled[det]:
                out.append({"source": det, "reason": "DISABLED (tắt mặc định trong cấu hình ML)"})
            elif not any(c.category == det for c in comps) and not any(x["source"] == det for x in insufficient):
                out.append({"source": det, "reason": "NOT_SCORED (chưa có tín hiệu cho chủ thể này: chưa chấm hoặc ngoài phạm vi detector)"})
        return out + insufficient

    @staticmethod
    def _gap_out(g) -> dict:
        return {"gap_id": g["gap_id"], "rule_id": g["rule_id"], "rule_version": g["rule_version"],
                "missing_fields": g["missing_fields"], "coverage_status": g["coverage_status"],
                "observed_at": _iso(g["observed_at"])}

    # -- chủ thể ------------------------------------------------------------------------------
    def process(self, hostname: str, process_guid: str) -> dict:
        comps, insuf = self._build(self._alerts(hostname, process_guid), self._signals(hostname, process_guid))
        gaps = [self._gap_out(g) for g in self._gaps(hostname) if process_guid in g["process_guids"]]
        out = score_components(comps, self.cfg, not_evaluated=self._not_evaluated(comps, insuf), data_gaps=gaps)
        out["subject"] = {"kind": "process", "hostname": hostname, "process_guid": process_guid}
        return out

    def host(self, hostname: str, until: Optional[datetime] = None) -> dict:
        win = timedelta(seconds=self.cfg.data["host_window_seconds"])
        alerts, signals = self._alerts(hostname), self._signals(hostname)
        times = [a["last_seen_utc"] for a in alerts] + [s["observed_at_utc"] for s in signals if s["observed_at_utc"]]
        end = until or (max(times) if times else None)
        inside = (lambda t: t is not None and end - win <= t <= end) if end else (lambda t: False)
        comps, insuf = self._build([a for a in alerts if inside(a["last_seen_utc"])],
                                   [s for s in signals if inside(s["observed_at_utc"])])
        gaps = [self._gap_out(g) for g in self._gaps(hostname) if inside(g["observed_at"])]
        out = score_components(comps, self.cfg, not_evaluated=self._not_evaluated(comps, insuf), data_gaps=gaps)
        out["subject"] = {"kind": "host", "hostname": hostname, "window_end": _iso(end),
                          "window_start": _iso(end - win) if end else None,
                          "window_seconds": self.cfg.data["host_window_seconds"],
                          "window_basis": "thời gian dữ liệu (last_seen_utc / observed_at_utc), không theo đồng hồ máy"}
        return out

    def subjects(self, kind: str, *, min_level: Optional[str] = None, limit: int = 100, offset: int = 0) -> List[dict]:
        if kind == "process":
            keys = {(a["hostname"], a["process_guid"]) for a in self._alerts() if a["process_guid"]}
            keys |= {(s["hostname"], s["process_guid"]) for s in self._signals() if s["process_guid"] and s["hostname"]}
            items = [self.process(h, g) for h, g in keys]
        elif kind == "host":
            hosts = {a["hostname"] for a in self._alerts()} | {s["hostname"] for s in self._signals() if s["hostname"]}
            items = [self.host(h) for h in hosts]
        else:
            raise ValueError("kind phải là process hoặc host")
        if min_level:
            if min_level not in LEVELS:
                raise ValueError("min_level không hợp lệ")
            items = [i for i in items if i["level"] in LEVELS[LEVELS.index(min_level):]]
        latest = lambda i: max((c["observed_at"] or "" for c in i["components"]), default="")  # noqa: E731
        items.sort(key=lambda i: (-i["score"], -(datetime.fromisoformat(latest(i)).timestamp() if latest(i) else 0.0),
                                  json.dumps(i["subject"], sort_keys=True)))
        return items[max(offset, 0):max(offset, 0) + min(max(limit, 1), 500)]

    def for_alert(self, alert_id: str) -> Optional[dict]:
        row = self.con.execute("select hostname, process_guid, last_seen_utc from alerts where alert_id=?",
                               [alert_id]).fetchone()
        if row is None:
            return None
        return self.process(row[0], row[1]) if row[1] else self.host(row[0], until=row[2])
