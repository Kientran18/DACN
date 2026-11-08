"""DACN-DET-010: tạo tệp (11) -> chạy tệp (1) -> xóa tệp (23/26), cùng host + đường dẫn chuẩn hóa."""
from __future__ import annotations

from datetime import timedelta
from typing import List

from .paths import normalize_path
from .result import DetectionResult, make_dedup_key


def evaluate_drop_execute_delete(rule: dict, files: List[dict], procs: List[dict], watermark) -> List[DetectionResult]:
    """files: hàng silver_file_events (11/23/26); procs: hàng silver_process_events (Event 1).
    watermark: timestamp lớn nhất đã nạp (mốc đóng cửa sổ)."""
    rid, ver = rule["rule_id"], rule["rule_version"]
    win = timedelta(seconds=rule["time_window_seconds"])
    out: List[DetectionResult] = []
    deletes = [f for f in files if f["sysmon_event_id"] in (23, 26)]
    for c in sorted((f for f in files if f["sysmon_event_id"] == 11), key=lambda r: r["timestamp"]):
        npath = normalize_path(c["file_path"])
        subject = c["event_id"]
        base = dict(rule_id=rid, rule_version=ver, subject=subject,
                    dedup_key=make_dedup_key(rid, ver, subject, str(rule["time_window_seconds"])))
        if npath is None:
            out.append(DetectionResult(outcome="INSUFFICIENT_TELEMETRY", contributing_event_ids=[c["event_id"]],
                                       missing_fields=["normalized_path"], coverage_status="PATH_NOT_NORMALIZABLE",
                                       severity_reason="đường dẫn không chuẩn hóa chắc chắn", **base))
            continue
        t0 = c["timestamp"]
        execs = [p for p in procs if p["hostname"] == c["hostname"] and p["sysmon_event_id"] == 1
                 and normalize_path(p["image_path"]) == npath and t0 <= p["timestamp"] <= t0 + win]
        if not execs:
            continue  # chưa có bước chạy: không tạo kết quả (tránh nhiễu)
        e = min(execs, key=lambda r: r["timestamp"])
        dels = [d for d in deletes if d["hostname"] == c["hostname"] and normalize_path(d["file_path"]) == npath
                and e["timestamp"] <= d["timestamp"] <= t0 + win]
        steps = {"create": c["event_id"], "execute": e["event_id"]}
        if dels:
            d = min(dels, key=lambda r: r["timestamp"])
            steps["delete"] = d["event_id"]
            out.append(DetectionResult(outcome="MATCH", contributing_event_ids=list(steps.values()),
                                       matched_fields={"normalized_path": npath, **steps},
                                       severity=rule["severity"], severity_reason=rule["severity_reason"],
                                       notes=["window_status:" + rule["window_status"]], **base))
        elif watermark is not None and watermark < t0 + win:
            out.append(DetectionResult(outcome="PENDING_LATE_EVENTS", contributing_event_ids=list(steps.values()),
                                       matched_fields={"normalized_path": npath, **steps},
                                       coverage_status="PARTIAL_CHAIN", severity_reason="cửa sổ chưa đóng",
                                       notes=["window_status:" + rule["window_status"]], **base))
        else:
            out.append(DetectionResult(outcome="NO_MATCH", contributing_event_ids=list(steps.values()),
                                       matched_fields={"normalized_path": npath, **steps},
                                       coverage_status="PARTIAL_CHAIN",
                                       severity_reason="thiếu bước xóa trong cửa sổ đã đóng",
                                       notes=["window_status:" + rule["window_status"]], **base))
    return out
