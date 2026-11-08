"""Harness kiểm thử rule (PH4-T09). Fixture là dữ liệu SYNTHETIC có nhãn, không phải telemetry thật."""
from __future__ import annotations

import uuid
from pathlib import Path
from typing import Dict, List

import yaml

from detection.engine import DetectionEngine
from detection.ioc import IocStore
from detection.loader import load_rules
from pipeline.silver_store import SilverStore

NS = uuid.UUID("11111111-2222-3333-4444-555555555555")
FIXTURES = Path(__file__).parent / "fixtures"
TABLE = {"process": "silver_process_events", "file": "silver_file_events",
         "registry": "silver_registry_events", "network": "silver_network_events"}
COMMON = {"source": "SYSMON", "channel": "Microsoft-Windows-Sysmon/Operational", "hostname": "LABHOST",
          "process_guid": "11111111-1111-1111-1111-111111111111", "raw_data": "{}", "record_id": 1,
          "timestamp": "2026-01-01T09:00:00+00:00"}
DEFAULTS = {
    "process": {"event_type": "PROCESS_START", "sysmon_event_id": 1, "pid": 100, "image_path": "C:\\Windows\\x.exe"},
    "file": {"event_type": "FILE_CREATE", "sysmon_event_id": 11, "operation": "FILE_CREATE", "file_path": "C:\\t\\a.exe",
             "image_path": "C:\\Windows\\x.exe"},
    "registry": {"event_type": "REGISTRY_SET_VALUE", "sysmon_event_id": 13, "operation": "SetValue", "hive": "HKU",
                 "key_path": "k", "target_object": "HKU\\S\\k", "image_path": "C:\\Windows\\x.exe"},
    "network": {"event_type": "NETWORK_CONNECT", "sysmon_event_id": 3, "image_path": "C:\\Windows\\x.exe"},
}


def build_rows(fixture: dict):
    out = []
    for i, r in enumerate(fixture["rows"], 1):
        r = dict(r)
        kind = r.pop("table")
        alias = r.pop("id")
        row = {**COMMON, **DEFAULTS[kind], "record_id": i, **r}
        row["event_id"] = str(uuid.uuid5(NS, fixture["name"] + alias))
        out.append((TABLE[kind], alias, row))
    return out


def run_fixture(fixture: dict, tmp: Path, ioc: IocStore = None) -> Dict[str, List[str]]:
    st = SilverStore(tmp / (fixture["name"] + ".duckdb"))
    for table, _, row in build_rows(fixture):
        st._insert(table, row)
    eng = DetectionEngine(st.con, rules=load_rules(), ioc=ioc or IocStore())
    first = eng.run()
    again = eng.run()
    assert again == [], f"{fixture['name']}: chạy lần 2 không được phát kết quả mới"
    res: Dict[str, List[str]] = {rid: [] for rid in fixture["rules"]}
    for r in first:
        if r.rule_id in res:
            res[r.rule_id].append(r.outcome)
    st.close()
    return {k: sorted(v) for k, v in res.items()}


def load_fixtures() -> List[dict]:
    fx = []
    for p in sorted(FIXTURES.glob("*.yaml")):
        d = yaml.safe_load(p.read_text(encoding="utf-8"))
        assert d.get("synthetic") is True, f"{p.name}: fixture phải gắn synthetic: true"
        fx.append(d)
    return fx


def matrix(tmp: Path) -> List[dict]:
    rows = []
    for f in load_fixtures():
        obs = run_fixture(f, tmp)
        for rid, exp in f["expected"].items():
            rows.append({"fixture": f["name"], "rule": rid, "expected": sorted(exp),
                         "observed": obs[rid], "ok": sorted(exp) == obs[rid]})
    return rows
