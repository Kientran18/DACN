"""K1 (audit): bảng EXPECTED của contract_check phải khớp cột THẬT trong DDL v1.1 (nguồn sự thật), không tự khai.
 in_silver          -> cột đích có trong bảng Silver của loại sự kiện đó
 missing_in_silver  -> cột đích KHÔNG có trong bảng đó
 no_target          -> loại sự kiện không được định tuyến vào bảng Silver nào (Sysmon 4, 16)"""
import re
from pathlib import Path

import pytest

import contract_check as cc
from detection.schema import SILVER_TABLE_FOR_EVENT   # cùng bảng định tuyến với validator (SUPPORTED_SYSMON_IDS)

DDL = Path(__file__).resolve().parents[2] / "src" / "pipeline" / "sql" / "silver_gold_schema_and_views_v1_1.sql"


def silver_columns():
    text = DDL.read_text(encoding="utf-8")
    out = {}
    for m in re.finditer(r"CREATE TABLE IF NOT EXISTS (\w+)\s*\((.*?)\n\);", text, re.S):
        out[m.group(1)] = {ln.split()[0] for ln in m.group(2).splitlines()
                           if ln.strip() and not ln.strip().startswith(("--", "PRIMARY", "CONSTRAINT", "UNIQUE", "CHECK", "FOREIGN"))}
    return out


COLS = silver_columns()
CASES = [(eid, field, target, status) for eid, m in cc.EXPECTED.items() for field, (target, status) in m.items()
         if not target.startswith("(") or status == "no_target"]


@pytest.mark.parametrize("eid,field,target,status", CASES, ids=[f"{e}-{f}" for e, f, _, _ in CASES])
def test_expected_status_matches_ddl(eid, field, target, status):
    table = SILVER_TABLE_FOR_EVENT.get(eid)
    if status == "no_target":
        assert table is None, f"Event {eid} đã có bảng {table}: không thể là no_target"
        return
    assert table is not None, f"Event {eid} không có bảng Silver nhưng ghi {status}"
    has = target in COLS[table]
    assert has == (status == "in_silver"), f"Event {eid} {field}->{table}.{target}: ghi {status}, DDL v1.1 {'có' if has else 'không có'} cột"
