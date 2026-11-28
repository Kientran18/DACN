"""Nạp theo lô và chia ngân sách thời gian (sửa lỗi hiệu năng quan sát trên Windows 10 VM ngày 2026-11-28: ~0,42 s/bản ghi,
một vòng core 1.962 s nên Detection không chạy). Dữ liệu SYNTHETIC. Ngữ nghĩa dedup/va chạm/DLQ phải giữ nguyên."""
import os
import sys
from pathlib import Path

import bronze_contract as bc
from agent.bronze_writer import BronzeWriter
from pipeline.silver_store import SilverStore

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "e2e"))
import scenario_xml as sx  # noqa: E402

SYN = Path(__file__).resolve().parents[2] / "poc/sysmon-collector/configs/synthetic_events.xml"


def xml_many(n, start=1):
    out = []
    for r in range(start, start + n):
        ts = f"2026-11-28T08:{(r // 60) % 60:02d}:{r % 60:02d}.000Z"
        x = sx.filecreate(ts, f"f{r}", f"C:\\tmp\\f{r}.txt") if r % 2 else sx.regset(ts, f"HKLM\\SOFTWARE\\k{r}", "DWORD (0x1)")
        out.append(x.replace(x[x.index("<EventRecordID>"):x.index("</EventRecordID>")], f"<EventRecordID>{r}"))
    return out


def make_seg(d, xmls):
    w = BronzeWriter(d)
    for i, x in enumerate(xmls):
        w.append(bc.build_bronze_record(x, mode="file", seq=i))
    return w.seal()


class CountingCon:
    def __init__(self, con):
        self._con, self.n = con, 0

    def execute(self, *a, **k):
        self.n += 1
        return self._con.execute(*a, **k)

    def __getattr__(self, name):
        return getattr(self._con, name)


def statements(tmp_path, n):
    st = SilverStore(tmp_path / f"s{n}.duckdb")
    seg = make_seg(tmp_path / f"b{n}", xml_many(n))
    st.con = CountingCon(st.con)
    res = st.ingest_segment(seg, "r")
    assert res["inserted"] == n
    return st.con.n


def test_statement_count_does_not_grow_with_records(tmp_path):
    # trước khi sửa: ~2 lệnh DuckDB mỗi bản ghi (INSERT + lineage); trên VM mỗi lệnh ~0,3 s
    small, big = statements(tmp_path, 10), statements(tmp_path, 400)
    assert big <= small + 12, (small, big)


def test_rows_and_lineage_match_per_record_semantics(tmp_path):
    xmls = xml_many(300)
    st = SilverStore(tmp_path / "s.duckdb")
    res = st.ingest_segment(make_seg(tmp_path / "a", xmls), "r1")
    assert res == {"read": 300, "inserted": 300, "duplicates": 0, "quarantined": 0, "status": "INGESTED"}
    n_rows = sum(st.con.execute(f"select count(*) from {t}").fetchone()[0]
                 for t in ("silver_file_events", "silver_registry_events"))
    assert n_rows == 300 == st.con.execute("select count(*) from silver_event_lineage").fetchone()[0]
    seg, line = st.con.execute("select bronze_segment, bronze_line_no from silver_event_lineage order by bronze_line_no limit 1").fetchone()
    assert seg.startswith("seg-") and line == 1


def test_duplicate_and_collision_inside_one_segment(tmp_path):
    xmls = list(bc.iter_raw_xml_from_file(SYN))
    forged = xmls[0].replace("</Event>", "<!--log-reset--></Event>")
    st = SilverStore(tmp_path / "s.duckdb")
    res = st.ingest_segment(make_seg(tmp_path / "a", xmls + [xmls[0], forged]), "r1")
    # bản sao y hệt trong cùng segment = duplicate; cùng event_id nhưng raw khác = va chạm (DLQ), không ghi đè
    assert res["read"] == len(xmls) + 2 and res["inserted"] == len(xmls)
    assert res["duplicates"] == 1 and res["quarantined"] == 1
    assert st.con.execute("select error_code from silver_quarantine_dlq").fetchall() == [("ERR_EVENT_ID_COLLISION",)]


def test_mixed_channels_in_batches(tmp_path):
    fix = Path(__file__).resolve().parents[1] / "fixtures/windows_channels"
    xmls = [x for n in ("defender_1116.synthetic.xml", "ps4104_three_parts.synthetic.xml")
            for x in bc.iter_raw_xml_from_file(fix / n)] + xml_many(5)
    st = SilverStore(tmp_path / "s.duckdb")
    res = st.ingest_segment(make_seg(tmp_path / "a", xmls), "r1")
    assert res["inserted"] == len(xmls) and res["quarantined"] == 0
    assert st.con.execute("select count(*) from silver_powershell_scriptblock_events").fetchone()[0] == 3


def test_ingest_dir_oldest_sealed_first_and_time_budget(tmp_path, monkeypatch):
    bdir = tmp_path / "b"
    a = make_seg(bdir, xml_many(3, 1))
    b = make_seg(bdir, xml_many(3, 100))
    ps = BronzeWriter(bdir, name_prefix="microsoft_windows_powershell_operational-")
    for x in bc.iter_raw_xml_from_file(Path(__file__).resolve().parents[1] / "fixtures/windows_channels/ps4104_single.synthetic.xml"):
        ps.append(bc.build_bronze_record(x, mode="file"))
    p = ps.seal()
    # niêm phong: PowerShell trước nhất, rồi a, rồi b. Tên tệp xếp ngược (seg-2026... < seg-microsoft...)
    for i, s in enumerate((p, a, b)):
        os.utime(s, (1_000_000 + i, 1_000_000 + i))
    st = SilverStore(tmp_path / "s.duckdb")
    clock = iter([0.0, 10.0])
    monkeypatch.setattr("pipeline.silver_store.time.monotonic", lambda: next(clock, 10.0))
    first = st.ingest_dir(bdir, "r", max_seconds=5)
    assert [r["segment"] for r in first] == [p.name]               # hết ngân sách sau segment đầu, nhưng luôn nạp >= 1
    rest = st.ingest_dir(bdir, "r")
    assert [r["segment"] for r in rest] == [a.name, b.name]
