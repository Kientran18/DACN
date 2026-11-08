"""Chỉ số chất lượng đo từ dữ liệu thật của lần chạy (PH3-T08). Không đặt SLO 'đạt'."""
from __future__ import annotations


def quality_metrics(con) -> dict:
    led = con.execute("select coalesce(sum(records_read),0), coalesce(sum(inserted),0),"
                      " coalesce(sum(duplicates),0), coalesce(sum(quarantined),0) from _ingest_ledger").fetchone()
    read, ins, dup, quar = (int(x) for x in led)
    seg_q = con.execute("select count(*) from _ingest_ledger where status='QUARANTINED_SEGMENT'").fetchone()[0]
    return {"records_read": read, "inserted": ins, "duplicates": dup, "quarantined": quar,
            "segments_quarantined": seg_q,
            "quarantine_ratio": round(quar / read, 6) if read else None,
            "uniqueness_ratio": round(ins / (ins + dup), 6) if (ins + dup) else None,
            "accounting_balanced": read == ins + dup + quar,
            "note": "chỉ số đo trên dữ liệu đã nạp; chưa có SLO"}
