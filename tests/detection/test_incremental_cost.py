"""Chi phí detection không được tăng theo lịch sử: vòng thứ hai chỉ xử lý sự kiện mới."""
import sys
import time
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
import harness  # noqa: E402

from detection.engine import DetectionEngine  # noqa: E402
from detection.loader import load_rules  # noqa: E402
from pipeline.silver_store import SilverStore  # noqa: E402

N = 50_000


def test_second_cycle_over_50k_history_is_fast_and_sees_only_new_rows(tmp_path):
    st = SilverStore(tmp_path / "s.duckdb")
    st.con.execute(
        "insert into silver_process_events (event_id, timestamp, event_type, sysmon_event_id, channel, record_id, hostname,"
        " process_guid, raw_data, pid, image_path, command_line) select uuid()::varchar,"
        " TIMESTAMPTZ '2026-01-01 00:00:00+00' + to_seconds(i), 'PROCESS_START', 1, 'ch', i, 'H', uuid()::varchar, '{}', i,"
        " 'C:/Windows/x.exe', 'x.exe' from range(?) t(i)", [N])
    eng = DetectionEngine(st.con, rules=load_rules())
    eng.run()                                                   # lần đầu: quét toàn bộ lịch sử
    fx = {"name": "inc", "rows": [{"id": "p", "table": "process", "image_path": r"C:\a\powershell.exe",
                                   "command_line": "powershell.exe -enc AAAAAAAA", "timestamp": "2026-01-02T00:00:00+00:00",
                                   "record_id": N + 1}]}
    for t, _, row in harness.build_rows(fx):
        st._insert(t, row)
    t0 = time.monotonic()
    out = eng.run()
    dt = time.monotonic() - t0
    assert [r.rule_id for r in out if r.outcome == "MATCH"] == ["DACN-DET-001"]
    assert dt < 1.0, f"vòng thứ hai mất {dt:.2f}s trên {N} hàng lịch sử"
    assert eng.run() == []                                      # không có gì mới thì không đánh giá gì
