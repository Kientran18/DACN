"""Màn hình cây tiến trình (điều tra): truy vấn chỉ đọc theo (hostname, process_guid). Dữ liệu SYNTHETIC."""
import sys
from datetime import datetime, timezone
from pathlib import Path

import pytest

HERE = Path(__file__).resolve().parent
sys.path.insert(0, str(HERE.parent / "detection"))
import harness  # noqa: E402

from alerts.process_view import process_events, process_tree_view, search_processes  # noqa: E402
from alerts.store import AlertStore  # noqa: E402
from pipeline.silver_store import SilverStore  # noqa: E402

H = "LAB-HOST-01"
OTHER = "LAB-HOST-02"
ZERO = "00000000-0000-0000-0000-000000000000"
G = lambda i: f"dddddddd-0000-0000-0000-{i:012d}"      # noqa: E731
MISSING_PARENT = "eeeeeeee-0000-0000-0000-00000000dead"


def _ts(s):
    return f"2026-01-01T10:00:{s:02d}+00:00"


ROWS = [
    # G(2) có Event 1, cha MISSING_PARENT không có Event 1 trong Silver -> nút NO_DATA
    {"id": "p2", "table": "process", "hostname": H, "process_guid": G(2), "parent_guid": MISSING_PARENT, "pid": 200, "ppid": 199,
     "image_path": "C:\\Windows\\explorer.exe", "parent_image": "C:\\Windows\\System32\\userinit.exe",
     "parent_command_line": "userinit.exe", "command_line": "explorer.exe", "user_name": "LAB\\user01",
     "integrity_level": "Medium", "timestamp": _ts(1), "record_id": 1},
    {"id": "p3", "table": "process", "hostname": H, "process_guid": G(3), "parent_guid": G(2), "pid": 300, "ppid": 200,
     "image_path": "C:\\Windows\\System32\\cmd.exe", "command_line": "cmd.exe /c lab.bat", "user_name": "LAB\\user01",
     "integrity_level": "High", "file_sha256": "AB" * 32, "hashes": {"SHA256": "AB" * 32},
     "timestamp": _ts(2), "record_id": 2},
    {"id": "p4", "table": "process", "hostname": H, "process_guid": G(4), "parent_guid": G(3), "pid": 400, "ppid": 300,
     "image_path": "C:\\lab\\payload_sim.exe", "command_line": "payload_sim.exe --synthetic", "timestamp": _ts(3), "record_id": 3},
    {"id": "p5", "table": "process", "hostname": H, "process_guid": G(5), "parent_guid": G(3), "pid": 500, "ppid": 300,
     "image_path": "C:\\Windows\\System32\\whoami.exe", "timestamp": _ts(40), "record_id": 4},
    {"id": "t4", "table": "process", "hostname": H, "process_guid": G(4), "parent_guid": G(3), "event_type": "PROCESS_END",
     "sysmon_event_id": 5, "image_path": "C:\\lab\\payload_sim.exe", "timestamp": _ts(9), "record_id": 5},
    # sự kiện của G(4)
    {"id": "f4", "table": "file", "hostname": H, "process_guid": G(4), "file_path": "C:\\lab\\drop.txt", "timestamp": _ts(4), "record_id": 6},
    {"id": "r4", "table": "registry", "hostname": H, "process_guid": G(4), "timestamp": _ts(5), "record_id": 7,
     "target_object": "HKU\\S\\Software\\Microsoft\\Windows\\CurrentVersion\\Run\\lab", "details": "C:\\lab\\payload_sim.exe"},
    {"id": "n4", "table": "network", "hostname": H, "process_guid": G(4), "dest_ip": "192.0.2.10", "dest_port": 443,
     "timestamp": _ts(6), "record_id": 8},
    {"id": "d4", "table": "network", "hostname": H, "process_guid": G(4), "event_type": "DNS_QUERY", "sysmon_event_id": 22,
     "dns_query_name": "lab.example.test", "timestamp": _ts(7), "record_id": 9},
    # host khác, cùng GUID con của G(3): không được lẫn vào cây của H
    {"id": "x", "table": "process", "hostname": OTHER, "process_guid": G(9), "parent_guid": G(3),
     "image_path": "C:\\other\\host.exe", "timestamp": _ts(4), "record_id": 10},
    {"id": "xf", "table": "file", "hostname": OTHER, "process_guid": G(4), "timestamp": _ts(4), "record_id": 11},
]


@pytest.fixture
def st(tmp_path):
    s = SilverStore(tmp_path / "s.duckdb")
    ids = {}
    for t, rid, row in harness.build_rows({"name": "pv", "rows": ROWS}):
        s._insert(t, row)
        ids[rid] = row["event_id"]
    t0 = datetime(2026, 1, 1, 10, 0, 3, tzinfo=timezone.utc)
    store = AlertStore(s.con)
    s.alert_id = store.insert_alert(detection_dedup_key="pv-1", group_key="pv-1", first_seen_utc=t0, last_seen_utc=t0,
                                    detection_source="RULE", rule_id="DACN-DET-001", rule_version=1, rule_name="pv",
                                    severity="high", severity_reason="synthetic", hostname=H, process_guid=G(4),
                                    contributing_event_ids=[ids["p4"]])
    store.insert_alert(detection_dedup_key="pv-2", group_key="pv-2", first_seen_utc=t0, last_seen_utc=t0,
                       detection_source="RULE", rule_id="DACN-DET-003", rule_version=3, rule_name="pv-other-host",
                       severity="medium", severity_reason="synthetic", hostname=OTHER, process_guid=G(4),
                       contributing_event_ids=[ids["xf"]])
    s.ids = ids
    return s


def _by_guid(tree):
    return {n["process_guid"]: n for n in tree["nodes"]}


def test_tree_has_ancestors_focus_descendants_with_node_fields(st):
    t = process_tree_view(st.con, H, G(3))
    n = _by_guid(t)
    assert t["focus"] == G(3) and t["hostname"] == H
    assert n[G(3)]["role"] == "focus" and n[G(3)]["depth"] == 0
    assert n[G(2)]["role"] == "ancestor" and n[G(2)]["depth"] == -1
    assert n[G(4)]["role"] == "descendant" and n[G(4)]["depth"] == 1 and n[G(5)]["depth"] == 1
    f = n[G(3)]
    assert f["status"] == "OBSERVED" and f["image_path"].endswith("cmd.exe") and f["command_line"] == "cmd.exe /c lab.bat"
    assert f["user_name"] == "LAB\\user01" and f["integrity_level"] == "High" and f["file_sha256"] == "AB" * 32
    assert f["pid"] == 300 and f["start_utc"] is not None and f["event_id"] == st.ids["p3"]
    assert "raw_data" not in f
    # thứ tự: tổ tiên xa -> gần, trọng tâm, con cháu theo thời điểm
    assert [x["process_guid"] for x in t["nodes"]][:3] == [MISSING_PARENT, G(2), G(3)]


def test_missing_parent_is_no_data_node_from_child_fields_only(st):
    t = process_tree_view(st.con, H, G(3))
    p = _by_guid(t)[MISSING_PARENT]
    assert p["status"] == "NO_DATA" and p["role"] == "ancestor" and p["depth"] == -2
    assert p["parent_image"] == "C:\\Windows\\System32\\userinit.exe"      # chỉ từ ParentImage của con
    assert p["parent_command_line"] == "userinit.exe" and p["pid_from_child"] == 199
    assert p["image_path"] is None and p["command_line"] is None and p["user_name"] is None   # không bịa
    assert p["evidence_source"] == st.ids["p2"]
    assert t["coverage_status"] == "PARTIAL_ANCESTRY"


def test_terminate_time_alerts_and_event_counts_per_node(st):
    n = _by_guid(process_tree_view(st.con, H, G(3)))
    k = n[G(4)]
    assert k["end_utc"] is not None
    assert k["event_counts"] == {"file": 1, "registry": 1, "network": 1, "dns": 1}
    assert [(a["rule_id"], a["severity"]) for a in k["alerts"]] == [("DACN-DET-001", "high")]   # alert host khác bị loại
    assert k["alerts"][0]["alert_id"] == st.alert_id
    assert n[G(5)]["alerts"] == [] and n[G(5)]["event_counts"] == {"file": 0, "registry": 0, "network": 0, "dns": 0}


def test_tree_is_host_scoped(st):
    t = process_tree_view(st.con, H, G(3))
    assert G(9) not in _by_guid(t)
    assert all(x["hostname"] == H for x in t["nodes"] if x["status"] == "OBSERVED")


def test_focus_without_event1_is_no_data_but_children_still_shown(st):
    t = process_tree_view(st.con, H, MISSING_PARENT)
    n = _by_guid(t)
    assert n[MISSING_PARENT]["status"] == "NO_DATA" and n[MISSING_PARENT]["role"] == "focus"
    assert n[MISSING_PARENT]["parent_image"] == "C:\\Windows\\System32\\userinit.exe"
    assert n[G(2)]["role"] == "descendant" and t["coverage_status"] == "PARTIAL_ANCESTRY"


def test_unknown_process_gives_empty_tree(st):
    t = process_tree_view(st.con, H, G(77))
    assert t["nodes"] == [] and t["coverage_status"] == "NOT_FOUND"


def test_descendant_window_and_limits(st):
    w = process_tree_view(st.con, H, G(3), until=datetime(2026, 1, 1, 10, 0, 30, tzinfo=timezone.utc))
    assert G(5) not in _by_guid(w) and G(4) in _by_guid(w)          # whoami bắt đầu ở giây 40, ngoài cửa sổ
    assert w["window"]["until"] is not None
    lim = process_tree_view(st.con, H, G(3), max_nodes=4)            # 1 NO_DATA + G2 + G3 + 1 con
    assert len(lim["nodes"]) == 4 and lim["node_limit_reached"] is True
    assert _by_guid(lim)[G(3)]["children_truncated"] is True
    d = process_tree_view(st.con, H, G(2), max_depth=1)
    assert G(4) not in _by_guid(d) and _by_guid(d)[G(3)]["children_truncated"] is True and d["descendants_truncated"] is True
    a = process_tree_view(st.con, H, G(4), max_depth=1)
    assert a["ancestors_truncated"] is True and G(2) not in _by_guid(a)


def test_parameter_validation(st):
    with pytest.raises(ValueError):
        process_tree_view(st.con, H, G(3), max_nodes=0)
    with pytest.raises(ValueError):
        process_tree_view(st.con, H, G(3), max_depth=99)


def test_process_events_merged_timeline_paged_and_host_scoped(st):
    r = process_events(st.con, H, G(4))
    assert [e["category"] for e in r["items"]] == ["process", "file", "registry", "network", "dns", "process"]
    assert all("raw_data" not in e for e in r["items"])
    assert r["items"][2]["summary"].startswith("HKU\\S\\Software")
    assert r["items"][4]["summary"] == "lab.example.test"
    assert r["items"][3]["summary"] == "192.0.2.10:443"
    p = process_events(st.con, H, G(4), limit=2, offset=0)
    assert len(p["items"]) == 2 and p["has_more"] is True
    q = process_events(st.con, H, G(4), limit=2, offset=4)
    assert len(q["items"]) == 2 and q["has_more"] is False
    only = process_events(st.con, H, G(4), kinds=["dns"])
    assert [e["category"] for e in only["items"]] == ["dns"]
    assert process_events(st.con, OTHER, G(4))["items"][0]["category"] == "file"
    with pytest.raises(ValueError):
        process_events(st.con, H, G(4), kinds=["bogus"])


def test_search_by_image_substring_and_sha256(st):
    r = search_processes(st.con, hostname=H, image="payload")
    assert [x["process_guid"] for x in r] == [G(4)]
    assert search_processes(st.con, image="%") == []                 # wildcard được escape
    assert [x["process_guid"] for x in search_processes(st.con, sha256="ab" * 32)] == [G(3)]   # không phân biệt hoa thường
    assert {x["hostname"] for x in search_processes(st.con, image=".exe")} == {H, OTHER}
    with pytest.raises(ValueError):
        search_processes(st.con, hostname=H)                          # cần image hoặc sha256
