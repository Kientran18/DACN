"""API điều tra cây tiến trình (chỉ đọc). Dữ liệu SYNTHETIC qua harness, không phải telemetry thật."""
import sys
from datetime import datetime, timezone
from pathlib import Path

import pytest
from fastapi.testclient import TestClient

HERE = Path(__file__).resolve().parent
sys.path.insert(0, str(HERE.parent / "detection"))
import harness  # noqa: E402

from alerts.store import AlertStore  # noqa: E402
from api.app import create_app  # noqa: E402
from api.auth import TokenStore, hash_token  # noqa: E402
from common.config import Config  # noqa: E402
from detection.loader import load_rules  # noqa: E402
from pipeline.silver_store import SilverStore  # noqa: E402
from response.policy import Policy  # noqa: E402

TOK = {r: f"tok-{r}-0123456789" for r in ("viewer", "analyst", "approver", "responder")}
H = "LAB-HOST-01"
P, C, K = ("ffffffff-0000-0000-0000-000000000001", "ffffffff-0000-0000-0000-000000000002",
           "ffffffff-0000-0000-0000-000000000003")
MISSING = "ffffffff-0000-0000-0000-00000000dead"
ROWS = [
    {"id": "p", "table": "process", "hostname": H, "process_guid": P, "parent_guid": MISSING, "ppid": 4,
     "parent_image": "C:\\Windows\\System32\\services.exe", "image_path": "C:\\Windows\\System32\\cmd.exe",
     "timestamp": "2026-01-01T10:00:00+00:00", "record_id": 1},
    {"id": "c", "table": "process", "hostname": H, "process_guid": C, "parent_guid": P,
     "image_path": "C:\\lab\\sim_tool.exe", "command_line": "sim_tool.exe --synthetic", "file_sha256": "cd" * 32,
     "timestamp": "2026-01-01T10:00:01+00:00", "record_id": 2},
    {"id": "k", "table": "process", "hostname": H, "process_guid": K, "parent_guid": C,
     "image_path": "C:\\Windows\\System32\\whoami.exe", "timestamp": "2026-01-01T10:00:02+00:00", "record_id": 3},
    {"id": "f", "table": "file", "hostname": H, "process_guid": C, "file_path": "C:\\lab\\out.txt",
     "timestamp": "2026-01-01T10:00:03+00:00", "record_id": 4},
    {"id": "d", "table": "network", "hostname": H, "process_guid": C, "event_type": "DNS_QUERY", "sysmon_event_id": 22,
     "dns_query_name": "lab.example.test", "timestamp": "2026-01-01T10:00:04+00:00", "record_id": 5},
]


@pytest.fixture
def ctx(tmp_path):
    st = SilverStore(tmp_path / "s.duckdb")
    ids = {}
    for t, rid, row in harness.build_rows({"name": "inv", "rows": ROWS}):
        st._insert(t, row)
        ids[rid] = row["event_id"]
    t0 = datetime(2026, 1, 1, 10, 0, 1, tzinfo=timezone.utc)
    aid = AlertStore(st.con).insert_alert(detection_dedup_key="inv", group_key="inv", first_seen_utc=t0, last_seen_utc=t0,
                                          detection_source="RULE", rule_id="DACN-DET-001", rule_version=1, rule_name="inv",
                                          severity="high", severity_reason="synthetic", hostname=H, process_guid=C,
                                          contributing_event_ids=[ids["c"]])
    tokens = TokenStore({hash_token(t): {"role": r, "actor": f"user-{r}"} for r, t in TOK.items()})
    policy = Policy(mode="dry_run", execute_unlocked=False, allowed_actions=set(), protected_process_names=set(),
                    protected_dirs=[], lab_dirs=[tmp_path / "lab"], quarantine_dir=tmp_path / "lab" / "q")
    app = create_app(Config(home=tmp_path), tokens, store=st, rules=load_rules(), policy=policy, bronze_dir=tmp_path / "b")
    return {"app": app, "alert_id": aid, "st": st}


def cl(ctx, role=None):
    c = TestClient(ctx["app"])
    if role:
        c.headers["Authorization"] = f"Bearer {TOK[role]}"
    return c


TREE = f"/investigation/process-tree?hostname={H}&process_guid={C}"
EVENTS = f"/investigation/process-events?hostname={H}&process_guid={C}"
SEARCH = f"/investigation/process-search?hostname={H}&image=sim_tool"


@pytest.mark.parametrize("path", [TREE, EVENTS, SEARCH])
def test_auth_and_roles(ctx, path):
    assert cl(ctx).get(path).status_code == 401
    assert cl(ctx, "responder").get(path).status_code == 403           # responder không có quyền đọc dữ liệu
    for role in ("viewer", "analyst", "approver"):
        assert cl(ctx, role).get(path).status_code == 200, role


@pytest.mark.parametrize("path", [TREE, EVENTS, SEARCH])
def test_read_only(ctx, path):
    base = path.split("?")[0]
    for m in ("post", "put", "delete"):
        assert getattr(cl(ctx, "approver"), m)(base).status_code in (405, 411)


def test_tree_payload(ctx):
    d = cl(ctx, "viewer").get(TREE).json()
    n = {x["process_guid"]: x for x in d["nodes"]}
    assert d["focus"] == C and d["coverage_status"] == "PARTIAL_ANCESTRY"
    assert n[MISSING]["status"] == "NO_DATA" and n[MISSING]["parent_image"].endswith("services.exe")
    assert n[MISSING]["image_path"] is None
    assert n[C]["alerts"][0]["alert_id"] == ctx["alert_id"] and n[C]["alerts"][0]["severity"] == "high"
    assert n[C]["event_counts"] == {"file": 1, "registry": 0, "network": 0, "dns": 1}
    assert n[K]["role"] == "descendant"
    assert all("raw_data" not in x for x in d["nodes"])


def test_tree_limits_and_window(ctx):
    d = cl(ctx, "viewer").get(TREE + "&max_nodes=3").json()
    assert len(d["nodes"]) == 3 and d["node_limit_reached"] is True
    w = cl(ctx, "viewer").get(TREE + "&until=2026-01-01T10:00:02Z").json()
    assert K not in {x["process_guid"] for x in w["nodes"]}


@pytest.mark.parametrize("q", ["max_nodes=0", "max_nodes=501", "max_depth=0", "max_depth=21", "until=2026-01-01T10:00:02"])
def test_tree_validation(ctx, q):
    r = cl(ctx, "viewer").get(TREE + "&" + q)
    assert r.status_code == 422 and r.json()["error"]["code"] == "E-VALIDATION"


def test_tree_requires_params_and_not_found(ctx):
    assert cl(ctx, "viewer").get("/investigation/process-tree?hostname=" + H).status_code == 422
    r = cl(ctx, "viewer").get(f"/investigation/process-tree?hostname={H}&process_guid=ffffffff-0000-0000-0000-000000000099")
    assert r.status_code == 200 and r.json()["coverage_status"] == "NOT_FOUND" and r.json()["nodes"] == []


def test_events_payload_and_paging(ctx):
    d = cl(ctx, "viewer").get(EVENTS).json()
    assert [e["category"] for e in d["items"]] == ["process", "file", "dns"]
    assert all("raw_data" not in e and "raw_data" not in e["detail"] for e in d["items"])
    p = cl(ctx, "viewer").get(EVENTS + "&limit=1&offset=1").json()
    assert [e["category"] for e in p["items"]] == ["file"] and p["has_more"] is True
    assert [e["category"] for e in cl(ctx, "viewer").get(EVENTS + "&kinds=dns").json()["items"]] == ["dns"]
    r = cl(ctx, "viewer").get(EVENTS + "&kinds=bogus")
    assert r.status_code == 422 and r.json()["error"]["code"] == "E-VALIDATION"
    assert cl(ctx, "viewer").get(EVENTS + "&limit=201").status_code == 422


def test_search(ctx):
    d = cl(ctx, "viewer").get(SEARCH).json()
    assert [x["process_guid"] for x in d["items"]] == [C]
    assert [x["process_guid"] for x in cl(ctx, "viewer").get("/investigation/process-search?sha256=" + "CD" * 32).json()["items"]] == [C]
    for bad in ("", "?hostname=" + H, "?sha256=xyz", "?image=" + "a" * 300):
        r = cl(ctx, "viewer").get("/investigation/process-search" + bad)
        assert r.status_code == 422 and r.json()["error"]["code"] == "E-VALIDATION", bad
