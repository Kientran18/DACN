"""Kiểm thử giao diện bằng Playwright với API + DuckDB fixture SYNTHETIC (PH9-T08).
KHÔNG phải tích hợp thật. Bỏ qua nếu thiếu node/playwright."""
import json
import os
import shutil
import socket
import subprocess
import sys
import threading
import time
from pathlib import Path

import pytest

HERE = Path(__file__).resolve().parent
sys.path.insert(0, str(HERE.parent / "detection"))
import harness  # noqa: E402

import bronze_contract as bc  # noqa: E402
from agent.bronze_writer import BronzeWriter  # noqa: E402
from alerts.builder import build_from_results  # noqa: E402
from alerts.store import AlertStore  # noqa: E402
from api.app import create_app  # noqa: E402
from api.auth import TokenStore, hash_token  # noqa: E402
from common.config import Config  # noqa: E402
from detection.engine import DetectionEngine  # noqa: E402
from detection.loader import load_rules  # noqa: E402
from pipeline.silver_store import SilverStore  # noqa: E402
from response.policy import Policy  # noqa: E402

SYN = Path(__file__).resolve().parents[2] / "poc/sysmon-collector/configs/synthetic_events.xml"
XSS = '<img src=x onerror="window.__xss=1"> powershell -enc AAAAAAAA'


def _node_ok():
    if not shutil.which("node"):
        return False
    r = subprocess.run(["node", "-e", "require('playwright')"], capture_output=True)
    return r.returncode == 0


pytestmark = pytest.mark.skipif(not _node_ok(), reason="cần node + playwright")


@pytest.fixture(scope="module")
def server(tmp_path_factory):
    import uvicorn
    tmp = tmp_path_factory.mktemp("ui")
    bdir = tmp / "bronze"
    w = BronzeWriter(bdir)
    for i, x in enumerate(bc.iter_raw_xml_from_file(SYN)):
        w.append(bc.build_bronze_record(x, mode="file", seq=i))
    w.seal()
    st = SilverStore(tmp / "s.duckdb")
    st.ingest_dir(bdir, "t")
    for t, _, row in harness.build_rows({"name": "ui", "rows": [
            {"id": "p", "table": "process", "image_path": "C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe",
             "command_line": XSS, "timestamp": "2026-01-01T10:00:00+00:00", "record_id": 900}]}):
        st._insert(t, row)
    rules = load_rules()
    store = AlertStore(st.con)
    build_from_results(store, rules, DetectionEngine(st.con, rules=rules).run(), st.con)
    # D1 (audit): alert có process_guid KHÔNG có Event 1 trong Silver nhưng có tiến trình con -> cây phải vẫn hiện tiến trình con
    from datetime import datetime, timezone
    orphan = "cccccccc-0000-0000-0000-000000000001"
    ids = {}
    for t, rid, row in harness.build_rows({"name": "orphan", "rows": [
            {"id": "kid", "table": "process", "process_guid": "cccccccc-0000-0000-0000-000000000002", "parent_guid": orphan,
             "image_path": "C:\\lab\\orphan_child.exe", "timestamp": "2025-12-31T10:00:05+00:00", "record_id": 901},
            {"id": "f", "table": "file", "process_guid": orphan, "timestamp": "2025-12-31T10:00:06+00:00", "record_id": 902}]}):
        st._insert(t, row)
        ids[rid] = row["event_id"]
    t0 = datetime(2025, 12, 31, 10, 0, tzinfo=timezone.utc)      # sớm hơn alert gốc: không đổi thứ tự "alert đầu tiên"
    store.insert_alert(detection_dedup_key="ui-orphan", group_key="ui-orphan", first_seen_utc=t0, last_seen_utc=t0,
                       detection_source="RULE", rule_id="DACN-DET-001", rule_version=1, rule_name="ui-orphan-parent",
                       severity="low", severity_reason="synthetic", hostname="LAB-HOST-01", process_guid=orphan,
                       contributing_event_ids=[ids["f"]])
    from response.actions import ActionStore
    acts = ActionStore(st.con, store)
    for a in store.list():
        acts.request("QUARANTINE_FILE", {"path": "x"}, requested_by="user-viewer", requested_mode="dry_run", alert_id=a["alert_id"])
    toks = {"approver": "tok-approver-ui-0123456789", "viewer": "tok-viewer-ui-0123456789"}
    tokens = TokenStore({hash_token(t): {"role": r, "actor": f"user-{r}"} for r, t in toks.items()})
    pol = Policy(mode="dry_run", execute_unlocked=False, allowed_actions={"QUARANTINE_FILE"}, protected_process_names=set(),
                 protected_dirs=[], lab_dirs=[tmp / "lab"], quarantine_dir=tmp / "lab" / "q")
    app = create_app(Config(home=tmp), tokens, store=st, rules=rules, policy=pol, bronze_dir=bdir, data_label="SAMPLE")
    s = socket.socket(); s.bind(("127.0.0.1", 0)); port = s.getsockname()[1]; s.close()
    srv = uvicorn.Server(uvicorn.Config(app, host="127.0.0.1", port=port, log_level="warning"))
    th = threading.Thread(target=srv.run, daemon=True); th.start()
    for _ in range(50):
        try:
            socket.create_connection(("127.0.0.1", port), 0.2).close(); break
        except OSError:
            time.sleep(0.1)
    yield {"base": f"http://127.0.0.1:{port}", "toks": toks, "tmp": tmp}
    srv.should_exit = True
    th.join(timeout=5)


def test_dashboard_ui_checks(server):
    shots = server["tmp"] / "shots"; shots.mkdir()
    node_path = subprocess.run(["npm", "root", "-g"], capture_output=True, text=True).stdout.strip()
    env = {**os.environ, "NODE_PATH": node_path}
    r = subprocess.run(["node", str(HERE / "ui_check.js"), server["base"], server["toks"]["approver"], server["toks"]["viewer"], str(shots)],
                       capture_output=True, text=True, timeout=180, env=env)
    assert r.returncode == 0, r.stdout + r.stderr
    res = json.loads(r.stdout.strip().splitlines()[-1])
    booleans = {k: v for k, v in res.items() if isinstance(v, bool) or k == "no_external_requests"}
    failed = {k: v for k, v in booleans.items() if v is not True}
    assert not failed, (failed, res)
    assert res["events_rows"] >= 1 and res["alerts_rows"] >= 1 and res["rules_rows"] >= 4
    keep = os.environ.get("DACN_UI_SHOTS")
    if keep:
        shutil.copytree(shots, keep, dirs_exist_ok=True)
