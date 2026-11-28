"""Playwright: alert Sigma trên dashboard (nguồn "Sigma", lọc nguồn, khung giải thích + tác giả/giấy phép/link rule gốc,
mục Rule Sigma đã nạp/bị loại). Dữ liệu SYNTHETIC. Bỏ qua nếu thiếu node/playwright."""
import json
import os
import shutil
import socket
import subprocess
import sys
import threading
import time
import uuid
from pathlib import Path

import pytest

HERE = Path(__file__).resolve().parent
sys.path.insert(0, str(HERE.parent / "detection"))
import harness  # noqa: E402

from alerts.builder import build_from_results  # noqa: E402
from alerts.store import AlertStore  # noqa: E402
from api.app import create_app  # noqa: E402
from api.auth import TokenStore, hash_token  # noqa: E402
from common.config import Config  # noqa: E402
from detection.engine import DetectionEngine  # noqa: E402
from detection.loader import load_rules  # noqa: E402
from detection.sigma.loader import load_sigma  # noqa: E402
from pipeline.silver_store import SilverStore  # noqa: E402
from response.policy import Policy  # noqa: E402

XSS = "<img src=x onerror=\"window.__xss=1\">"


def _node_ok():
    if not shutil.which("node"):
        return False
    return subprocess.run(["node", "-e", "require('playwright')"], capture_output=True).returncode == 0


pytestmark = pytest.mark.skipif(not _node_ok(), reason="cần node + playwright")


@pytest.fixture(scope="module")
def server(tmp_path_factory):
    import uvicorn
    tmp = tmp_path_factory.mktemp("ui_sigma")
    st = SilverStore(tmp / "s.duckdb")
    sch = "C:\\Windows\\System32\\schtasks.exe"
    raw = {"Image": sch, "OriginalFileName": "schtasks.exe", "CommandLine": "schtasks.exe /create /tn " + XSS + " /tr x",
           "User": "LAB\\analyst", "ParentImage": "C:\\Windows\\System32\\cmd.exe"}
    for t, _, row in harness.build_rows({"name": "uisigma", "rows": [
            {"id": "s", "table": "process", "hostname": "SYNTH-HOST", "image_path": sch, "command_line": raw["CommandLine"],
             "raw_data": json.dumps(raw), "timestamp": "2026-11-28T01:30:00+00:00"},
            {"id": "d", "table": "process", "hostname": "SYNTH-HOST", "image_path": "C:\\a\\powershell.exe", "record_id": 2,
             "process_guid": str(uuid.uuid4()), "command_line": "powershell.exe -enc AAAAAAAA",
             "raw_data": json.dumps({"Image": "C:\\a\\powershell.exe", "CommandLine": "powershell.exe -enc AAAAAAAA"}),
             "timestamp": "2026-11-28T01:31:00+00:00"}]}):
        st._insert(t, row)
    sig = load_sigma({"enabled": True})
    rules = {**load_rules(), **sig.rules}
    store = AlertStore(st.con)
    eng = DetectionEngine(st.con, rules=rules)
    eng.run()
    res = eng.pending_delivery()
    build_from_results(store, {r.rule_id: eng.delivery_rule(r) for r in res}, res, st.con)
    tok = "tok-viewer-sigma-0123456789"
    pol = Policy(mode="dry_run", execute_unlocked=False, allowed_actions=set(), protected_process_names=set(),
                 protected_dirs=[], lab_dirs=[tmp / "lab"], quarantine_dir=tmp / "lab" / "q")
    app = create_app(Config(home=tmp), TokenStore({hash_token(tok): {"role": "viewer", "actor": "v"}}), store=st,
                     rules=rules, policy=pol, bronze_dir=tmp / "b", data_label="SAMPLE", sigma_report=sig.report)
    s = socket.socket(); s.bind(("127.0.0.1", 0)); port = s.getsockname()[1]; s.close()
    srv = uvicorn.Server(uvicorn.Config(app, host="127.0.0.1", port=port, log_level="warning"))
    th = threading.Thread(target=srv.run, daemon=True); th.start()
    for _ in range(50):
        try:
            socket.create_connection(("127.0.0.1", port), 0.2).close(); break
        except OSError:
            time.sleep(0.1)
    yield {"base": f"http://127.0.0.1:{port}", "tok": tok, "tmp": tmp}
    srv.should_exit = True
    th.join(timeout=5)


def test_dashboard_sigma(server):
    shots = server["tmp"] / "shots"; shots.mkdir()
    env = {**os.environ, "NODE_PATH": subprocess.run(["npm", "root", "-g"], capture_output=True, text=True).stdout.strip()}
    r = subprocess.run(["node", str(HERE / "ui_sigma_check.js"), server["base"], server["tok"], str(shots)],
                       capture_output=True, text=True, timeout=180, env=env)
    assert r.returncode == 0, r.stdout + r.stderr
    res = json.loads(r.stdout.strip().splitlines()[-1])
    failed = {k: v for k, v in res.items() if v is not True}
    assert not failed, res
    keep = os.environ.get("DACN_UI_SHOTS")
    if keep:
        shutil.copytree(shots, keep, dirs_exist_ok=True)
