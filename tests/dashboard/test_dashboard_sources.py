"""Playwright: dashboard hiển thị nguồn phát hiện DACN/Defender, lọc theo nguồn, khung script PowerShell đã che và xem bản gốc
có audit (hạng mục 9, docs/architecture/w8). Dữ liệu SYNTHETIC; bí mật là chuỗi giả ghép lúc chạy. Bỏ qua nếu thiếu node/playwright."""
import json
import os
import shutil
import socket
import subprocess
import sys
import threading
import time
from pathlib import Path
from xml.sax.saxutils import escape

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

ROOT = HERE.parents[1]
FIX = ROOT / "tests/fixtures/windows_channels"
SECRET = "Synthetic" + "UiPw0rd" + "NotReal"
NS = "http://schemas.microsoft.com/win/2004/08/events/event"


def _node_ok():
    if not shutil.which("node"):
        return False
    return subprocess.run(["node", "-e", "require('playwright')"], capture_output=True).returncode == 0


pytestmark = pytest.mark.skipif(not _node_ok(), reason="cần node + playwright")


def ps_xml(text):
    return (f"<Event xmlns='{NS}'><System><Provider Name='Microsoft-Windows-PowerShell'/><EventID>4104</EventID>"
            "<Version>1</Version><Level>5</Level><TimeCreated SystemTime='2026-11-28T01:20:00.0000000Z'/>"
            "<EventRecordID>77</EventRecordID><Execution ProcessID='3333' ThreadID='4444'/>"
            "<Channel>Microsoft-Windows-PowerShell/Operational</Channel><Computer>SYNTH-HOST</Computer>"
            "<Security UserID='S-1-5-21-0-0-0-1001'/></System><EventData><Data Name='MessageNumber'>1</Data>"
            f"<Data Name='MessageTotal'>1</Data><Data Name='ScriptBlockText'>{escape(text)}</Data>"
            "<Data Name='ScriptBlockId'>00000000-0000-4000-8000-0000000000d1</Data><Data Name='Path'></Data></EventData></Event>")


@pytest.fixture(scope="module")
def server(tmp_path_factory):
    import uvicorn
    tmp = tmp_path_factory.mktemp("ui_src")
    bdir = tmp / "bronze"
    w = BronzeWriter(bdir)
    xmls = [x for n in ("defender_1116.synthetic.xml", "defender_1117.synthetic.xml") for x in bc.iter_raw_xml_from_file(FIX / n)]
    xmls.append(ps_xml(f"$p = ConvertTo-SecureString '{SECRET}' -AsPlainText -Force\n"
                       "# <img src=x onerror=\"window.__xss=1\">\n$x = 'a' | " + "Invoke-" + "Expression"))
    for x in xmls:
        w.append(bc.build_bronze_record(x, mode="file"))
    w.seal()
    st = SilverStore(tmp / "s.duckdb")
    st.ingest_dir(bdir, "t")
    for t, _, row in harness.build_rows({"name": "uisrc", "rows": [{
            "id": "p", "table": "process", "hostname": "SYNTH-HOST", "image_path": "C:\\a\\powershell.exe",
            "command_line": "powershell.exe -enc AAAAAAAA", "timestamp": "2026-11-28T01:30:00+00:00"}]}):
        st._insert(t, row)
    rules = load_rules()
    store = AlertStore(st.con)
    build_from_results(store, rules, DetectionEngine(st.con, rules=rules).run(), st.con)
    toks = {"approver": "tok-approver-src-0123456789", "viewer": "tok-viewer-src-0123456789"}
    tokens = TokenStore({hash_token(t): {"role": r, "actor": f"user-{r}"} for r, t in toks.items()})
    pol = Policy(mode="dry_run", execute_unlocked=False, allowed_actions=set(), protected_process_names=set(),
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
    yield {"base": f"http://127.0.0.1:{port}", "toks": toks, "tmp": tmp, "st": st}
    srv.should_exit = True
    th.join(timeout=5)


def test_dashboard_sources_and_script_panel(server):
    shots = server["tmp"] / "shots"; shots.mkdir()
    env = {**os.environ, "NODE_PATH": subprocess.run(["npm", "root", "-g"], capture_output=True, text=True).stdout.strip()}
    r = subprocess.run(["node", str(HERE / "ui_sources_check.js"), server["base"], server["toks"]["approver"], server["toks"]["viewer"],
                        SECRET, str(shots)], capture_output=True, text=True, timeout=180, env=env)
    assert r.returncode == 0, r.stdout + r.stderr
    res = json.loads(r.stdout.strip().splitlines()[-1])
    failed = {k: v for k, v in res.items() if v is not True}
    assert not failed, res
    audit = [a for (a,) in server["st"].con.execute("select actor from audit_log where action='SCRIPT_RAW_VIEW'").fetchall()]
    assert audit == ["user-approver"]                      # chỉ lần reveal của approver được ghi
    keep = os.environ.get("DACN_UI_SHOTS")
    if keep:
        shutil.copytree(shots, keep, dirs_exist_ok=True)
