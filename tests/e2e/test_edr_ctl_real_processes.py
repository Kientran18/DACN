"""Chạy THẬT nhiều tiến trình qua edr_ctl (core + agent) trên Linux với dữ liệu synthetic (PH10-T01/T03).
Kiểm chuỗi: tệp XML -> agent --follow -> Bronze -> core (ingest+detect+alert) -> API qua HTTP thật -> dừng sạch."""
import json
import os
import socket
import subprocess
import sys
import time
from pathlib import Path

import httpx
import pytest
import yaml

sys.path.insert(0, str(Path(__file__).parent))
import scenario_xml as sx  # noqa: E402
from api.auth import create_token  # noqa: E402
from edr_ctl import pid_alive  # noqa: E402

ROOT = Path(__file__).resolve().parents[2]


def free_port():
    s = socket.socket(); s.bind(("127.0.0.1", 0)); p = s.getsockname()[1]; s.close(); return p


def test_start_ingest_alert_stop(tmp_path):
    home, port = tmp_path / "edr", free_port()
    home.mkdir()
    cfg = tmp_path / "edr.yaml"
    cfg.write_text(yaml.safe_dump({"home": str(home), "api": {"host": "127.0.0.1", "port": port, "tokens_file": str(home / "tok.json")}}))
    token = create_token(home / "tok.json", "analyst", "e2e")
    xml = tmp_path / "events.xml"; xml.write_text("\n".join(sx.full_scenario()), encoding="utf-8")
    (home / "ioc").mkdir(); (home / "ioc" / "ioc.yaml").write_text(yaml.safe_dump({"ioc_hashes": [{"sha256": sx.IOC_SHA, "source": "e2e-synthetic"}]}))
    env = {**os.environ, "PYTHONPATH": os.pathsep.join(str(ROOT / p) for p in ("src", "src/pipeline", "poc/sysmon-collector")),
           "TEMP": "/tmp/x", "PUBLIC": "/tmp/p", "SystemRoot": "/tmp/s", "ProgramFiles": "/tmp/pf", "ProgramFiles(x86)": "/tmp/pf86"}
    env.pop("EDR_RESPONDER_TOKEN", None)
    ctl = [sys.executable, "-m", "edr_ctl", "--config", str(cfg)]
    run = lambda *a: subprocess.run([*ctl, *a], capture_output=True, text=True, cwd=ROOT, env=env, timeout=60)
    pids = []
    try:
        r = run("start", "--agent-input", str(xml))
        assert r.returncode == 0, r.stdout + r.stderr
        started = json.loads(r.stdout)
        assert set(started) == {"core", "agent"} and all(v.startswith("started") for v in started.values())
        pids = [int(v.split("pid=")[1]) for v in started.values()]
        base = {"Authorization": f"Bearer {token}"}
        alerts = []
        deadline = time.time() + 40
        while time.time() < deadline:
            try:
                alerts = httpx.get(f"http://127.0.0.1:{port}/alerts", headers=base, timeout=3).json().get("items", [])
            except (httpx.HTTPError, ValueError):
                alerts = []
            if len(alerts) >= 4:
                break
            time.sleep(0.5)
        logs = (home / "logs" / "core.log").read_text(errors="replace") if (home / "logs" / "core.log").exists() else ""
        assert len(alerts) == 4, (alerts, logs[-2000:])
        assert {a["rule_id"] for a in alerts} == {"DACN-DET-001", "DACN-DET-003", "DACN-DET-010", "DACN-DET-101"}
        assert httpx.get(f"http://127.0.0.1:{port}/health", timeout=3).status_code == 401
        st = json.loads(run("status").stdout)
        assert st["core"]["state"] == "running" and st["agent"]["state"] == "running"
        assert st["agent"]["health"]["events_written"] == 8
    finally:
        r = run("stop")
        time.sleep(0.3)
        for p in pids:
            if pid_alive(p):
                os.kill(p, 9)
    assert r.returncode == 0
    stopped = json.loads(r.stdout)
    assert stopped["core"] == "stopped" and stopped["agent"] == "stopped", stopped      # dừng sạch bằng tệp stop, không phải ép kết thúc
    assert set(stopped.values()) <= {"stopped", "not-running"}
    assert not any(pid_alive(p) for p in pids)
