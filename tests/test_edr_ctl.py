"""Test launcher với tiến trình giả (PH10-T01): start/stop lặp lại không để tiến trình mồ côi."""
import json
import os
import subprocess
import sys
import textwrap
import time
from pathlib import Path

import pytest

import edr_ctl
from edr_ctl import EdrCtl, pid_alive

FAKE = textwrap.dedent("""
    import sys, time, pathlib
    stop = pathlib.Path(sys.argv[1])
    while not stop.exists():
        time.sleep(0.05)
""")


@pytest.fixture
def ctl(tmp_path):
    script = tmp_path / "fake.py"; script.write_text(FAKE)
    run = tmp_path / "run"
    cmds = {n: [sys.executable, str(script), str(run / f"{n}.stop"), f"-m {n}"] for n in ("core", "agent", "responder")}
    markers = {"core": "-m core", "agent": "-m agent", "responder": "-m responder"}
    c = EdrCtl(tmp_path, cmds, markers)
    yield c
    for n in cmds:                      # dọn chắc chắn
        pid = c._read_pid(n)
        if pid and pid_alive(pid):
            os.kill(pid, 9)


def test_start_status_stop_clean(ctl):
    out = ctl.start()
    assert all(v.startswith("started") for v in out.values())
    st = ctl.status()
    assert all(v["state"] == "running" for v in st.values())
    pids = [v["pid"] for v in st.values()]
    res = ctl.stop(timeout=5)
    assert set(res.values()) == {"stopped"}
    time.sleep(0.2)
    assert not any(pid_alive(p) for p in pids)
    assert all(v["state"] == "stopped" for v in ctl.status().values())


def test_start_twice_does_not_duplicate_and_repeat_cycles_leave_no_orphans(ctl):
    ctl.start()
    first = {n: ctl._read_pid(n) for n in ("core", "agent", "responder")}
    again = ctl.start()
    assert set(again.values()) == {"already-running"}
    assert {n: ctl._read_pid(n) for n in first} == first
    ctl.stop(timeout=5)
    seen = []
    for _ in range(3):
        ctl.start(); seen += [ctl._read_pid(n) for n in first]; ctl.stop(timeout=5)
    time.sleep(0.2)
    assert not any(pid_alive(p) for p in seen + list(first.values()))


def test_stop_when_nothing_running_and_stale_pidfile(ctl):
    assert set(ctl.stop(timeout=1).values()) == {"not-running"}
    ctl.pidfile("core").write_text("999999")
    assert ctl.state("core") == "stale-pidfile"
    assert ctl.stop(timeout=1, only=["core"])["core"] == "cleaned-stale-pidfile"
    assert not ctl.pidfile("core").exists()


@pytest.mark.skipif(not Path("/proc/self/cmdline").exists(), reason="cần /proc")
def test_pid_reuse_is_not_killed(ctl, tmp_path):
    other = subprocess.Popen([sys.executable, "-c", "import time; time.sleep(30)"])
    try:
        ctl.pidfile("core").write_text(str(other.pid))
        res = ctl.stop(timeout=1, only=["core"])
        assert res["core"] == "pid-reused-not-killed" and pid_alive(other.pid)
    finally:
        other.kill(); other.wait()


def test_logs_are_captured(ctl):
    ctl.start(only=["core"])
    ctl.stop(timeout=5)
    assert (ctl.log_dir / "core.log").exists()
    assert isinstance(ctl.logs("core"), str)
