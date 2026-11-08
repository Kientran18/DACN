"""Launcher: python -m edr_ctl start|stop|status|logs [--config edr.yaml] (PH10-T01). Không cài service.
Dừng sạch bằng tệp stop; chỉ ép kết thúc khi xác minh được đúng tiến trình (tránh tái sử dụng PID)."""
from __future__ import annotations

import argparse
import json
import os
import signal
import subprocess
import sys
import time
from pathlib import Path
from typing import Dict, List, Optional

ROOT = Path(__file__).resolve().parents[1]
PY_PATH = [ROOT / "src", ROOT / "src" / "pipeline", ROOT / "poc" / "sysmon-collector"]
ORDER = ["core", "agent", "responder"]       # khởi động core trước; dừng ngược lại


def default_commands(cfg_path: Optional[Path], agent_args: List[str]) -> Dict[str, List[str]]:
    c = ["--config", str(cfg_path)] if cfg_path else []
    return {"core": [sys.executable, "-m", "core", *c],
            "agent": [sys.executable, "-m", "agent", "run", *c, "--follow", *agent_args],
            "responder": [sys.executable, "-m", "response", *c]}


def pid_alive(pid: int) -> bool:
    try:
        os.kill(pid, 0)
    except ProcessLookupError:
        return False
    except PermissionError:
        return True
    except OSError:
        return False
    stat = Path(f"/proc/{pid}/stat")           # Linux: tiến trình zombie đã thoát, không tính là còn chạy
    try:
        if stat.exists() and stat.read_text().rsplit(")", 1)[1].split()[0] == "Z":
            return False
    except (OSError, IndexError):
        pass
    return True


def cmdline_matches(pid: int, marker: str) -> Optional[bool]:
    """True/False nếu xác minh được, None nếu không xác minh được (ví dụ Windows)."""
    p = Path(f"/proc/{pid}/cmdline")
    if not p.exists():
        return None
    try:
        return marker in p.read_bytes().replace(b"\0", b" ").decode("utf-8", "ignore")
    except OSError:
        return None


class EdrCtl:
    def __init__(self, home: Path, commands: Dict[str, List[str]], markers: Optional[Dict[str, str]] = None):
        self.home, self.commands = Path(home), commands
        self.markers = markers or {"core": "-m core", "agent": "-m agent", "responder": "-m response"}
        self.run_dir, self.log_dir = self.home / "run", self.home / "logs"
        self.run_dir.mkdir(parents=True, exist_ok=True)
        self.log_dir.mkdir(parents=True, exist_ok=True)

    def pidfile(self, n): return self.run_dir / f"{n}.pid"
    def stopfile(self, n): return self.run_dir / f"{n}.stop"

    def _read_pid(self, n) -> Optional[int]:
        try:
            return int(self.pidfile(n).read_text().strip())
        except (OSError, ValueError):
            return None

    def state(self, n) -> str:
        pid = self._read_pid(n)
        if pid is None:
            return "stopped"
        return "running" if pid_alive(pid) else "stale-pidfile"

    def start(self, only: Optional[List[str]] = None) -> Dict[str, str]:
        out = {}
        for n in [x for x in ORDER if x in self.commands and (not only or x in only)]:
            if self.state(n) == "running":
                out[n] = "already-running"
                continue
            self.stopfile(n).unlink(missing_ok=True)
            env = {**os.environ, "PYTHONPATH": os.pathsep.join(map(str, PY_PATH)), "EDR_HOME": str(self.home)}
            log = open(self.log_dir / f"{n}.log", "ab")
            kw = {"creationflags": getattr(subprocess, "CREATE_NEW_PROCESS_GROUP", 0)} if os.name == "nt" else {"start_new_session": True}
            proc = subprocess.Popen(self.commands[n], stdout=log, stderr=subprocess.STDOUT, env=env, cwd=str(ROOT), **kw)
            self.pidfile(n).write_text(str(proc.pid))
            out[n] = f"started pid={proc.pid}"
        return out

    def stop(self, timeout: float = 15.0, force: bool = False, only: Optional[List[str]] = None) -> Dict[str, str]:
        out = {}
        names = [x for x in reversed(ORDER) if x in self.commands and (not only or x in only)]
        for n in names:
            pid = self._read_pid(n)
            if pid is None:
                out[n] = "not-running"; continue
            if not pid_alive(pid):
                self.pidfile(n).unlink(missing_ok=True); out[n] = "cleaned-stale-pidfile"; continue
            self.stopfile(n).write_text("stop")
            deadline = time.time() + timeout
            while time.time() < deadline and pid_alive(pid):
                time.sleep(0.2)
            if not pid_alive(pid):
                out[n] = "stopped"
            else:
                ok = cmdline_matches(pid, self.markers[n])
                if ok is True or (ok is None and force):
                    os.kill(pid, signal.SIGTERM)
                    time.sleep(0.5)
                    out[n] = "terminated" if not pid_alive(pid) else "STILL-RUNNING"
                else:
                    out[n] = "STILL-RUNNING (không xác minh được tiến trình; dùng --force nếu chắc chắn)" if ok is None else "pid-reused-not-killed"
            if not pid_alive(pid):
                self.pidfile(n).unlink(missing_ok=True)
                self.stopfile(n).unlink(missing_ok=True)
        return out

    def status(self) -> Dict[str, dict]:
        res = {}
        for n in ORDER:
            if n in self.commands:
                res[n] = {"state": self.state(n), "pid": self._read_pid(n)}
        h = self.home / "agent" / "health.json"
        if h.exists() and "agent" in res:
            try:
                res["agent"]["health"] = json.loads(h.read_text(encoding="utf-8"))
            except ValueError:
                res["agent"]["health"] = "unreadable"
        return res

    def logs(self, name: str, lines: int = 40) -> str:
        p = self.log_dir / f"{name}.log"
        return "".join(p.read_text(encoding="utf-8", errors="replace").splitlines(True)[-lines:]) if p.exists() else ""


def main(argv=None) -> int:
    from common.config import load_config
    ap = argparse.ArgumentParser(prog="edr_ctl")
    ap.add_argument("cmd", choices=["start", "stop", "status", "logs"])
    ap.add_argument("--config", type=Path)
    ap.add_argument("--only", nargs="*", choices=ORDER)
    ap.add_argument("--agent-input", type=Path, help="tệp XML export cho agent (file mode)")
    ap.add_argument("--live", action="store_true", help="agent đọc Windows Event Log (chỉ Windows)")
    ap.add_argument("--no-responder", action="store_true")
    ap.add_argument("--force", action="store_true")
    ap.add_argument("--name", choices=ORDER, default="core")
    a = ap.parse_args(argv)
    cfg = load_config(a.config)
    agent_args = ["--live"] if a.live else (["--input", str(a.agent_input)] if a.agent_input else [])
    cmds = default_commands(a.config, agent_args)
    if a.cmd == "start":      # status/stop/logs luôn thấy đủ ba thành phần, không phụ thuộc tham số của start
        if a.no_responder or not os.environ.get("EDR_RESPONDER_TOKEN"):
            cmds.pop("responder", None)
        if not agent_args:
            cmds.pop("agent")
    ctl = EdrCtl(cfg.home, cmds)
    if a.cmd == "start":
        print(json.dumps(ctl.start(a.only), indent=2))
    elif a.cmd == "stop":
        print(json.dumps(ctl.stop(force=a.force, only=a.only), indent=2))
    elif a.cmd == "status":
        print(json.dumps(ctl.status(), indent=2, default=str))
    else:
        print(ctl.logs(a.name))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
