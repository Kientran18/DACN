"""CLI: python -m agent run --input events.xml [--config edr.yaml]"""
from __future__ import annotations

import argparse
import signal
import sys
from pathlib import Path

from common.config import load_config
from .bronze_writer import BronzeWriter
from .checkpoint import Checkpoint
from .runner import AgentRunner
from .sources.file_source import FileEventSource


def main(argv=None) -> int:
    ap = argparse.ArgumentParser(prog="agent")
    sub = ap.add_subparsers(dest="cmd", required=True)
    run = sub.add_parser("run")
    run.add_argument("--config", type=Path)
    run.add_argument("--input", type=Path, help="tệp XML export (file mode)")
    run.add_argument("--live", action="store_true", help="đọc Windows Event Log (chỉ Windows)")
    a = ap.parse_args(argv)
    cfg = load_config(a.config)
    if a.live:
        from .sources.eventlog import EventLogSource
        src, mode = EventLogSource(), "live"
    elif a.input:
        src, mode = FileEventSource(a.input), "file"
    else:
        ap.error("cần --input hoặc --live")
    runner = AgentRunner(src, BronzeWriter(cfg.bronze_dir), Checkpoint(cfg.home / "agent" / "checkpoint.json"),
                         cfg.home / "agent" / "health.json", mode=mode, stop_file=cfg.home / "agent" / "STOP")
    signal.signal(signal.SIGINT, lambda *_: runner.request_stop())
    runner.run()
    return 0


if __name__ == "__main__":
    sys.exit(main())
