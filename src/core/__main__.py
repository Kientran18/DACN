"""python -m core --config edr.yaml [--sample-data]: worker ingest+detect+alert và API trong một tiến trình."""
from __future__ import annotations

import argparse
import threading
import time
from pathlib import Path

import uvicorn

from api.app import create_app
from api.auth import TokenStore
from common.config import load_config
from detection.loader import load_rules
from pipeline.silver_store import SilverStore
from response.policy import load_policy

from .service import CoreService


def main(argv=None) -> int:
    ap = argparse.ArgumentParser(prog="core")
    ap.add_argument("--config", type=Path)
    ap.add_argument("--policy", type=Path, default=Path("config/response-policy.yaml"))
    ap.add_argument("--sample-data", action="store_true", help="gắn nhãn DỮ LIỆU MẪU trên dashboard")
    ap.add_argument("--poll-seconds", type=float, default=2.0)
    a = ap.parse_args(argv)
    cfg = load_config(a.config)
    tokens = TokenStore.load(cfg.tokens_path)
    if not tokens.entries:
        raise SystemExit("Chưa có token. Tạo: python -m api.auth --config ... --role analyst --actor <tên>")
    store = SilverStore(cfg.silver_db)
    rules = load_rules()
    lock = threading.RLock()
    svc = CoreService(store, cfg.bronze_dir, cfg.home / "metrics.jsonl", rules, cfg.home / "ioc" / "ioc.yaml", lock)
    app = create_app(cfg, tokens, store=store, rules=rules, policy=load_policy(a.policy), bronze_dir=cfg.bronze_dir,
                     data_label="SAMPLE" if a.sample_data else "UNSPECIFIED", lock=lock)
    server = uvicorn.Server(uvicorn.Config(app, host=cfg.api_host, port=cfg.api_port, log_level="warning"))
    stop_file = cfg.home / "run" / "core.stop"

    def watch():
        while not server.should_exit:
            if stop_file.exists():
                server.should_exit = True
                svc.stop.set()
            time.sleep(0.5)
    threading.Thread(target=watch, daemon=True).start()
    threading.Thread(target=svc.run_forever, args=(a.poll_seconds, stop_file), daemon=True).start()
    server.run()
    svc.stop.set()
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
