"""python -m api [--config edr.yaml] [--policy config/response-policy.yaml]  (bind 127.0.0.1 do cấu hình ép)"""
from __future__ import annotations

import argparse
from pathlib import Path

from common.config import load_config
from detection.loader import load_rules
from detection.sigma.loader import load_sigma
from pipeline.silver_store import SilverStore
from response.policy import load_policy

from .app import create_app, serve
from .auth import TokenStore


def main(argv=None) -> int:
    ap = argparse.ArgumentParser(prog="api")
    ap.add_argument("--config", type=Path)
    ap.add_argument("--policy", type=Path, default=Path("config/response-policy.yaml"))
    ap.add_argument("--sigma-config", type=Path, default=None, help="mặc định config/sigma-rules.yaml (TẮT)")
    a = ap.parse_args(argv)
    cfg = load_config(a.config)
    tokens = TokenStore.load(cfg.tokens_path)
    if not tokens.entries:
        raise SystemExit("Chưa có token. Tạo: python -m api.auth --role analyst --actor <tên>")
    sigma = load_sigma(a.sigma_config)
    app = create_app(cfg, tokens, store=SilverStore(cfg.silver_db), rules={**load_rules(), **sigma.rules},
                     policy=load_policy(a.policy), bronze_dir=cfg.bronze_dir, sigma_report=sigma.report)
    serve(cfg, app)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
