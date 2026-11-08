"""python -m response --config edr.yaml: tiến trình responder tách khỏi core, kéo hành động APPROVED qua API.
Token vai trò 'responder' lấy từ biến môi trường EDR_RESPONDER_TOKEN (không ghi trong tệp cấu hình)."""
from __future__ import annotations

import argparse
import os
import time
from pathlib import Path

import httpx

from common.config import load_config
from .factory import make_executor
from .policy import load_policy
from .remote import RemoteActions
from .responder import Responder


def main(argv=None) -> int:
    ap = argparse.ArgumentParser(prog="response")
    ap.add_argument("--config", type=Path)
    ap.add_argument("--policy", type=Path, default=Path("config/response-policy.yaml"))
    ap.add_argument("--poll-seconds", type=float, default=2.0)
    a = ap.parse_args(argv)
    cfg = load_config(a.config)
    token = os.environ.get("EDR_RESPONDER_TOKEN")
    if not token:
        raise SystemExit("Thiếu EDR_RESPONDER_TOKEN (token vai trò responder)")
    http = httpx.Client(base_url=f"http://{cfg.api_host}:{cfg.api_port}", headers={"Authorization": f"Bearer {token}"}, timeout=10)
    remote = RemoteActions(http)
    policy = load_policy(a.policy)       # mặc định dry_run; execute cần cả hai khóa trong policy
    ex = make_executor(policy, remote)
    stop_file = cfg.home / "run" / "responder.stop"
    r = Responder(remote.list_approved, ex, lambda aid, res: None)
    while not stop_file.exists():
        try:
            r.run_once()
        except httpx.HTTPError:
            pass      # core chưa sẵn sàng: thử lại vòng sau
        time.sleep(a.poll_seconds)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
