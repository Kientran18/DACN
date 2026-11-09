"""Dựng Executor từ policy. Trên hệ không phải Windows, chỉ có backend giả/dry-run; không bao giờ tự bật execute."""
from __future__ import annotations

import sys

from .backends.dryrun import DryRunBackend
from .backends.local import LocalBackend
from .executor import Executor


def make_executor(policy, actions, process_api=None, ioc_path=None) -> Executor:
    roots = list(policy.lab_dirs) + [policy.quarantine_dir]
    if process_api is None and policy.execute_allowed():
        if sys.platform != "win32":
            raise RuntimeError("execute chỉ hỗ trợ trên Windows VM lab; trên hệ này dùng dry_run")
        from .backends.windows import WinProcessApi
        process_api = WinProcessApi()
        tol = 1.0     # Sysmon UtcTime chính xác ms; sai số tạm 1s, chưa hiệu chỉnh trên Windows thật
    else:
        tol = 0.0
    if process_api is None:
        from .backends.local import FakeProcessApi
        process_api = FakeProcessApi({})     # dry_run: không dùng tới
    return Executor(policy, actions, LocalBackend(process_api, roots, tol), DryRunBackend(), ioc_path=ioc_path)
