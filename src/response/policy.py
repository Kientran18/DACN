"""Response policy và cổng bảo vệ (PH7-T01). Mặc định dry_run; execute cần HAI khóa; fail closed."""
from __future__ import annotations

import os
import re
from dataclasses import dataclass, field
from pathlib import Path
from typing import Dict, List, Optional, Set, Tuple

import yaml


class PolicyError(ValueError):
    pass


ACTION_TYPES = {"TERMINATE_PROCESS", "QUARANTINE_FILE", "RESTORE_FILE"}
_KEYS = {"mode", "execute_unlocked", "require_distinct_approver", "allowed_actions", "lab_marker_prefix", "lab_dirs",
         "quarantine_dir", "protected_process_names", "protected_dirs", "auto_response"}
PROTECTED_PIDS = {0, 4}


@dataclass
class Policy:
    mode: str
    execute_unlocked: bool
    allowed_actions: Set[str]
    protected_process_names: Set[str]
    protected_dirs: List[Path]
    lab_dirs: List[Path]
    lab_marker_prefix: str
    quarantine_dir: Path
    require_distinct_approver: bool = False
    auto_response: Dict = field(default_factory=lambda: {"enabled": False, "rules": [], "allowed_actions": []})

    def execute_allowed(self) -> bool:
        return self.mode == "execute" and self.execute_unlocked is True


def _real(p) -> str:
    return os.path.normcase(os.path.realpath(str(p)))


def is_within(path, root) -> bool:
    a, r = _real(path), _real(root)
    try:
        return os.path.commonpath([a, r]) == r
    except ValueError:      # khác ổ đĩa
        return False


def _expand(value: str, env: Dict[str, str]) -> str:
    low = {k.lower(): v for k, v in env.items()}

    def sub(m):
        name = m.group(1).lower()
        if name not in low:
            raise PolicyError(f"biến môi trường không có: %{m.group(1)}%")
        return low[name]
    return re.sub(r"%([^%]+)%", sub, value)


def load_policy(path: Path, env: Optional[Dict[str, str]] = None) -> Policy:
    env = dict(os.environ) if env is None else env
    try:
        d = yaml.safe_load(Path(path).read_text(encoding="utf-8")) or {}
    except (OSError, yaml.YAMLError) as exc:
        raise PolicyError("không đọc được policy") from exc
    if not isinstance(d, dict) or set(d) - _KEYS:
        raise PolicyError(f"khóa không hỗ trợ: {sorted(set(d) - _KEYS) if isinstance(d, dict) else 'policy phải là mapping'}")
    if d.get("mode", "dry_run") not in ("dry_run", "execute"):
        raise PolicyError("mode phải là dry_run hoặc execute")
    acts = set(d.get("allowed_actions", []))
    if acts - ACTION_TYPES:
        raise PolicyError(f"action không hỗ trợ: {sorted(acts - ACTION_TYPES)}")
    for k in ("execute_unlocked", "require_distinct_approver"):
        if not isinstance(d.get(k, False), bool):
            raise PolicyError(f"{k} phải là true/false")
    if not d.get("lab_dirs") or not d.get("quarantine_dir"):
        raise PolicyError("cần lab_dirs và quarantine_dir")
    ar = d.get("auto_response") or {"enabled": False, "rules": [], "allowed_actions": []}
    return Policy(
        mode=d.get("mode", "dry_run"), execute_unlocked=d.get("execute_unlocked", False), allowed_actions=acts,
        protected_process_names={n.lower() for n in d.get("protected_process_names", [])},
        protected_dirs=[Path(_expand(x, env)) for x in d.get("protected_dirs", [])],
        lab_dirs=[Path(_expand(x, env)) for x in d["lab_dirs"]],
        lab_marker_prefix=d.get("lab_marker_prefix", "DACN_LAB_"),
        quarantine_dir=Path(_expand(d["quarantine_dir"], env)),
        require_distinct_approver=d.get("require_distinct_approver", False), auto_response=ar)


def _in_lab(p: Policy, path) -> bool:
    return any(is_within(path, r) for r in p.lab_dirs)


def _in_protected(p: Policy, path) -> bool:
    return any(is_within(path, r) for r in p.protected_dirs)


def check_process_target(p: Policy, target: dict, own_pid: int) -> Tuple[bool, Optional[str]]:
    """(ok, mã lý do). Thứ tự: PID bảo vệ, chính EDR, tên bảo vệ, thư mục bảo vệ, phải nằm trong thư mục lab."""
    pid, image = target.get("pid"), target.get("image_path")
    if not isinstance(pid, int) or not image:
        return False, "P-BAD_TARGET"
    if pid in PROTECTED_PIDS:
        return False, "P-PROTECTED_PID"
    if pid == own_pid:
        return False, "P-SELF"
    if re.split(r"[\\/]", str(image))[-1].lower() in p.protected_process_names:
        return False, "P-PROTECTED_NAME"
    if _in_protected(p, image):
        return False, "P-PROTECTED_PATH"
    if not _in_lab(p, image):
        return False, "P-NOT_LAB_TARGET"
    return True, None


def check_file_target(p: Policy, target: dict) -> Tuple[bool, Optional[str]]:
    path = target.get("path")
    if not path:
        return False, "P-BAD_TARGET"
    if _in_protected(p, path):
        return False, "P-PROTECTED_PATH"
    if not _in_lab(p, path):
        return False, "P-NOT_LAB_TARGET"
    if is_within(path, p.quarantine_dir):
        return False, "P-IN_QUARANTINE"
    return True, None


def check_restore_target(p: Policy, target: dict) -> Tuple[bool, Optional[str]]:
    q, orig = target.get("quarantined_to"), target.get("original_path")
    if not q or not orig:
        return False, "P-BAD_TARGET"
    if not is_within(q, p.quarantine_dir):
        return False, "P-NOT_IN_QUARANTINE"
    if _in_protected(p, orig) or not _in_lab(p, orig):
        return False, "P-NOT_LAB_TARGET"
    return True, None
