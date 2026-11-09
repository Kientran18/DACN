"""Response policy và cổng bảo vệ (PH7-T01). Mặc định dry_run; execute cần HAI khóa; fail closed.
Đây là NƠI DUY NHẤT quyết định chế độ response (mode + execute_unlocked); cấu hình edr.yaml không có khóa response.
Mục tiêu thật chỉ được nằm trong lab_dirs: tên/marker không đủ."""
from __future__ import annotations

import os
import re
from dataclasses import dataclass, field
from pathlib import Path
from typing import Dict, List, Optional, Set, Tuple

import yaml


class PolicyError(ValueError):
    pass


ACTION_TYPES = {"TERMINATE_PROCESS", "QUARANTINE_FILE", "RESTORE_FILE", "ADD_WHITELIST", "REMOVE_WHITELIST"}
_KEYS = {"mode", "execute_unlocked", "require_distinct_approver", "allowed_actions", "lab_dirs",
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
    quarantine_dir: Path
    require_distinct_approver: bool = True      # quy tắc hai người bật mặc định; demo một người dùng phải tắt
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
        quarantine_dir=Path(_expand(d["quarantine_dir"], env)),
        require_distinct_approver=d.get("require_distinct_approver", True), auto_response=ar)


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


_SHA256 = re.compile(r"^[0-9a-fA-F]{64}$")


def check_whitelist_target(p: Policy, target: dict) -> Tuple[bool, Optional[str]]:
    """ADD_WHITELIST/REMOVE_WHITELIST: đích là hash SHA-256 (không wildcard). ADD cần lý do (>= 5 ký tự) để có dấu vết.
    Không xét thư mục lab vì hành động chỉ sửa danh sách cho phép cục bộ, nhưng làm giảm phát hiện nên luôn qua phê duyệt."""
    sha = target.get("sha256")
    if not isinstance(sha, str) or not _SHA256.match(sha) or set(sha.lower()) == {"0"}:
        return False, "P-BAD_TARGET"
    return True, None


def check_add_whitelist_target(p: Policy, target: dict) -> Tuple[bool, Optional[str]]:
    ok, code = check_whitelist_target(p, target)
    if not ok:
        return ok, code
    if len(str(target.get("reason", "")).strip()) < 5:
        return False, "P-REASON_REQUIRED"
    return True, None
