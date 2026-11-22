"""Mọi cờ --xxx trong lệnh `python -m <module>` của EDR_INSTALL_GUIDE.md và WINDOWS_ACCEPTANCE_CHECKLIST.md
phải tồn tại trong CLI thật (tránh hướng dẫn lệch code). Không chứng minh chạy được trên Windows."""
import re
import subprocess
import sys
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[1]
DOCS = [ROOT / "docs/implementation/EDR_INSTALL_GUIDE.md", ROOT / "docs/implementation/acceptance/WINDOWS_ACCEPTANCE_CHECKLIST.md"]
MODULES = {"edr_ctl": ["edr_ctl"], "agent": ["agent", "run"], "api.auth": ["api.auth"],
           "pipeline.retention": ["pipeline.retention"], "core": ["core"]}


def _help(mod_args):
    env = {"PYTHONPATH": f"{ROOT/'src'}:{ROOT/'src'/'pipeline'}:{ROOT/'poc'/'sysmon-collector'}", "PATH": "/usr/bin:/bin"}
    r = subprocess.run([sys.executable, "-m", *mod_args, "--help"], capture_output=True, text=True, env=env, cwd=ROOT, check=False)
    return r.stdout


def _uses():
    for doc in DOCS:
        for line in doc.read_text(encoding="utf-8").splitlines():
            m = re.search(r"python -m ([\w.]+)((?: [^\s`#]+)*)", line)
            if m and m.group(1) in MODULES:
                for flag in re.findall(r"(?<=\s)(--[a-z][\w-]*)", m.group(2)):
                    yield doc.name, m.group(1), flag


@pytest.mark.parametrize("doc,mod,flag", sorted(set(_uses())))
def test_flag_exists(doc, mod, flag):
    assert flag in _help(MODULES[mod]), f"{doc}: `python -m {mod}` không có {flag}"
