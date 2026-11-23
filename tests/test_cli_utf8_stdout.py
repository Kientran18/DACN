"""Windows: stdout qua ống dẫn/chuyển hướng (`| Tee-Object`, `> tệp`) dùng codepage ANSI (cp1252), không in được tiếng Việt.
Đo trên VM Windows: `--help` của edr_ctl, agent, pipeline.retention bị UnicodeEncodeError. Mọi CLI phải ép stdout UTF-8."""
import os
import subprocess
import sys
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[1]
CLIS = [["edr_ctl"], ["agent", "run"], ["core"], ["pipeline.retention"], ["api.auth"], ["response"], ["detection.ml.static_scorer"]]


@pytest.mark.parametrize("mod", CLIS, ids=lambda m: ".".join(m))
def test_help_prints_with_a_cp1252_pipe(mod):
    env = {**os.environ, "PYTHONIOENCODING": "cp1252",
           "PYTHONPATH": os.pathsep.join(str(ROOT / p) for p in ("src", "src/pipeline", "poc/sysmon-collector"))}
    r = subprocess.run([sys.executable, "-m", *mod, "--help"], capture_output=True, env=env, cwd=ROOT, timeout=60, check=False)
    assert r.returncode == 0, r.stderr.decode("utf-8", "replace")[-300:]
