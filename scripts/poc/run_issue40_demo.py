"""PoC W07 vô hại: bytes lab -> hash/pattern -> candidate -> review; không Sysmon/response/network."""
from __future__ import annotations

import argparse
import hashlib
import json
import sys
import tempfile
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
for relative in ("src", "src/pipeline", "poc/sysmon-collector"):
    sys.path.insert(0, str(ROOT / relative))

from pipeline.silver_store import SilverStore
from static_analysis.service import StaticWorkflow


def run_demo():
    with tempfile.TemporaryDirectory(prefix="dacn-issue40-") as temp:
        root = Path(temp)
        lab = root / "lab"; lab.mkdir()
        file = lab / "harmless.txt"; file.write_bytes(b"DACN-LAB-MARKER")
        sha = hashlib.sha256(file.read_bytes()).hexdigest()
        st = SilverStore(root / "silver.duckdb")
        try:
            wf = StaticWorkflow(st.con, [lab], root / "knowledge")
            wf.knowledge.activate({"schema_version": "dacn-knowledge/1.0", "version": 1,
                "indicators": [{"id": "lab-hash", "sha256": sha, "source": "synthetic-lab",
                                "expires_at": "2099-01-01T00:00:00Z"}], "allowlist": [],
                "patterns": [{"id": "lab-marker", "hex": b"LAB-MARKER".hex(), "source": "synthetic-lab",
                              "expires_at": "2099-01-01T00:00:00Z"}]},
                expected_revision=None, actor="lab-reviewer", reason="harmless lab fixture")
            row = wf.analyze(file, actor="lab-analyst")
            cid = row["candidate_id"]
            wf.candidates.transition(cid, "TRIAGED", expected_revision=1, actor="lab-analyst", role="analyst", reason="reviewed lab marker")
            final = wf.candidates.transition(cid, "SUSPICIOUS", expected_revision=2, actor="lab-reviewer", role="approver", reason="test review state only, not malware")
            assert final["analysis"]["sha256"] == sha and final["detection"]["outcome"] == "MATCH"
            assert final["verdict"]["signature_hit"]["pattern_ids"] == ["lab-marker"]
            assert st.con.execute("select count(*) from alerts").fetchone()[0] == 0
            assert st.con.execute("select count(*) from response_actions").fetchone()[0] == 0
            assert wf.candidates.audit.verify_audit() == []
            final["analysis"]["path"] = "<LAB_ROOT>/harmless.txt"  # redact đường dẫn máy thật khỏi artifact
            final["analysis"]["file_identity"] = None  # không xuất filesystem IDs của host
            return {"synthetic": True, "path_and_file_identity_redacted": True, "result": "PASS",
                    "scope": "current-byte standalone lab observation; no fabricated event refs; no response",
                    "candidate": final, "history": wf.candidates.history(cid)}
        finally:
            st.close()


if __name__ == "__main__":
    ap = argparse.ArgumentParser()
    ap.add_argument("--out", type=Path, required=True)
    args = ap.parse_args()
    result = run_demo()
    args.out.parent.mkdir(parents=True, exist_ok=True)
    args.out.write_text(json.dumps(result, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")
    print("PASS: harmless lab hash/pattern -> candidate -> triage/review; no alert without source, no response")
