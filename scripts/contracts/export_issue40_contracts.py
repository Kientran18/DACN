"""Export contracts/examples W06/W07 từ source; không đọc mẫu máy thật hoặc gọi API mạng."""
from __future__ import annotations

import hashlib
import json
import math
import sys
import tempfile
from collections import Counter
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
for relative in ("src", "src/pipeline", "poc/sysmon-collector"):
    sys.path.insert(0, str(ROOT / relative))

from detection.schema import DETECTION_RESULT_SCHEMA, RULE_SCHEMA
from detection.result import DetectionResult
from static_analysis.contracts import CONTRACTS
from static_analysis.knowledge import revision

ERROR_SCHEMA = {"type": "object", "additionalProperties": False,
                "required": ["schema_version", "stage", "reason_code", "run_id", "retryable", "source_event_ids"],
                "properties": {"schema_version": {"const": "dacn-detection-error/1.0"},
                               "stage": {"enum": ["LOAD", "READ", "EVALUATE", "PUBLISH"]},
                               "reason_code": {"type": "string"}, "run_id": {"type": "string"},
                               "rule_id": {"type": ["string", "null"]}, "retryable": {"type": "boolean"},
                               "source_event_ids": {"type": "array", "items": {"type": "string"}}}}


def outputs():
    w6, w7 = "docs/architecture/w6/contracts/", "docs/architecture/w7/contracts/"
    out = {w6 + "rule.schema.json": RULE_SCHEMA, w6 + "detection-result.schema.json": DETECTION_RESULT_SCHEMA,
           w6 + "detection-error.schema.json": ERROR_SCHEMA}
    for name, schema in CONTRACTS.items():
        out[w7 + name + ".schema.json"] = schema
    results = [DetectionResult(rule_id="DACN-DET-010", rule_version=1, outcome=state, subject="synthetic-subject",
                               contributing_event_ids=[], coverage_status="SYNTHETIC_EXAMPLE",
                               missing_fields=["delete"] if state != "MATCH" else [],
                               severity="medium" if state == "MATCH" else None,
                               severity_reason="synthetic example; not a confirmed threat",
                               dedup_key="synthetic-key").to_dict()
               for state in ("MATCH", "NO_MATCH", "INSUFFICIENT_TELEMETRY", "PENDING_LATE_EVENTS")]
    error = {"schema_version": "dacn-detection-error/1.0", "stage": "PUBLISH", "reason_code": "DB_UNAVAILABLE",
             "run_id": "synthetic-run", "retryable": True, "source_event_ids": []}
    out[w6 + "examples.json"] = {"synthetic": True, "results": results, "error": error}
    data = b"harmless"
    sha = hashlib.sha256(data).hexdigest()
    bundle = {"schema_version": "dacn-knowledge/1.0", "version": 1,
              "indicators": [{"id": "lab-sha", "sha256": sha, "source": "synthetic-lab",
                              "expires_at": "2099-01-01T00:00:00Z"}], "allowlist": [],
              "patterns": [{"id": "lab-marker", "hex": b"harm".hex(), "source": "synthetic-lab",
                            "expires_at": "2099-01-01T00:00:00Z"}]}
    analysis = {"schema_version": "dacn-static/1.0", "analysis_id": "11111111-2222-4333-8444-555555555555",
                "observed_at": "2026-11-17T00:00:00Z", "extractor_version": "1.0",
                "path": "C:\\EDR\\lab\\harmless.txt", "source_event_ids": [], "status": "OK", "error_code": None,
                "sha256": sha, "size_bytes": len(data),
                "entropy": -sum(n / len(data) * math.log2(n / len(data)) for n in Counter(data).values()),
                "file_identity": [0, 0, len(data), 0, 0], "pe": {"status": "NOT_PE", "value": None},
                "signature": {"status": "UNAVAILABLE", "reason": "NO_OFFLINE_TRUST_PROVIDER"},
                "pattern_ids": ["lab-marker"], "historical_identity": "UNVERIFIED"}
    hit = {"schema_version": "dacn-signature-hit/1.0", "ioc_ids": ["lab-sha"], "pattern_ids": ["lab-marker"], "suppressed": False}
    verdict = {"schema_version": "dacn-whitelist-verdict/1.0", "knowledge_revision": revision(bundle), "knowledge_version": 1,
               "verdict": "HIT", "allowlist_ids": [], "signature_hit": hit,
               "policy": "STATIC_ALLOWLIST_FIRST_BEHAVIOR_UNCHANGED", "evaluated_at": "2026-11-17T00:00:01Z"}
    candidate = {"schema_version": "dacn-candidate/1.0", "candidate_id": "66666666-7777-4888-8999-000000000000",
                 "state": "NEW", "revision": 1, "created_by": "lab-analyst", "analysis": analysis, "verdict": verdict,
                 "detection": {**results[0], "rule_id": "DACN-STATIC-001"}, "alert_ids": [], "created_at": "2026-11-17T00:00:01Z"}
    out[w7 + "examples.json"] = {"synthetic": True, "knowledge": bundle, "static_result": analysis,
                                  "error_result": {**analysis, "status": "ERROR", "error_code": "NOT_FOUND", "sha256": None,
                                                   "size_bytes": None, "entropy": None, "file_identity": None, "pattern_ids": [],
                                                   "pe": {"status": "UNAVAILABLE", "value": None}},
                                  "signature_hit": hit, "whitelist_verdict": verdict, "candidate": candidate}
    return out


def export_static_openapi():
    """Schema HTTP từ routes thật, chỉ giữ component được static paths tham chiếu."""
    from api.app import create_app
    from api.auth import TokenStore
    from common.config import Config
    from pipeline.silver_store import SilverStore
    from response.policy import Policy
    with tempfile.TemporaryDirectory(prefix="dacn-openapi-") as temp:
        home = Path(temp)
        store = SilverStore(home / "schema.duckdb")
        try:
            policy = Policy(mode="dry_run", execute_unlocked=False, allowed_actions=set(), protected_process_names=set(),
                            protected_dirs=[], lab_dirs=[home / "lab"], quarantine_dir=home / "lab/q")
            app = create_app(Config(home=home), TokenStore({}), store=store, rules={}, policy=policy, bronze_dir=home / "bronze")
            spec = app.openapi()
            paths = {k: v for k, v in spec["paths"].items() if k.startswith("/static/")}
            pending, schemas = [paths], {}
            while pending:
                part = pending.pop()
                if isinstance(part, dict):
                    ref = part.get("$ref", "")
                    if ref.startswith("#/components/schemas/"):
                        name = ref.split("/")[-1]
                        if name not in schemas:
                            schemas[name] = spec["components"]["schemas"][name]
                            pending.append(schemas[name])
                    pending.extend(part.values())
                elif isinstance(part, list):
                    pending.extend(part)
            return {"openapi": spec["openapi"], "info": {"title": "DACN W07 Static API", "version": "1.0-proposal"},
                    "paths": paths, "components": {"schemas": schemas}}
        finally:
            store.close()


if __name__ == "__main__":
    for relative, value in outputs().items():
        path = ROOT / relative
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(json.dumps(value, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")
    (ROOT / "docs/architecture/w7/contracts/openapi-static.json").write_text(
        json.dumps(export_static_openapi(), ensure_ascii=False, indent=2) + "\n", encoding="utf-8")
    print("Exported W06/W07 schemas and synthetic examples")
