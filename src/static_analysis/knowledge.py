"""Kho JSON local: revision bất biến theo SHA-256, activate/rollback nguyên tử, không threat feed."""
from __future__ import annotations

import hashlib
import json
import os
import re
import tempfile
import threading
from datetime import datetime, timezone
from pathlib import Path

import jsonschema

HASH = r"^[a-fA-F0-9]{64}$"
ITEM = {"type": "object", "additionalProperties": False, "required": ["id", "source", "expires_at"],
        "properties": {"id": {"type": "string", "minLength": 1, "maxLength": 100},
                       "source": {"type": "string", "minLength": 1, "maxLength": 200},
                       "expires_at": {"type": "string", "format": "date-time"},
                       "sha256": {"type": "string", "pattern": HASH},
                       "hex": {"type": "string", "pattern": r"^(?:[a-fA-F0-9]{2}){1,256}$"}}}
KNOWLEDGE_SCHEMA = {
    "type": "object", "additionalProperties": False,
    "required": ["schema_version", "version", "indicators", "allowlist", "patterns"],
    "properties": {"schema_version": {"const": "dacn-knowledge/1.0"},
                   "version": {"type": "integer", "minimum": 1},
                   **{k: {"type": "array", "maxItems": 1000, "items": ITEM}
                      for k in ("indicators", "allowlist", "patterns")}}}


class KnowledgeError(ValueError):
    pass


def canonical(data):
    return json.dumps(data, sort_keys=True, separators=(",", ":"), ensure_ascii=False).encode("utf-8")


def revision(data):
    return hashlib.sha256(canonical(data)).hexdigest()


def expiry(item):
    return datetime.fromisoformat(item["expires_at"].replace("Z", "+00:00")).astimezone(timezone.utc)


def validate_bundle(data):
    try:
        jsonschema.validate(data, KNOWLEDGE_SCHEMA, format_checker=jsonschema.FormatChecker())
        for key in ("indicators", "allowlist", "patterns"):
            ids = set()
            for item in data[key]:
                needed = "hex" if key == "patterns" else "sha256"
                if needed not in item or ("sha256" if needed == "hex" else "hex") in item:
                    raise KnowledgeError("sai loại indicator/pattern")
                if item["id"] in ids:
                    raise KnowledgeError("trùng id")
                ids.add(item["id"])
                expiry(item)
        if len(canonical(data)) > 1024 * 1024:
            raise KnowledgeError("package quá lớn")
    except (jsonschema.ValidationError, TypeError, KeyError, ValueError) as exc:
        raise KnowledgeError("KNOWLEDGE_INVALID: " + str(exc)[:200]) from exc
    return data


def atomic_json(path, data):
    path = Path(path)
    path.parent.mkdir(parents=True, exist_ok=True)
    fd, temp = tempfile.mkstemp(dir=path.parent, prefix=".knowledge-", suffix=".tmp")
    try:
        with os.fdopen(fd, "wb") as f:
            f.write(canonical(data)); f.flush(); os.fsync(f.fileno())
        os.replace(temp, path)
    finally:
        if os.path.exists(temp):
            os.unlink(temp)


class KnowledgeStore:
    def __init__(self, root):
        self.root, self.lock = Path(root), threading.RLock()

    def _read(self, path):
        if path.stat().st_size > 2 * 1024 * 1024:
            raise KnowledgeError("package quá lớn")
        return json.loads(path.read_text(encoding="utf-8"))

    def _pointer(self):
        p = self.root / "current.json"
        return self._read(p) if p.exists() else {"revision": None, "history": []}

    def _load_revision(self, rev):
        if not isinstance(rev, str) or not re.fullmatch(r"[a-f0-9]{64}", rev):
            raise KnowledgeError("revision không hợp lệ")
        data = validate_bundle(self._read(self.root / "revisions" / (rev + ".json")))
        if revision(data) != rev:
            raise KnowledgeError("KNOWLEDGE_HASH_MISMATCH")
        return data

    def snapshot(self):
        with self.lock:
            rev = self._pointer()["revision"]
            if rev is None:
                return None, {"schema_version": "dacn-knowledge/1.0", "version": 1,
                              "indicators": [], "allowlist": [], "patterns": []}
            return rev, self._load_revision(rev)

    def _point(self, pointer, rev, actor, reason, operation):
        if not actor.strip() or not reason.strip():
            raise KnowledgeError("actor/reason bắt buộc")
        event = {"operation": operation, "revision": rev, "previous": pointer["revision"],
                 "actor": actor, "reason": reason, "at": datetime.now(timezone.utc).isoformat()}
        updated = {"revision": rev, "history": pointer["history"] + [event]}
        if len(canonical(updated)) > 2 * 1024 * 1024:
            raise KnowledgeError("HISTORY_LIMIT: cần archive có kiểm soát trước khi update")
        atomic_json(self.root / "current.json", updated)

    def activate(self, data, *, expected_revision, actor, reason):
        data = validate_bundle(data)
        with self.lock:
            pointer = self._pointer()
            if pointer["revision"] != expected_revision:
                raise KnowledgeError("REVISION_CONFLICT")
            if pointer["revision"] and data["version"] <= self._load_revision(pointer["revision"])["version"]:
                raise KnowledgeError("VERSION_NOT_INCREASING: dùng rollback riêng")
            rev = revision(data)
            atomic_json(self.root / "revisions" / (rev + ".json"), data)
            self._point(pointer, rev, actor, reason, "ACTIVATE")
            return rev

    def rollback(self, rev, *, expected_revision, actor, reason):
        with self.lock:
            pointer = self._pointer()
            if pointer["revision"] != expected_revision:
                raise KnowledgeError("REVISION_CONFLICT")
            self._load_revision(rev)
            if rev not in {x["revision"] for x in pointer["history"]}:
                raise KnowledgeError("revision chưa từng activate")
            self._point(pointer, rev, actor, reason, "ROLLBACK")
            return rev

    def match(self, analysis, snapshot, *, now=None):
        now = now or datetime.now(timezone.utc)
        rev, bundle = snapshot
        active = lambda key: [x for x in bundle[key] if expiry(x) > now]
        sha = analysis.get("sha256")
        iocs = [x["id"] for x in active("indicators") if x["sha256"].lower() == sha]
        allows = [x["id"] for x in active("allowlist") if x["sha256"].lower() == sha]
        patterns = [x["id"] for x in active("patterns") if x["id"] in analysis.get("pattern_ids", [])]
        verdict = "UNAVAILABLE" if analysis["status"] != "OK" else (
            "ALLOWLISTED" if allows else "HIT" if iocs or patterns else "NO_HIT")
        return {"schema_version": "dacn-whitelist-verdict/1.0", "knowledge_revision": rev,
                "knowledge_version": bundle["version"], "verdict": verdict, "allowlist_ids": allows,
                "signature_hit": {"schema_version": "dacn-signature-hit/1.0", "ioc_ids": iocs,
                                  "pattern_ids": patterns, "suppressed": bool(allows and (iocs or patterns))},
                "policy": "STATIC_ALLOWLIST_FIRST_BEHAVIOR_UNCHANGED", "evaluated_at": now.isoformat()}
