import copy
import hashlib
from datetime import datetime, timezone

import pytest

from static_analysis.knowledge import KnowledgeError, KnowledgeStore, validate_bundle

SHA = hashlib.sha256(b"safe").hexdigest()


def item(id="i", **kw):
    return {"id": id, "source": "synthetic-lab", "expires_at": "2099-01-01T00:00:00Z", **kw}


def test_activate_revision_conflict_invalid_update_and_rollback(tmp_path, bundle):
    store = KnowledgeStore(tmp_path)
    one = store.activate(bundle, expected_revision=None, actor="reviewer", reason="lab revision")
    bad = copy.deepcopy(bundle); bad["schema_version"] = "other/2"
    with pytest.raises(KnowledgeError): store.activate(bad, expected_revision=one, actor="r", reason="bad")
    assert store.snapshot()[0] == one
    with pytest.raises(KnowledgeError): store.activate(bundle, expected_revision="0" * 64, actor="r", reason="conflict")
    two_bundle = {**bundle, "version": 2}
    two = store.activate(two_bundle, expected_revision=one, actor="r", reason="upgrade")
    store.rollback(one, expected_revision=two, actor="r", reason="revert")
    assert store.snapshot() == (one, bundle)
    assert (tmp_path / "current.json").read_text().count("ROLLBACK") == 1


@pytest.mark.parametrize("field,value", [("sha256", "bad"), ("expires_at", "tomorrow"), ("source", "")])
def test_bad_indicator_rejected(bundle, field, value):
    bundle["indicators"] = [item(sha256=SHA)]; bundle["indicators"][0][field] = value
    with pytest.raises(KnowledgeError): validate_bundle(bundle)


def test_hash_expiry_is_evaluated_each_time_and_allowlist_retains_conflict_evidence(tmp_path, bundle):
    bundle["indicators"] = [item(sha256=SHA)]
    bundle["allowlist"] = [item("a", sha256=SHA)]
    store = KnowledgeStore(tmp_path)
    rev = store.activate(bundle, expected_revision=None, actor="r", reason="test")
    observation = {"status": "OK", "sha256": SHA, "pattern_ids": []}
    hit = store.match(observation, (rev, bundle), now=datetime(2030, 1, 1, tzinfo=timezone.utc))
    assert hit["verdict"] == "ALLOWLISTED" and hit["signature_hit"]["ioc_ids"] == ["i"]
    assert hit["signature_hit"]["suppressed"]
    expired = store.match(observation, (rev, bundle), now=datetime(2100, 1, 1, tzinfo=timezone.utc))
    assert expired["verdict"] == "NO_HIT"


def test_revision_bytes_tamper_detected(tmp_path, bundle):
    store = KnowledgeStore(tmp_path)
    rev = store.activate(bundle, expected_revision=None, actor="r", reason="test")
    (tmp_path / "revisions" / (rev + ".json")).write_text('{"schema_version":"dacn-knowledge/1.0","version":2,"indicators":[],"allowlist":[],"patterns":[]}', encoding="utf-8")
    with pytest.raises(KnowledgeError, match="HASH_MISMATCH"): store.snapshot()


def test_failed_pointer_publish_keeps_last_known_good(tmp_path, bundle, monkeypatch):
    import static_analysis.knowledge as module
    store = KnowledgeStore(tmp_path)
    rev = store.activate(bundle, expected_revision=None, actor="r", reason="test")
    real = module.atomic_json
    def fail(path, data):
        if path.name == "current.json": raise OSError("disk denied")
        return real(path, data)
    monkeypatch.setattr(module, "atomic_json", fail)
    with pytest.raises(OSError): store.activate({**bundle, "version": 2}, expected_revision=rev, actor="r", reason="new")
    assert store.snapshot()[0] == rev
