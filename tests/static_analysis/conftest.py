import pytest


@pytest.fixture
def bundle():
    return {"schema_version": "dacn-knowledge/1.0", "version": 1, "indicators": [], "allowlist": [], "patterns": []}
