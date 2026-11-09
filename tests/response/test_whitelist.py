"""ADD_WHITELIST / REMOVE_WHITELIST (dữ liệu synthetic; sửa tệp ioc.yaml trong thư mục tạm)."""
import yaml
import pytest

from detection.ioc import IocStore
from response.actions import ActionStore
from response.backends.dryrun import DryRunBackend
from response.backends.local import LocalBackend, FakeProcessApi
from response.executor import Executor, precheck
from response.policy import Policy
from alerts.store import AlertStore
from pipeline.silver_store import SilverStore

SHA = "a" * 63 + "b"
ACTS = {"ADD_WHITELIST", "REMOVE_WHITELIST", "QUARANTINE_FILE"}


@pytest.fixture
def env(tmp_path):
    st = SilverStore(tmp_path / "s.duckdb")
    pol = Policy(mode="execute", execute_unlocked=True, allowed_actions=ACTS, protected_process_names=set(),
                 protected_dirs=[], lab_dirs=[tmp_path / "lab"], quarantine_dir=tmp_path / "lab" / "q",
                 require_distinct_approver=False)
    acts = ActionStore(st.con, AlertStore(st.con))
    ioc = tmp_path / "ioc" / "ioc.yaml"
    ex = Executor(pol, acts, LocalBackend(FakeProcessApi({}), [tmp_path / "lab"]), DryRunBackend(), ioc_path=ioc)
    return pol, acts, ex, ioc


def run(acts, ex, typ, target, mode="execute"):
    aid = acts.request(typ, target, requested_by="a", requested_mode=mode)
    acts.approve(aid, approver="b", reason="đã xem")
    return ex.run(aid)


def test_precheck_rejects_bad_hash_and_missing_reason(env):
    pol = env[0]
    assert precheck(pol, "ADD_WHITELIST", {"sha256": "xyz", "reason": "đủ dài"}) == (False, "P-BAD_TARGET")
    assert precheck(pol, "ADD_WHITELIST", {"sha256": "0" * 64, "reason": "đủ dài"}) == (False, "P-BAD_TARGET")
    assert precheck(pol, "ADD_WHITELIST", {"sha256": SHA}) == (False, "P-REASON_REQUIRED")
    assert precheck(pol, "ADD_WHITELIST", {"sha256": SHA, "reason": "phần mềm nội bộ"}) == (True, None)
    assert precheck(pol, "REMOVE_WHITELIST", {"sha256": SHA}) == (True, None)


def test_add_then_ioc_store_allowlists_and_rollback_removes(env):
    _, acts, ex, ioc = env
    r = run(acts, ex, "ADD_WHITELIST", {"sha256": SHA.upper(), "reason": "phần mềm nội bộ"})
    assert r["status"] == "DONE" and r["rollback"]["action"] == "REMOVE_WHITELIST"
    assert IocStore(ioc).check(SHA) == ("ALLOWLISTED", None)
    assert yaml.safe_load(ioc.read_text(encoding="utf-8"))["allowlist_meta"][SHA]["reason"] == "phần mềm nội bộ"
    r2 = run(acts, ex, r["rollback"]["action"], r["rollback"]["target"])
    assert r2["status"] == "DONE" and IocStore(ioc).check(SHA) == (None, None)


def test_add_twice_and_ioc_conflict_fail_without_change(env):
    _, acts, ex, ioc = env
    ioc.parent.mkdir(parents=True)
    ioc.write_text(yaml.safe_dump({"version": 1, "ioc_hashes": [{"sha256": "c" * 64, "source": "lab"}]}), encoding="utf-8")
    assert run(acts, ex, "ADD_WHITELIST", {"sha256": "c" * 64, "reason": "thử xung đột"})["result"]["code"] == "X-IOC_CONFLICT"
    run(acts, ex, "ADD_WHITELIST", {"sha256": SHA, "reason": "lần một nội bộ"})
    assert run(acts, ex, "ADD_WHITELIST", {"sha256": SHA, "reason": "lần hai nội bộ"})["result"]["code"] == "X-ALREADY_ALLOWLISTED"
    d = yaml.safe_load(ioc.read_text(encoding="utf-8"))
    assert d["allowlist_hashes"] == [SHA] and d["ioc_hashes"][0]["sha256"] == "c" * 64     # IOC giữ nguyên


def test_dry_run_does_not_write(env):
    _, acts, ex, ioc = env
    r = run(acts, ex, "ADD_WHITELIST", {"sha256": SHA, "reason": "chỉ mô phỏng"}, mode="dry_run")
    assert r["status"] == "DONE" and r["result"]["mode"] == "dry_run" and not ioc.exists()


def test_corrupt_ioc_file_is_not_overwritten(env):
    _, acts, ex, ioc = env
    ioc.parent.mkdir(parents=True)
    ioc.write_text("- đây không phải mapping", encoding="utf-8")
    r = run(acts, ex, "ADD_WHITELIST", {"sha256": SHA, "reason": "tệp hỏng"})
    assert r["result"]["code"] == "X-IOC_FILE_INVALID" and ioc.read_text(encoding="utf-8").startswith("- đây")


def test_remove_not_allowlisted_fails(env):
    _, acts, ex, _ = env
    assert run(acts, ex, "REMOVE_WHITELIST", {"sha256": SHA})["result"]["code"] == "X-NOT_ALLOWLISTED"


def test_action_not_in_policy_is_blocked(env):
    pol, acts, ex, _ = env
    pol.allowed_actions = {"QUARANTINE_FILE"}
    assert run(acts, ex, "ADD_WHITELIST", {"sha256": SHA, "reason": "bị chặn"})["result"]["code"] == "P-ACTION_NOT_ALLOWED"
