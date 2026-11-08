import json
import os
import sys
from pathlib import Path

import pytest
import yaml

from alerts.store import AlertStore
from pipeline.silver_store import SilverStore
from response.actions import ActionStore, ActionError
from response.backends.dryrun import DryRunBackend
from response.backends.local import LocalBackend, FakeProcessApi
from response.executor import Executor
from response.policy import Policy, PolicyError, load_policy, check_file_target, check_process_target

POLICY_YAML = Path(__file__).resolve().parents[2] / "config" / "response-policy.yaml"


def mk_policy(tmp_path, **kw):
    base = dict(mode="dry_run", execute_unlocked=False, allowed_actions={"TERMINATE_PROCESS", "QUARANTINE_FILE", "RESTORE_FILE"},
                protected_process_names={"lsass.exe", "explorer.exe", "system"}, protected_dirs=[tmp_path / "Windows"],
                lab_dirs=[tmp_path / "lab"], lab_marker_prefix="DACN_LAB_", quarantine_dir=tmp_path / "lab" / "quarantine",
                require_distinct_approver=False, auto_response={"enabled": False, "rules": [], "allowed_actions": []})
    base.update(kw)
    return Policy(**base)


@pytest.fixture
def env(tmp_path):
    st = SilverStore(tmp_path / "s.duckdb")
    (tmp_path / "lab").mkdir()
    return st, ActionStore(st.con, AlertStore(st.con)), tmp_path


def proc_target(tmp_path, pid=500, image=None, ct=1000):
    return {"pid": pid, "creation_time": ct, "image_path": str(image or tmp_path / "lab" / "DACN_LAB_x_whoami.exe")}


def approved(actions, type_, target, mode="execute", approver="boss", requester="analyst"):
    aid = actions.request(type_, target, requested_by=requester, requested_mode=mode)
    actions.approve(aid, approver=approver, reason="đã xem bằng chứng")
    return aid


# ---- policy -----------------------------------------------------------------
def test_shipped_policy_is_dry_run_and_locked():
    p = load_policy(POLICY_YAML, env={"TEMP": "T", "PUBLIC": "P", "SystemRoot": "S", "ProgramFiles": "PF", "ProgramFiles(x86)": "PF86"})
    assert p.mode == "dry_run" and p.execute_unlocked is False and p.auto_response["enabled"] is False
    assert not p.execute_allowed()


def test_execute_needs_both_locks(tmp_path):
    assert not mk_policy(tmp_path, mode="execute", execute_unlocked=False).execute_allowed()
    assert not mk_policy(tmp_path, mode="dry_run", execute_unlocked=True).execute_allowed()
    assert mk_policy(tmp_path, mode="execute", execute_unlocked=True).execute_allowed()


def test_invalid_policy_rejected(tmp_path):
    bad = tmp_path / "p.yaml"; bad.write_text("mode: yolo\n")
    with pytest.raises(PolicyError):
        load_policy(bad, env={})
    bad.write_text(POLICY_YAML.read_text().replace("%TEMP%", "%NOPE%"))
    with pytest.raises(PolicyError):
        load_policy(bad, env={"PUBLIC": "P", "SystemRoot": "S", "ProgramFiles": "x", "ProgramFiles(x86)": "y"})


@pytest.mark.parametrize("name", ["lsass.exe", "LSASS.EXE", "explorer.exe", "System"])
def test_protected_process_names_always_denied_even_in_lab(tmp_path, name):
    p = mk_policy(tmp_path)
    ok, code = check_process_target(p, {"pid": 9, "creation_time": 1, "image_path": str(tmp_path / "lab" / name)}, own_pid=1)
    assert not ok and code == "P-PROTECTED_NAME"


def test_protected_dir_and_non_lab_and_self_denied(tmp_path):
    p = mk_policy(tmp_path)
    assert check_process_target(p, {"pid": 9, "creation_time": 1, "image_path": str(tmp_path / "Windows" / "x.exe")}, 1)[1] == "P-PROTECTED_PATH"
    assert check_process_target(p, {"pid": 9, "creation_time": 1, "image_path": str(tmp_path / "other" / "x.exe")}, 1)[1] == "P-NOT_LAB_TARGET"
    assert check_process_target(p, proc_target(tmp_path, pid=77), own_pid=77)[1] == "P-SELF"
    assert check_process_target(p, proc_target(tmp_path, pid=4), own_pid=1)[1] == "P-PROTECTED_PID"


def test_marker_in_name_outside_lab_dir_is_still_denied_path_traversal(tmp_path):
    p = mk_policy(tmp_path)
    t = {"pid": 9, "creation_time": 1, "image_path": str(tmp_path / "lab" / ".." / "elsewhere" / "DACN_LAB_x.exe")}
    assert check_process_target(p, t, 1)[0] is False


def test_file_target_must_be_inside_lab(tmp_path):
    p = mk_policy(tmp_path)
    assert check_file_target(p, {"path": str(tmp_path / "lab" / "a.exe")})[0]
    assert check_file_target(p, {"path": str(tmp_path / "x" / "a.exe")})[1] == "P-NOT_LAB_TARGET"
    assert check_file_target(p, {"path": str(tmp_path / "Windows" / "a.exe")})[1] == "P-PROTECTED_PATH"


# ---- action state machine -------------------------------------------------------
def test_action_lifecycle_and_invalid_transitions(env):
    st, actions, tmp = env
    aid = actions.request("TERMINATE_PROCESS", proc_target(tmp), requested_by="a", requested_mode="dry_run")
    with pytest.raises(ActionError):
        actions.mark_executing(aid)          # chưa được duyệt
    actions.approve(aid, approver="b", reason="ok")
    with pytest.raises(ActionError):
        actions.approve(aid, approver="b", reason="lần hai")
    assert actions.get(aid)["status"] == "APPROVED"


def test_reject_and_empty_reason(env):
    st, actions, tmp = env
    aid = actions.request("QUARANTINE_FILE", {"path": "x"}, requested_by="a", requested_mode="dry_run")
    with pytest.raises(ValueError):
        actions.reject(aid, approver="b", reason="")
    actions.reject(aid, approver="b", reason="không đủ bằng chứng")
    assert actions.get(aid)["status"] == "REJECTED"


def test_unknown_action_type_rejected(env):
    st, actions, tmp = env
    with pytest.raises(ActionError):
        actions.request("FORMAT_DISK", {}, requested_by="a", requested_mode="dry_run")


def test_distinct_approver_enforced_when_configured(env):
    st, actions, tmp = env
    actions.require_distinct = True
    aid = actions.request("TERMINATE_PROCESS", proc_target(tmp), requested_by="a", requested_mode="dry_run")
    with pytest.raises(ActionError):
        actions.approve(aid, approver="a", reason="tự duyệt")


# ---- executor ----------------------------------------------------------------------
def test_dry_run_changes_nothing_and_records_plan(env):
    st, actions, tmp = env
    api = FakeProcessApi({500: {"creation_time": 1000, "image_path": proc_target(tmp)["image_path"]}})
    ex = Executor(mk_policy(tmp), actions, LocalBackend(api, [tmp / "lab"]), DryRunBackend(), own_pid=1)
    aid = approved(actions, "TERMINATE_PROCESS", proc_target(tmp), mode="execute")
    res = ex.run(aid)
    assert res["status"] == "DONE" and res["result"]["mode"] == "dry_run" and api.terminated == []


def test_execute_blocked_without_both_locks_falls_back_to_dry_run(env):
    st, actions, tmp = env
    api = FakeProcessApi({500: {"creation_time": 1000, "image_path": proc_target(tmp)["image_path"]}})
    ex = Executor(mk_policy(tmp, mode="execute", execute_unlocked=False), actions, LocalBackend(api, [tmp / "lab"]), DryRunBackend(), own_pid=1)
    res = ex.run(approved(actions, "TERMINATE_PROCESS", proc_target(tmp)))
    assert res["result"]["mode"] == "dry_run" and api.terminated == []


def test_execute_terminates_verified_lab_process(env):
    st, actions, tmp = env
    api = FakeProcessApi({500: {"creation_time": 1000, "image_path": proc_target(tmp)["image_path"]}})
    ex = Executor(mk_policy(tmp, mode="execute", execute_unlocked=True), actions, LocalBackend(api, [tmp / "lab"]), DryRunBackend(), own_pid=1)
    res = ex.run(approved(actions, "TERMINATE_PROCESS", proc_target(tmp)))
    assert res["status"] == "DONE" and api.terminated == [500]
    assert res["rollback"]["possible"] is False


def test_pid_reuse_is_refused(env):
    st, actions, tmp = env
    api = FakeProcessApi({500: {"creation_time": 9999, "image_path": proc_target(tmp)["image_path"]}})   # PID tái sử dụng
    ex = Executor(mk_policy(tmp, mode="execute", execute_unlocked=True), actions, LocalBackend(api, [tmp / "lab"]), DryRunBackend(), own_pid=1)
    res = ex.run(approved(actions, "TERMINATE_PROCESS", proc_target(tmp)))
    assert res["status"] == "FAILED" and res["result"]["code"] == "X-IDENTITY_MISMATCH" and api.terminated == []


def test_process_gone_is_refused(env):
    st, actions, tmp = env
    api = FakeProcessApi({})
    ex = Executor(mk_policy(tmp, mode="execute", execute_unlocked=True), actions, LocalBackend(api, [tmp / "lab"]), DryRunBackend(), own_pid=1)
    assert ex.run(approved(actions, "TERMINATE_PROCESS", proc_target(tmp)))["result"]["code"] == "X-TARGET_GONE"


def test_protected_target_denied_before_backend_even_if_approved(env):
    st, actions, tmp = env
    t = {"pid": 600, "creation_time": 1, "image_path": str(tmp / "lab" / "lsass.exe")}
    api = FakeProcessApi({600: {"creation_time": 1, "image_path": t["image_path"]}})
    ex = Executor(mk_policy(tmp, mode="execute", execute_unlocked=True), actions, LocalBackend(api, [tmp / "lab"]), DryRunBackend(), own_pid=1)
    res = ex.run(approved(actions, "TERMINATE_PROCESS", t))
    assert res["status"] == "FAILED" and res["result"]["code"] == "P-PROTECTED_NAME" and api.terminated == []


def test_unapproved_action_not_executed(env):
    st, actions, tmp = env
    api = FakeProcessApi({500: {"creation_time": 1000, "image_path": proc_target(tmp)["image_path"]}})
    ex = Executor(mk_policy(tmp, mode="execute", execute_unlocked=True), actions, LocalBackend(api, [tmp / "lab"]), DryRunBackend(), own_pid=1)
    aid = actions.request("TERMINATE_PROCESS", proc_target(tmp), requested_by="a", requested_mode="execute")
    with pytest.raises(ActionError):
        ex.run(aid)
    assert api.terminated == []


def test_action_type_not_in_policy_denied(env):
    st, actions, tmp = env
    ex = Executor(mk_policy(tmp, allowed_actions={"QUARANTINE_FILE"}), actions, LocalBackend(FakeProcessApi({}), [tmp / "lab"]), DryRunBackend(), own_pid=1)
    res = ex.run(approved(actions, "TERMINATE_PROCESS", proc_target(tmp)))
    assert res["result"]["code"] == "P-ACTION_NOT_ALLOWED"


# ---- quarantine / restore (tệp thật trong thư mục tạm của test) ---------------------------
def mk_file(tmp, name="DACN_LAB_x_drop.bin", content=b"harmless"):
    f = tmp / "lab" / name
    f.write_bytes(content)
    import hashlib
    return f, hashlib.sha256(content).hexdigest()


def test_quarantine_moves_file_records_hash_and_restore_matches(env):
    st, actions, tmp = env
    f, sha = mk_file(tmp)
    ex = Executor(mk_policy(tmp, mode="execute", execute_unlocked=True), actions, LocalBackend(FakeProcessApi({}), [tmp / "lab"]), DryRunBackend(), own_pid=1)
    res = ex.run(approved(actions, "QUARANTINE_FILE", {"path": str(f), "expected_sha256": sha}))
    assert res["status"] == "DONE" and not f.exists()
    q = Path(res["result"]["quarantined_to"])
    assert q.exists() and res["result"]["sha256"] == sha
    meta = json.loads(Path(str(q) + ".json").read_text())
    assert meta["original_path"] == str(f) and meta["sha256"] == sha
    # restore
    rb = res["rollback"]
    assert rb["possible"] is True
    res2 = ex.run(approved(actions, "RESTORE_FILE", rb["target"]))
    assert res2["status"] == "DONE" and f.read_bytes() == b"harmless" and not q.exists()


def test_quarantine_refuses_hash_mismatch_and_leaves_file(env):
    st, actions, tmp = env
    f, _ = mk_file(tmp)
    ex = Executor(mk_policy(tmp, mode="execute", execute_unlocked=True), actions, LocalBackend(FakeProcessApi({}), [tmp / "lab"]), DryRunBackend(), own_pid=1)
    res = ex.run(approved(actions, "QUARANTINE_FILE", {"path": str(f), "expected_sha256": "0" * 64}))
    assert res["result"]["code"] == "X-HASH_MISMATCH" and f.exists()


def test_quarantine_outside_lab_denied(env):
    st, actions, tmp = env
    outside = tmp / "outside.bin"; outside.write_bytes(b"x")
    ex = Executor(mk_policy(tmp, mode="execute", execute_unlocked=True), actions, LocalBackend(FakeProcessApi({}), [tmp / "lab"]), DryRunBackend(), own_pid=1)
    res = ex.run(approved(actions, "QUARANTINE_FILE", {"path": str(outside)}))
    assert res["result"]["code"] == "P-NOT_LAB_TARGET" and outside.exists()


def test_restore_refuses_overwrite_and_tampered_quarantine(env):
    st, actions, tmp = env
    f, sha = mk_file(tmp)
    ex = Executor(mk_policy(tmp, mode="execute", execute_unlocked=True), actions, LocalBackend(FakeProcessApi({}), [tmp / "lab"]), DryRunBackend(), own_pid=1)
    res = ex.run(approved(actions, "QUARANTINE_FILE", {"path": str(f)}))
    rb = res["rollback"]["target"]
    f.write_bytes(b"new file at same path")
    assert ex.run(approved(actions, "RESTORE_FILE", rb))["result"]["code"] == "X-DEST_EXISTS"
    f.unlink()
    Path(rb["quarantined_to"]).write_bytes(b"tampered")
    assert ex.run(approved(actions, "RESTORE_FILE", rb))["result"]["code"] == "X-HASH_MISMATCH"


def test_dry_run_quarantine_leaves_file(env):
    st, actions, tmp = env
    f, _ = mk_file(tmp)
    ex = Executor(mk_policy(tmp), actions, LocalBackend(FakeProcessApi({}), [tmp / "lab"]), DryRunBackend(), own_pid=1)
    res = ex.run(approved(actions, "QUARANTINE_FILE", {"path": str(f)}))
    assert res["result"]["mode"] == "dry_run" and f.exists()


# ---- audit ------------------------------------------------------------------------------
def test_every_execution_is_audited_before_and_after_with_intact_chain(env):
    st, actions, tmp = env
    api = FakeProcessApi({500: {"creation_time": 1000, "image_path": proc_target(tmp)["image_path"]}})
    ex = Executor(mk_policy(tmp, mode="execute", execute_unlocked=True), actions, LocalBackend(api, [tmp / "lab"]), DryRunBackend(), own_pid=1)
    ex.run(approved(actions, "TERMINATE_PROCESS", proc_target(tmp)))
    acts = [r[0] for r in st.con.execute("select action from audit_log order by seq").fetchall()]
    assert acts.index("RESPONSE_EXEC_BEGIN") < acts.index("RESPONSE_EXEC_END")
    assert {"RESPONSE_REQUEST", "RESPONSE_APPROVE"} <= set(acts)
    assert actions.audit.verify_audit() == []


# ---- auto response (T08) và block hash (T09) --------------------------------------------------
def test_auto_response_off_by_default(env):
    from response.auto import AutoResponder
    st, actions, tmp = env
    ar = AutoResponder(mk_policy(tmp), actions)
    assert ar.propose({"alert_id": "a", "rule_id": "DACN-DET-010", "coverage_status": "FULL"},
                      "QUARANTINE_FILE", {"path": "x"}) is None


def test_auto_response_requires_every_gate(env):
    from response.auto import AutoResponder
    st, actions, tmp = env
    on = dict(enabled=True, rules=["DACN-DET-010"], allowed_actions=["QUARANTINE_FILE"])
    alert = {"alert_id": "a", "rule_id": "DACN-DET-010", "coverage_status": "FULL"}
    # thiếu khóa execute
    assert AutoResponder(mk_policy(tmp, auto_response=on), actions).propose(alert, "QUARANTINE_FILE", {"path": "x"}) is None
    p = mk_policy(tmp, mode="execute", execute_unlocked=True, auto_response=on)
    ar = AutoResponder(p, actions)
    assert ar.propose({**alert, "coverage_status": "PARTIAL_CHAIN"}, "QUARANTINE_FILE", {"path": "x"}) is None
    assert ar.propose({**alert, "rule_id": "DACN-DET-001"}, "QUARANTINE_FILE", {"path": "x"}) is None
    assert ar.propose(alert, "TERMINATE_PROCESS", {"pid": 1}) is None
    aid = ar.propose(alert, "QUARANTINE_FILE", {"path": "x"})
    assert aid and actions.get(aid)["approved_by"] == "policy:auto"


def test_block_hash_is_detection_only_and_flagged_later(tmp_path):
    from response.blockhash import block_hash
    from detection.ioc import IocStore
    f = tmp_path / "ioc.yaml"
    sha = "e" * 64
    msg = block_hash(f, sha, actor="analyst", reason="xác nhận độc hại", audit=None)
    assert "không ngăn" in msg
    s = IocStore(f)
    assert s.check(sha)[0] == "IOC_MATCH" and s.hashes[sha]["source"] == "analyst-block"
    with pytest.raises(ValueError):
        block_hash(f, "xyz", actor="a", reason="r", audit=None)


# ---- responder (T07) -----------------------------------------------------------------------
def test_responder_executes_only_approved_and_reports(env):
    from response.responder import Responder
    st, actions, tmp = env
    api = FakeProcessApi({})
    ex = Executor(mk_policy(tmp), actions, LocalBackend(api, [tmp / "lab"]), DryRunBackend(), own_pid=1)
    a1 = approved(actions, "TERMINATE_PROCESS", proc_target(tmp))
    actions.request("TERMINATE_PROCESS", proc_target(tmp, pid=501), requested_by="a", requested_mode="dry_run")
    reports = []
    n = Responder(lambda: actions.list_by_status("APPROVED"), ex, lambda aid, r: reports.append((aid, r["status"]))).run_once()
    assert n == 1 and reports == [(a1, "DONE")]


# ---- backend Windows & factory (không chạy được ở đây) ------------------------------------------------
def test_windows_api_refuses_to_construct_on_other_os():
    from response.backends.windows import WinProcessApi
    if sys.platform == "win32":
        pytest.skip("Linux only")
    with pytest.raises(RuntimeError):
        WinProcessApi()


def test_factory_never_enables_execute_on_non_windows(env):
    from response.factory import make_executor
    st, actions, tmp = env
    if sys.platform == "win32":
        pytest.skip("Linux only")
    with pytest.raises(RuntimeError):
        make_executor(mk_policy(tmp, mode="execute", execute_unlocked=True), actions)
    assert make_executor(mk_policy(tmp), actions) is not None      # dry_run vẫn dựng được


def test_creation_time_iso_tolerance_and_filetime_conversion():
    from response.backends.local import same_time
    from response.backends.windows import filetime_to_iso
    assert same_time("2026-11-08 09:11:55.836", "2026-11-08T09:11:55.9+00:00", 1.0)
    assert not same_time("2026-11-08 09:11:55", "2026-11-08 09:12:55", 1.0)
    assert not same_time("rác", "2026-11-08 09:12:55", 1.0)
    assert filetime_to_iso(116444736000000000).startswith("1970-01-01T00:00:00")
