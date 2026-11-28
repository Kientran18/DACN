"""Hạng mục 8 (docs/architecture/w8 mục 2.7, P1): API che chuỗi giống bí mật trong script PowerShell 4104 theo mặc định;
xem bản gốc cần quyền `raw` và được ghi audit. Dữ liệu SYNTHETIC; chuỗi "bí mật" là giả và được ghép lúc chạy."""
import json
from xml.sax.saxutils import escape

import pytest
from fastapi.testclient import TestClient

import bronze_contract as bc
from agent.bronze_writer import BronzeWriter
from alerts.builder import build_from_results
from alerts.store import AlertStore
from api.app import create_app
from api.auth import TokenStore, hash_token
from common.config import Config
from common.redact import MASK, redact
from detection.engine import DetectionEngine
from detection.loader import load_rules
from pipeline.silver_store import SilverStore
from response.policy import Policy

TOK = {r: f"tok-{r}-0123456789" for r in ("viewer", "analyst", "approver", "responder")}
SECRET = "Synthetic" + "Pw0rd" + "NotReal"
IEX = "Invoke-" + "Expression"
NS = "http://schemas.microsoft.com/win/2004/08/events/event"


def ps_xml(rid, num, total, text, sbid="00000000-0000-4000-8000-0000000000e1"):
    return (f"<Event xmlns='{NS}'><System><Provider Name='Microsoft-Windows-PowerShell'/><EventID>4104</EventID>"
            "<Version>1</Version><Level>5</Level><TimeCreated SystemTime='2026-11-28T01:10:00.0000000Z'/>"
            f"<EventRecordID>{rid}</EventRecordID><Execution ProcessID='3333' ThreadID='4444'/>"
            "<Channel>Microsoft-Windows-PowerShell/Operational</Channel><Computer>SYNTH-HOST</Computer>"
            "<Security UserID='S-1-5-21-0-0-0-1001'/></System><EventData>"
            f"<Data Name='MessageNumber'>{num}</Data><Data Name='MessageTotal'>{total}</Data>"
            f"<Data Name='ScriptBlockText'>{escape(text)}</Data><Data Name='ScriptBlockId'>{sbid}</Data>"
            "<Data Name='Path'></Data></EventData></Event>")


@pytest.fixture
def ctx(tmp_path):
    bdir = tmp_path / "bronze"
    w = BronzeWriter(bdir)
    xmls = [ps_xml(10, 1, 3, f"$p = ConvertTo-SecureString '{SECRET}' -AsPlainText -Force\n"),
            ps_xml(12, 3, 3, f"$x = 'a' | {IEX}")]          # phần 2 thiếu
    for x in xmls:
        w.append(bc.build_bronze_record(x, mode="file"))
    w.seal()
    st = SilverStore(tmp_path / "s.duckdb")
    st.ingest_dir(bdir, "t")
    rules = load_rules()
    store = AlertStore(st.con)
    out = build_from_results(store, rules, DetectionEngine(st.con, rules=rules).run(), st.con)
    tokens = TokenStore({hash_token(t): {"role": r, "actor": f"user-{r}"} for r, t in TOK.items()})
    policy = Policy(mode="dry_run", execute_unlocked=False, allowed_actions=set(), protected_process_names=set(),
                    protected_dirs=[], lab_dirs=[tmp_path / "lab"], quarantine_dir=tmp_path / "lab" / "q")
    app = create_app(Config(home=tmp_path), tokens, store=st, rules=rules, policy=policy, bronze_dir=bdir)
    (aid,) = [a for a in out["alerts"] if store.get(a)["rule_id"] == "DACN-DET-203"]
    return {"app": app, "aid": aid, "st": st}


def cl(ctx, role):
    c = TestClient(ctx["app"])
    c.headers["Authorization"] = f"Bearer {TOK[role]}"
    return c


def audit_actions(ctx):
    return [r[0] for r in ctx["st"].con.execute("select action from audit_log order by seq").fetchall()]


def test_script_masked_by_default_with_gap_marker(ctx):
    r = cl(ctx, "viewer").get(f"/alerts/{ctx['aid']}/script")
    assert r.status_code == 200
    b = r.json()
    assert SECRET not in b["text"] and MASK in b["text"] and IEX in b["text"]     # bí mật che, hành vi vẫn thấy
    assert b["redacted"] is True and "securestring_plaintext" in b["redaction_rules"]
    assert b["missing_message_numbers"] == [2] and "THIẾU PHẦN 2" in b["text"] and b["parts_seen"] == 2
    assert "SCRIPT_RAW_VIEW" not in audit_actions(ctx)


def test_reveal_requires_raw_permission_and_is_audited(ctx):
    assert cl(ctx, "viewer").get(f"/alerts/{ctx['aid']}/script?reveal=true").status_code == 403
    r = cl(ctx, "analyst").get(f"/alerts/{ctx['aid']}/script?reveal=true")
    assert r.status_code == 200 and SECRET in r.json()["text"] and r.json()["redacted"] is False
    assert audit_actions(ctx).count("SCRIPT_RAW_VIEW") == 1
    assert ctx["st"].con.execute("select actor from audit_log where action='SCRIPT_RAW_VIEW'").fetchone()[0] == "user-analyst"
    assert cl(ctx, "responder").get(f"/alerts/{ctx['aid']}/script").status_code == 403


def test_evidence_masks_script_unless_include_raw(ctx):
    ev = cl(ctx, "viewer").get(f"/alerts/{ctx['aid']}/evidence").json()
    dumped = json.dumps(ev)
    assert SECRET not in dumped and all(e["raw_xml"] is None for e in ev["events"])
    s0 = ev["events"][0]["silver"]
    assert s0["script_redacted"] is True and "raw_data" not in s0
    assert cl(ctx, "viewer").get(f"/alerts/{ctx['aid']}/evidence?include_raw=true").status_code == 403
    raw = cl(ctx, "analyst").get(f"/alerts/{ctx['aid']}/evidence?include_raw=true").json()
    assert SECRET in json.dumps(raw) and "EVIDENCE_RAW_VIEW" in audit_actions(ctx)


def test_alert_list_and_detail_never_contain_script(ctx):
    c = cl(ctx, "viewer")
    assert SECRET not in json.dumps(c.get("/alerts").json()) and IEX not in json.dumps(c.get(f"/alerts/{ctx['aid']}").json())
    assert SECRET not in json.dumps(c.get("/detections").json())


def test_script_endpoint_404_for_non_powershell_alert(ctx):
    store = AlertStore(ctx["st"].con)
    from datetime import datetime, timezone
    t = datetime(2026, 1, 1, tzinfo=timezone.utc)
    other = store.insert_alert(detection_dedup_key="k-x", group_key="g", first_seen_utc=t, last_seen_utc=t,
                               detection_source="RULE", rule_id="DACN-DET-001", rule_version=1, rule_name="n",
                               severity="low", severity_reason="thử", hostname="H", contributing_event_ids=["none"])
    assert cl(ctx, "viewer").get(f"/alerts/{other}/script").status_code == 404
    assert cl(ctx, "viewer").get("/alerts/khong-co/script").status_code == 404


# ---- redact() --------------------------------------------------------------------------------------
@pytest.mark.parametrize("text,rule", [
    ("$c = ConvertTo-SecureString 'Abc123x' -AsPlainText -Force", "securestring_plaintext"),
    ("New-Thing -Password Abc123x -Name n", "password_param"),
    ("$cfg = 'password=Abc123x;server=s'", "password_assign"),
    ("api_key: Abc123x", "password_assign"),
    ("Authorization: Bearer abcdefgh.ijklmnop", "bearer"),
    ("$k = '" + "AKIA" + "SYNTHETICTEST000" + "'", "aws_access_key"),
    ("$t = '" + "aB3" * 15 + "'", "long_token"),
])
def test_redact_rules(text, rule):
    out, hits = redact(text)
    assert rule in hits and MASK in out


def test_redact_private_key_block():
    pem = "-----BEGIN " + "RSA PRIVATE KEY-----\nMIIsyntheticnotreal\n-----END " + "RSA PRIVATE KEY-----"
    out, hits = redact(f"$k = @'\n{pem}\n'@")
    assert hits == ["private_key"] and "MIIsynthetic" not in out


@pytest.mark.parametrize("text", [
    "Get-ChildItem C:\\Windows\\System32 | Select-Object Name",
    "# " + "=" * 60,                                          # đường kẻ dài không phải token
    "Write-Output 'thisisaverylongwordwithoutdigitsoruppercaseletters'",
    "",
])
def test_redact_leaves_ordinary_text(text):
    assert redact(text) == (text, [])
