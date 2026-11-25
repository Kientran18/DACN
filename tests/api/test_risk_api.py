"""API rủi ro chỉ đọc (/risk/*, /alerts/{id}/risk). Fixture SYNTHETIC."""
import pytest

from test_api import TOK, cl, ctx  # noqa: F401  (fixture dùng chung)


@pytest.mark.parametrize("path", ["/risk/config", "/risk/subjects?kind=process", "/risk/host?hostname=x",
                                  "/risk/process?hostname=x&process_guid=y"])
def test_risk_endpoints_require_token(ctx, path):  # noqa: F811
    assert cl(ctx).get(path).status_code == 401


def test_risk_config_is_versioned_and_uncalibrated(ctx):  # noqa: F811
    r = cl(ctx, "viewer").get("/risk/config").json()
    assert r["version"] == 1 and r["status"] == "heuristic_uncalibrated" and len(r["sha256"]) == 64
    assert r["values"]["weights"]["RULE"] == 1.0 and r["ml_enabled"] == {"ML_STATIC": False, "ML_BEHAVIOR": False}


def test_alert_risk_explained_and_never_triggers_response(ctx):  # noqa: F811
    con = ctx["st"].con
    before = con.execute("select count(*) from response_actions").fetchone()[0]
    r = cl(ctx, "viewer").get(f"/alerts/{ctx['alert_id']}/risk")
    assert r.status_code == 200
    d = r.json()
    assert d["triggers_response"] is False and d["score"] > 0 and d["level"] in ("low", "medium", "high", "critical")
    assert any(c["ref_id"] == ctx["alert_id"] for c in d["components"])
    assert all({"category", "weight", "base_points", "points", "reason"} <= set(c) for c in d["components"])
    assert {x["source"] for x in d["not_evaluated"]} == {"ML_STATIC", "ML_BEHAVIOR"}
    assert con.execute("select count(*) from response_actions").fetchone()[0] == before


def test_alert_risk_404(ctx):  # noqa: F811
    r = cl(ctx, "viewer").get("/alerts/khong-co/risk")
    assert r.status_code == 404 and r.json()["error"]["code"] == "E-NOT_FOUND"


def test_subjects_list_and_validation(ctx):  # noqa: F811
    c = cl(ctx, "viewer")
    items = c.get("/risk/subjects?kind=process").json()["items"]
    assert items and items[0]["subject"]["kind"] == "process"
    assert [i["score"] for i in items] == sorted((i["score"] for i in items), reverse=True)
    assert c.get("/risk/subjects?kind=host").json()["items"][0]["subject"]["kind"] == "host"
    assert c.get("/risk/subjects?kind=user").status_code == 422
    assert c.get("/risk/subjects?kind=process&min_level=huge").status_code == 422


def test_process_and_host_endpoints(ctx):  # noqa: F811
    c = cl(ctx, "viewer")
    a = c.get(f"/alerts/{ctx['alert_id']}").json()
    p = c.get("/risk/process", params={"hostname": a["hostname"], "process_guid": a["process_guid"]}).json()
    assert p["subject"]["process_guid"] == a["process_guid"]
    h = c.get("/risk/host", params={"hostname": a["hostname"]}).json()
    assert h["subject"]["kind"] == "host" and h["subject"]["window_seconds"] == 3600


def test_risk_is_read_only(ctx):  # noqa: F811
    c = cl(ctx, "approver")
    assert c.post("/risk/subjects?kind=process", content=b"", headers={"Content-Length": "0"}).status_code == 405
    assert c.post(f"/alerts/{ctx['alert_id']}/risk", content=b"", headers={"Content-Length": "0"}).status_code == 405
