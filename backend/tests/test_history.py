"""Scan history (SQLite) + disconnect.

Two scans of the same account diff into new / resolved findings and paths, keyed stably
(check + resource; node sequence), so a finding whose evidence text changes with time
("161 days" -> "162 days") is the SAME finding, not one resolved and one new.
"""
import json
import pathlib
import pytest
from fastapi.testclient import TestClient

from cleave import history
from cleave.api import service
from cleave.api.main import app
from cleave.config import settings

FIX = pathlib.Path(__file__).parent / "path_fixtures" / "06-overlapping-paths-shared-cut.json"


@pytest.fixture
def tmpdb(monkeypatch, tmp_path):
    monkeypatch.setattr(settings, "cleave_db_path", str(tmp_path / "cleave.db"))
    monkeypatch.setattr(settings, "cleave_output_dir", str(tmp_path / "raw"))
    monkeypatch.setattr(settings, "cleave_graph_store", "memory")
    monkeypatch.setattr(settings, "cleave_api_token", "")
    service._STATE.update(graph=None, analysis=None, source=None, account=None,
                          connected=False, mode=None, scanning=False)
    yield tmp_path
    service._STATE.update(graph=None, analysis=None, source=None, account=None,
                          connected=False, mode=None, scanning=False)


def finding(check, resource, severity="high", evidence="x"):
    return {"check": check, "resource": resource, "resource_name": resource, "title": check,
            "severity": severity, "reachability": "not_reachable", "evidence": evidence}


def analysis(findings, paths=()):
    return {"summary": {"paths_found": len(paths), "top_score": 0},
            "findings": findings,
            "findings_summary": {"total": len(findings), "by_severity": {"high": len(findings)},
                                 "by_reachability": {"on_path": 0}},
            "paths": [{"id": f"PATH-{i}", "nodes": list(p), "title": "t", "ranking": {"score": 1},
                       "source": {"kind": "ASSUMED_COMPROMISE"}, "sink": {"kind": "ADMIN"}}
                      for i, p in enumerate(paths, 1)]}


META = {"account": "111122223333", "arn": "arn:aws:iam::111122223333:user/x", "mode": "login",
        "principal_name": "x", "principal_type": "user", "scanned_at": "2026-10-01T00:00:00+00:00"}


def test_diff_new_and_resolved_with_stable_keys(tmpdb):
    a = history.record(META, analysis([finding("IAM.USER_NO_MFA", "u1"),
                                       finding("IAM.KEY_NOT_ROTATED", "u1", evidence="161 days")],
                                      paths=[("u1", "p", "admin")]))
    b = history.record({**META, "scanned_at": "2026-10-02T00:00:00+00:00"},
                       analysis([finding("IAM.KEY_NOT_ROTATED", "u1", evidence="162 days"),
                                 finding("VPC.SG_ADMIN_PORTS_OPEN", "sg-1")],
                                paths=[("u2", "p", "admin")]))
    d = history.diff(b)
    assert d["previous"]["id"] == a
    assert [f["check_id"] for f in d["findings"]["new"]] == ["VPC.SG_ADMIN_PORTS_OPEN"]
    assert [f["check_id"] for f in d["findings"]["resolved"]] == ["IAM.USER_NO_MFA"]
    assert d["findings"]["unchanged"] == 1        # same key, different evidence text
    assert len(d["paths"]["new"]) == 1 and len(d["paths"]["resolved"]) == 1

    listed = history.list_scans()
    assert [s["id"] for s in listed] == [b, a]      # newest first
    assert listed[0]["delta"] == {"previous_id": a, "findings_new": 1, "findings_newly_checked": 0,
                                  "findings_resolved": 1, "paths_new": 1, "paths_resolved": 1}
    assert listed[1]["delta"] is None               # first scan of the account


def test_findings_from_checks_the_previous_scan_lacked_are_not_called_new(tmpdb):
    """The 1 Oct demo: the 30 Sep scan predates the CloudTrail/MFA checks, so those findings
    existed then but were invisible. They are 'newly checked', never 'new'."""
    history.record(META, analysis([finding("IAM.USER_DIRECT_POLICY", "u1")]),
                   checks=["IAM.USER_DIRECT_POLICY"])
    b = history.record(META, analysis([finding("IAM.USER_DIRECT_POLICY", "u1"),
                                       finding("CLOUDTRAIL.NOT_ENABLED", "account")]))
    d = history.diff(b)
    assert d["coverage_changed"] is True
    assert [(f["check_id"], f["newly_checked"]) for f in d["findings"]["new"]] ==            [("CLOUDTRAIL.NOT_ENABLED", True)]
    delta = history.list_scans()[0]["delta"]
    assert (delta["findings_new"], delta["findings_newly_checked"]) == (0, 1)


def test_accounts_never_diff_against_each_other(tmpdb):
    history.record(META, analysis([finding("A", "r")]))
    other = history.record({**META, "account": "999988887777"}, analysis([]))
    assert history.diff(other)["previous"] is None


def test_forget_removes_only_that_account(tmpdb):
    history.record(META, analysis([finding("A", "r")]))
    history.record({**META, "account": "999988887777"}, analysis([]))
    assert history.forget("111122223333") == 1
    assert [s["account"] for s in history.list_scans()] == ["999988887777"]


def _fake_scan(monkeypatch):
    fx = json.loads(FIX.read_text())
    from cleave import aws_session, collect
    monkeypatch.setattr(aws_session, "build_session_for", lambda role_arn=None: object())
    monkeypatch.setattr(collect, "collect_records", lambda session, credscan=False: {
        "account": "111122223333", "arn": "arn:aws:iam::111122223333:user/x", "alias": None,
        "records": fx["records"], "cred_findings": fx.get("cred_findings", []), "by_collector": {"fixture": fx["records"]},
        "counts": {}})


def test_every_api_scan_is_recorded(tmpdb, monkeypatch):
    _fake_scan(monkeypatch)
    c = TestClient(app)
    assert c.post("/scan", json={"mode": "login"}).status_code == 200
    assert c.post("/scan", json={"mode": "login"}).status_code == 200
    scans = c.get("/history").json()
    assert len(scans) == 2 and scans[0]["paths_found"] == 5
    assert scans[0]["delta"]["findings_new"] == 0          # nothing changed between them
    d = c.get(f"/history/{scans[0]['id']}").json()
    assert d["previous"]["id"] == scans[1]["id"]
    assert c.get("/history/9999").status_code == 404


def test_disconnect_clears_the_scan_and_optionally_history(tmpdb, monkeypatch):
    _fake_scan(monkeypatch)
    c = TestClient(app)
    c.post("/scan", json={"mode": "login"})
    r = c.post("/disconnect", json={}).json()
    assert r["disconnected"] and r["history_deleted"] == 0
    conn = c.get("/connection").json()
    assert conn["connected"] is False and conn["last_scan"] is None
    assert not list((tmpdb / "raw").glob("*.json"))
    assert len(c.get("/history").json()) == 1               # kept unless asked

    c.post("/scan", json={"mode": "login"})
    assert c.post("/disconnect", json={"forget_history": True}).json()["history_deleted"] == 2
    assert c.get("/history").json() == []


def test_old_saved_scan_gets_identity_from_its_arn(tmpdb):
    raw = tmpdb / "raw"
    raw.mkdir()
    (raw / "_meta.json").write_text(json.dumps(
        {"account": "111122223333", "arn": "arn:aws:iam::111122223333:user/cleave-dev",
         "mode": "login", "scanned_at": "2026-09-29T21:14:39+00:00"}))
    meta = service._meta_from_raw(str(raw))
    assert (meta["principal_type"], meta["principal_name"]) == ("user", "cleave-dev")
