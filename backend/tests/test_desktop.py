"""Desktop-mode API behaviour: per-launch token, scan persistence, no-Neo4j graph store.

The desktop app runs the API on 127.0.0.1 with a random token only its own window knows,
so another web page open in the user's browser cannot drive a scan with their AWS creds.
The last scan is written to the app's data dir so a restart shows it again.
"""
import json
import pathlib
import pytest
from fastapi.testclient import TestClient

from cleave import collect, aws_session
from cleave.api.main import app
from cleave.api import service
from cleave.config import settings

FIX = pathlib.Path(__file__).parent / "path_fixtures" / "06-overlapping-paths-shared-cut.json"


@pytest.fixture
def fresh_state():
    service._STATE.update(graph=None, analysis=None, source=None, account=None,
                          connected=False, mode=None, scanning=False)
    yield
    service._STATE.update(graph=None, analysis=None, source=None, account=None,
                          connected=False, mode=None, scanning=False)


# ---- token ---------------------------------------------------------------------------

def test_no_token_configured_means_open_api(monkeypatch):
    monkeypatch.setattr(settings, "cleave_api_token", "")
    assert TestClient(app).get("/connection").status_code == 200


def test_token_required_when_configured(monkeypatch):
    monkeypatch.setattr(settings, "cleave_api_token", "s3cret")
    c = TestClient(app)
    assert c.get("/connection").status_code == 401
    assert c.get("/connection", headers={"X-Cleave-Token": "wrong"}).status_code == 401
    assert c.get("/connection", headers={"X-Cleave-Token": "s3cret"}).status_code == 200
    assert c.post("/scan", json={"mode": "login"}).status_code == 401


def test_health_and_preflight_stay_open_with_token(monkeypatch):
    monkeypatch.setattr(settings, "cleave_api_token", "s3cret")
    c = TestClient(app)
    assert c.get("/health").status_code == 200  # the shell polls this for readiness
    r = c.options("/scan", headers={"Origin": "http://localhost:3000",
                                    "Access-Control-Request-Method": "POST"})
    assert r.status_code == 200  # CORS preflight carries no custom headers


# ---- persistence ---------------------------------------------------------------------

def test_scan_is_persisted_and_reloaded_after_restart(monkeypatch, tmp_path, fresh_state):
    fx = json.loads(FIX.read_text())
    monkeypatch.setattr(settings, "cleave_output_dir", str(tmp_path))
    monkeypatch.setattr(settings, "cleave_graph_store", "memory")
    monkeypatch.setattr(aws_session, "build_session_for", lambda role_arn=None: object())
    monkeypatch.setattr(collect, "collect_records", lambda session, credscan=False: {
        "account": "111122223333", "arn": "arn:aws:iam::111122223333:user/x",
        "records": fx["records"], "cred_findings": fx.get("cred_findings", []),
        "by_collector": {"fixture": fx["records"]}, "counts": {"fixture": len(fx["records"])},
    })

    status = service.run_scan("login")
    assert status["connected"] and status["paths_found"] == 5
    assert (tmp_path / "fixture.json").exists()
    assert json.loads((tmp_path / "_meta.json").read_text())["account"] == "111122223333"
    assert status["last_scan"]["account"] == "111122223333"

    # "restart": wipe memory, rebuild from disk only
    service._STATE.update(graph=None, analysis=None, source=None, account=None)
    a = service.get_analysis()
    assert a["source"] == "raw"
    assert a["summary"]["paths_found"] == 5
    assert a["account"] == "111122223333"


def test_memory_store_never_touches_neo4j(monkeypatch, tmp_path):
    monkeypatch.setattr(settings, "cleave_output_dir", str(tmp_path))
    monkeypatch.setattr(settings, "cleave_graph_store", "memory")

    import builtins
    real_import = builtins.__import__

    def guard(name, *a, **k):
        assert not name.startswith("neo4j"), "memory store must not import neo4j"
        return real_import(name, *a, **k)

    monkeypatch.setattr(builtins, "__import__", guard)
    g, source = service.build_graph()
    assert source == "raw"
    assert service.connection_status()["last_scan"] is None  # nothing saved yet
