"""Phase 5/6 bridge — the analysis engine over HTTP.

The service's graph source is monkeypatched to a fixture graph, so these run with no Neo4j
and no raw dump. The point is the routing and shaping, not re-testing the engine.
"""
import json
import pathlib
import pytest
from fastapi.testclient import TestClient

from cleave.api.main import app
from cleave.api import service
from cleave.paths.graphview import graph_from_records

FIX = pathlib.Path(__file__).parent / "path_fixtures" / "06-overlapping-paths-shared-cut.json"


@pytest.fixture
def client(monkeypatch):
    fx = json.loads(FIX.read_text())
    g = graph_from_records(fx["records"], fx.get("cred_findings", []))
    monkeypatch.setattr(service, "build_graph", lambda: (g, "fixture"))
    service._STATE.update(graph=None, analysis=None, source=None)  # clear cache
    yield TestClient(app)
    service._STATE.update(graph=None, analysis=None, source=None)


def test_health():
    r = TestClient(app).get("/health")
    assert r.status_code == 200 and r.json()["status"] == "ok"


def test_analysis_returns_ranked_paths_cut_and_summary(client):
    r = client.get("/analysis")
    assert r.status_code == 200
    body = r.json()
    assert body["source"] == "fixture"
    assert body["summary"]["paths_found"] == len(body["paths"]) == 5
    # ranked, non-increasing score
    scores = [p["ranking"]["score"] for p in body["paths"]]
    assert scores == sorted(scores, reverse=True)
    assert body["minimum_cut"]["paths_cut"] == 5
    top = body["best_single_fix"][0]
    assert top["paths_cut"] == 3 and top["rel"] == "GRANTS_ADMIN"
    assert body["summary"]["best_single_fix"]["breaks"] == 3


def test_summary_is_light(client):
    r = client.get("/analysis/summary")
    assert r.status_code == 200
    body = r.json()
    assert "summary" in body and "paths" not in body


def test_path_detail_includes_subgraph_with_flags(client):
    top = client.get("/analysis").json()["paths"][0]["id"]
    r = client.get(f"/analysis/paths/{top}")
    assert r.status_code == 200
    body = r.json()
    assert body["path"]["id"] == top
    sub = body["subgraph"]
    assert sub["nodes"] and sub["edges"]
    # the source and sink of the path are flagged
    assert any(n["is_source"] for n in sub["nodes"])
    assert any(n["is_sink"] for n in sub["nodes"])
    # at least one edge is on the path
    assert any(e["on_path"] for e in sub["edges"])


def test_path_detail_marks_the_cut_edge(client):
    # PATH-001 in fixture 06 is the external route through bg-admin's GRANTS_ADMIN, which
    # is part of the minimum cut — its subgraph should flag that edge in_cut.
    body = client.get("/analysis").json()
    cut_edges = {(e["frm"], e["to"], e["rel"]) for e in body["minimum_cut"]["edges"]}
    # find a path whose subgraph contains a cut edge
    hit = False
    for p in body["paths"]:
        sub = client.get(f"/analysis/paths/{p['id']}").json()["subgraph"]
        for e in sub["edges"]:
            if e["in_cut"]:
                assert (e["frm"], e["to"], e["rel"]) in cut_edges
                hit = True
    assert hit, "no path subgraph flagged a cut edge"


def test_unknown_path_is_404(client):
    assert client.get("/analysis/paths/PATH-999").status_code == 404


def test_refresh_rebuilds(client, monkeypatch):
    client.get("/analysis")  # populate cache
    calls = {"n": 0}
    orig = service.build_graph
    def counting():
        calls["n"] += 1
        return orig()
    monkeypatch.setattr(service, "build_graph", counting)
    client.get("/analysis")            # cached — no rebuild
    assert calls["n"] == 0
    client.get("/analysis?refresh=true")  # forced rebuild
    assert calls["n"] == 1


def test_remediation_returns_fixes_and_bundle(client):
    r = client.get("/remediation")
    assert r.status_code == 200
    body = r.json()
    assert body["fixes"] and body["templated"] >= 1
    # every fix declares a confidence; templated ones carry Terraform
    assert all(f["confidence"] in ("templated", "guidance") for f in body["fixes"])
    assert any(f["terraform"] for f in body["fixes"] if f["confidence"] == "templated")
    # the downloadable bundle has a summary + at least one .tf
    assert "REMEDIATION.md" in body["files"]
    assert any(name.endswith(".tf") for name in body["files"])


def test_remediation_pr_is_credential_gated(client):
    # no CLEAVE_GITHUB_REPO configured -> 403 with instructions, never a silent attempt
    r = client.post("/remediation/pr")
    assert r.status_code == 403
    assert "CLEAVE_GITHUB_REPO" in r.json()["detail"]


def test_gate_endpoint_flags_new_path(client):
    p = {"format_version": "1.2", "resource_changes": [
        {"address": "aws_iam_user.x", "mode": "managed", "type": "aws_iam_user", "name": "x",
         "change": {"actions": ["create"], "after": {"name": "x"}}},
        {"address": "aws_iam_user_policy.p", "mode": "managed", "type": "aws_iam_user_policy",
         "name": "p", "change": {"actions": ["create"], "after": {"name": "danger", "user": "x",
            "policy": json.dumps({"Statement": [{"Effect": "Allow",
                "Action": "iam:CreatePolicyVersion", "Resource": "*"}]})}}}]}
    r = client.post("/gate", json=p)
    assert r.status_code == 200
    body = r.json()
    assert body["blocked"] and body["introduced"] >= 1 and "comment" in body


def test_gate_endpoint_rejects_non_plan(client):
    assert client.post("/gate", json={"not": "a plan"}).status_code == 400
