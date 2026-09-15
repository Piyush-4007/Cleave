"""Phase 1 smoke test — proves the package imports and the API is wired.
Real collector/graph/iam tests arrive with their phases."""
from fastapi.testclient import TestClient
from cleave.api.main import app


def test_health():
    r = TestClient(app).get("/health")
    assert r.status_code == 200
    assert r.json()["status"] == "ok"
