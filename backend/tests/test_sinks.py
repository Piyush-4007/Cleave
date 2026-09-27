"""Phase 5 — sinks beyond Admin (sensitive data stores)."""
import json
import pathlib
import pytest

from cleave.paths.graphview import graph_from_records
from cleave.paths.search import find_paths
from cleave.paths.endpoints import find_sinks
from cleave.paths.ranking import sensitive_reason, score

FIX = pathlib.Path(__file__).parent / "path_fixtures" / "07-sensitive-data-sink.json"


def _load():
    fx = json.loads(FIX.read_text())
    return fx, graph_from_records(fx["records"], fx.get("cred_findings", []))


def test_admin_is_still_a_sink():
    _fx, g = _load()
    assert any(s.kind == "ADMIN" for s in find_sinks(g))


def test_production_tagged_bucket_is_a_sink():
    _fx, g = _load()
    data_sinks = [s for s in find_sinks(g) if s.kind == "SENSITIVE_DATA"]
    assert [s.uid for s in data_sinks] == ["arn:aws:s3:::prod-customer-data"]
    assert "production" in data_sinks[0].reason


def test_untagged_store_is_not_a_sink():
    _fx, g = _load()
    assert "arn:aws:s3:::scratch" not in {s.uid for s in find_sinks(g)}


def test_path_reaches_the_sensitive_sink():
    _fx, g = _load()
    paths = find_paths(g)
    to_data = [p for p in paths if p.sink.kind == "SENSITIVE_DATA"]
    assert len(to_data) == 1
    p = to_data[0]
    assert p.source.uid.endswith("analyst")
    assert [h.rel for h in p.hops] == ["CAN_READ"]


def test_sensitive_sink_scores_the_production_factor_not_admin():
    _fx, g = _load()
    p = next(p for p in find_paths(g) if p.sink.kind == "SENSITIVE_DATA")
    factors = score(p, g)["factors"]
    assert "production_data_sink" in factors
    assert "admin_sink" not in factors


def test_classifier_matches_tags_case_insensitively():
    assert sensitive_reason("x", {"Tags": {"ENVIRONMENT": "Production"}})
    assert sensitive_reason("x", {"Tags": {"DataClassification": "PII"}})
    assert sensitive_reason("x", {"Tags": {"environment": "dev"}}) is None
    assert sensitive_reason("x", {"Tags": {}}) is None


def test_explicit_arn_list_marks_a_store_sensitive(monkeypatch):
    from cleave.paths import ranking
    fake = {"sensitive_data": {"tag_keys": [], "tag_values": [],
                               "arns": ["arn:aws:s3:::untagged-but-listed"]}}
    monkeypatch.setattr(ranking, "load_policy", lambda: fake)
    assert sensitive_reason("arn:aws:s3:::untagged-but-listed", {"Tags": {}})
    assert sensitive_reason("arn:aws:s3:::other", {"Tags": {}}) is None
