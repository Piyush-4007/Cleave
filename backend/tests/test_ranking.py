"""Phase 5 — ranking, dedup, and the minimum cut.

The overlapping-paths fixture (06) is the point of the phase: a min cut over a single path
is trivial, so correctness only shows when several paths share edges.
"""
import json
import pathlib
import pytest

from cleave.paths.graphview import graph_from_records
from cleave.paths.search import find_paths
from cleave.paths.model import EXTERNAL
from cleave.paths.ranking import rank, score, detect_technique, load_policy
from cleave.paths.cut import minimum_cut, best_single_fix, edge_cost

FIX_DIR = pathlib.Path(__file__).parent / "path_fixtures"
OVERLAP = FIX_DIR / "06-overlapping-paths-shared-cut.json"


def _paths(fixture):
    fx = json.loads(fixture.read_text())
    g = graph_from_records(fx["records"], fx.get("cred_findings", []))
    return fx, g, find_paths(g)


# ---- scoring -------------------------------------------------------------------------

def test_scores_are_recomputable_by_hand():
    """The whole point of a weighted sum: score == 10 * sum(applied factors) / sum(all)."""
    _fx, g, paths = _paths(OVERLAP)
    w = load_policy()["score_weights"]
    total_w = sum(w.values())
    for p in paths:
        sc = score(p, g)
        assert abs(sc["score"] - 10 * sc["raw"] / total_w) < 0.01
        assert abs(sc["raw"] - sum(sc["factors"].values())) < 0.01


def test_external_source_outranks_assumed_compromise():
    """An unauthenticated internet start is worse than 'if this credential leaked'."""
    _fx, g, paths = _paths(OVERLAP)
    ranked = rank(paths, g)
    top = ranked[0]
    assert top["source"]["kind"] == EXTERNAL
    assert top["rank"] == 1
    # every EXTERNAL path scores above every purely-assumed one of the same length
    ext = [d["ranking"]["score"] for d in ranked if d["source"]["kind"] == EXTERNAL]
    assert ext and min(ext) >= max(
        d["ranking"]["score"] for d in ranked if d["source"]["kind"] != EXTERNAL)


def test_shorter_path_scores_higher_all_else_equal():
    two = type("P", (), {})()  # not worth a real graph; use the scorer directly
    from cleave.paths.model import AttackPath, Source, Sink, Hop, ASSUMED_COMPROMISE
    src = Source("u", ASSUMED_COMPROMISE, "x", "e")
    sink = Sink("admin", "ADMIN", "x")
    def mk(nhops):
        hops = [Hop(f"n{i}", f"n{i+1}", "HAS_ATTACHED", "r", "e", "Certain", "d")
                for i in range(nhops)]
        return AttackPath(src, sink, [f"n{i}" for i in range(nhops + 1)], hops)
    assert score(mk(2))["score"] > score(mk(5))["score"]


def test_documented_technique_is_detected():
    _fx, _g, paths = _paths(OVERLAP)
    creds = [p for p in paths if any(h.rel == "CONTAINS_CREDENTIAL" for h in p.hops)]
    assert creds and all(detect_technique(p) for p in creds)


def test_production_sink_factor_is_zero_without_a_signal():
    """The factor exists in the formula but must not fire until something marks data as
    production — inventing the signal would be judgment in the wrong layer."""
    _fx, g, paths = _paths(OVERLAP)
    assert all("production_data_sink" not in score(p, g)["factors"] for p in paths)


# ---- dedup ---------------------------------------------------------------------------

def test_rank_dedups_by_signature_and_numbers_results():
    _fx, g, paths = _paths(OVERLAP)
    ranked = rank(paths, g)
    ids = [d["id"] for d in ranked]
    assert ids == [f"PATH-{i:03d}" for i in range(1, len(ranked) + 1)]
    assert [d["rank"] for d in ranked] == list(range(1, len(ranked) + 1))
    # scores are non-increasing
    scores = [d["ranking"]["score"] for d in ranked]
    assert scores == sorted(scores, reverse=True)


# ---- minimum cut ---------------------------------------------------------------------

def test_minimum_cut_breaks_every_path():
    _fx, _g, paths = _paths(OVERLAP)
    mc = minimum_cut(paths)
    assert mc["paths_cut"] == mc["paths_total"] == len(paths)
    # the two independent admin policies must both be cut (one per funnel)
    cut_rels = {(e["rel"], e["to"]) for e in mc["edges"]}
    assert ("GRANTS_ADMIN", "admin") in cut_rels
    assert len(mc["edges"]) == 2  # deploy-bot-iam and bg-admin, nothing wasteful


def test_minimum_cut_never_cuts_a_source_or_an_uncuttable_edge():
    _fx, _g, paths = _paths(OVERLAP)
    mc = minimum_cut(paths)
    source_uids = {p.source.uid for p in paths}
    for e in mc["edges"]:
        assert e["frm"] not in source_uids or e["rel"] != "CAN_REACH"
        assert e["cost"] is not None


def test_best_single_fix_leads_with_the_choke_point():
    """The demo headline: one change, the most paths gone."""
    _fx, _g, paths = _paths(OVERLAP)
    fixes = best_single_fix(paths)
    top = fixes[0]
    assert top["rel"] == "GRANTS_ADMIN"
    assert top["to"] == "admin"
    assert top["frm"].endswith("deploy-bot-iam")
    assert top["paths_cut"] == 3            # the three funnelling through deploy-bot
    assert top["paths_cut"] > fixes[-1]["paths_cut"]
    assert top["fix"] and top["cost"]


def test_fixture_06_matches_its_declared_expectations():
    fx, _g, paths = _paths(OVERLAP)
    exp = fx["expect"]
    assert len(paths) >= exp["min_paths"]
    choke = exp["shared_choke"]
    match = [e for e in best_single_fix(paths)
             if e["frm"] == choke["frm"] and e["to"] == choke["to"]
             and e["rel"] == choke["rel"]]
    assert match and match[0]["paths_cut"] >= choke["breaks_at_least"]


# ---- remediation cost model ----------------------------------------------------------

def test_full_admin_grants_admin_costs_more_than_a_primitive():
    """Cutting real AdministratorAccess removes legitimate access (expensive); cutting a
    GRANTS_ADMIN on a scoped primitive is a policy tweak (moderate)."""
    from cleave.paths.model import Hop
    real_admin = edge_cost("GRANTS_ADMIN", {"full_admin": True})
    primitive = edge_cost("GRANTS_ADMIN", {"full_admin": False})
    assert real_admin > primitive


def test_every_cuttable_edge_type_has_a_fix_string():
    pol = load_policy()
    for rel, cost in pol["remediation_costs"].items():
        if cost is not None:
            assert rel in pol["remediation_fixes"], f"{rel} has a cost but no fix text"


def test_empty_paths_cut_is_safe():
    assert minimum_cut([])["edges"] == []
    assert best_single_fix([]) == []
