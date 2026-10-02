"""Phase 10 — the benchmark scenario generator: ground truth must be exact.

The generator's contract is that the benign noise forms NO real path, so Cleave finds
exactly the planted paths — recall and precision both 1.0 on a clean generation. If either
drops, it's a generator bug (benign noise leaking a path) or an engine regression, and the
benchmark numbers would be meaningless. This pins it.
"""
import pytest
from cleave.benchmark.generate import generate
from cleave.paths.graphview import graph_from_records
from cleave.paths.search import find_paths


@pytest.mark.parametrize("seed", [1, 7, 42])
def test_cleave_recall_and_no_benign_path(seed):
    scn = generate(seed=seed, n_benign=160, n_paths=5)
    g = graph_from_records(scn["records"], scn["cred_findings"])
    paths = find_paths(g)
    planted_res = scn["planted_resources"]

    # recall: every planted path's intended route reaches admin
    found_sources = {p.source.uid for p in paths}
    planted_sources = {m["source"] for m in scn["manifest"]}
    assert planted_sources <= found_sources, planted_sources - found_sources

    # precision (vulnerability level): EVERY reported path traverses a planted resource —
    # i.e. no path is formed purely from benign noise. (A public-bucket path is reachable
    # from many principals, which is correct; they all go through the planted bucket.)
    for p in paths:
        assert planted_res & set(p.nodes), \
            f"benign-only path from {p.source.uid}: {p.nodes}"


def test_scale_and_manifest_shape():
    scn = generate(seed=1, n_benign=250, n_paths=5)
    assert len(scn["records"]) >= 200                 # a realistically-sized account
    assert len(scn["manifest"]) == 5
    assert {m["template"] for m in scn["manifest"]}   # templates recorded
    for m in scn["manifest"]:
        assert m["source"] and m["sink"] == "admin" and m["hops"]


# ---- metrics harness -------------------------------------------------------------------

def test_metrics_headline_numbers():
    from cleave.benchmark.metrics import evaluate
    from cleave.paths.analysis import analyze
    scn = generate(seed=1, n_benign=200, n_paths=5)
    m = evaluate(scn, analyze(graph_from_records(scn["records"], scn["cred_findings"])))
    assert m["recall"] == 1.0 and m["precision"] == 1.0      # exact on a clean generation
    assert m["ttfp_paths_rank"] == 1                          # first real path ranked top
    assert m["ttfp_findings_rank"] == 1                       # first real finding ranked top
    assert m["triage_reduction"] > 5                          # many findings -> few paths
    assert m["total_findings"] > m["planted_paths"]
    assert 0 < m["best_single_fix_cut"] <= 1.0
