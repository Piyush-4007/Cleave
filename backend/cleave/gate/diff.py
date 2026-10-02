"""The merge gate (Phase 9) — a set difference, nothing more.

G_before = the live account graph. G_after = live + the planned changes. The finding is
`paths_new = paths(G_after) - paths(G_before)`: routes this PR would CREATE that do not
exist today. Reporting "this PR touches IAM" is what a linter does; reporting "this change
opens a route that wasn't there before" is the Semester 8 differentiator.

Reuses the whole engine: build_records applies the plan, graph_from_records + find_paths do
the rest. If you are writing new graph code here, you have gone wrong (handbook).
"""
from __future__ import annotations
from ..paths.cut import minimum_cut
from ..paths.graphview import graph_from_records
from ..paths.search import find_paths
from .plan import build_records, parse_plan


def _sig(p) -> tuple:
    return (p.source.uid, p.sink.uid, tuple(p.nodes))


def gate(live_records: list[dict], plan: dict, account: str,
         live_cred_findings=()) -> dict:
    """Diff the attack-path sets of the live account and the account-with-plan-applied.

    Returns the new paths (compact views + narration), the minimum cut that would stop them
    with a Phase-8 Terraform fix per edge (the "scoped alternative"), and counts. `blocked`
    is True iff the PR introduces at least one path — the status check's fail signal.
    """
    before = find_paths(graph_from_records(live_records, live_cred_findings))
    after_records = build_records(live_records, parse_plan(plan, account), account)
    after_graph = graph_from_records(after_records, live_cred_findings)
    after = find_paths(after_graph)

    before_sigs = {_sig(p) for p in before}
    new = [p for p in after if _sig(p) not in before_sigs]
    removed = len(before_sigs - {_sig(p) for p in after})

    fixes = []
    if new:
        from ..remediation.generate import generate
        cut = minimum_cut(new)
        fixes = [generate(e, after_graph).to_dict() for e in cut["edges"]]

    return {
        "blocked": bool(new),
        "introduced": len(new),
        "paths_before": len(before),
        "paths_after": len(after),
        "paths_removed": removed,
        "new_paths": [_path_view(p) for p in new],
        "new_paths_narrated": [p.narrate() for p in new],
        "remediation": fixes,
    }


def _path_view(p) -> dict:
    """A compact, JSON-safe view of a new path for the status check / PR comment."""
    return {
        "source": {"uid": p.source.uid, "kind": p.source.kind},
        "sink": {"uid": p.sink.uid, "kind": p.sink.kind},
        "length": p.length,
        "confidence": p.confidence,
        "hops": [{"frm": h.frm, "to": h.to, "rel": h.rel, "reason": h.reason,
                  "confidence": h.confidence} for h in p.hops],
        "narration": p.narrate(),
    }
