"""Minimum cut — the single change that breaks the most attack paths (Phase 5).

Two outputs, because they answer two different questions:

  * `minimum_cut`     — the cheapest SET of edges whose removal breaks EVERY discovered
                        path. This is the "what does it take to be safe" number.
  * `best_single_fix` — every cuttable edge, ranked by (paths it breaks / its cost). This
                        is the demo headline: "one change, N of M paths gone."

A minimum cut breaks all paths by definition, so it can never answer "eliminates N of M" —
that is what best_single_fix is for. Both read remediation costs from policy.json.

The cut runs on a purpose-built flow graph, NOT the account graph: only the nodes and
edges that lie on a discovered path, with a synthetic super-source feeding every path
source. Cutting a source's own entry (or the attacker) is not a fix, so those super-source
edges are uncuttable (infinite capacity). Everything else gets its remediation cost as
capacity, and networkx.minimum_cut returns the min-capacity edge set — the cheapest real
set of changes.
"""
from __future__ import annotations
import networkx as nx
from .model import AttackPath
from .ranking import load_policy

SUPER_SOURCE = "__cut_source__"
SUPER_SINK = "__cut_sink__"
UNCUTTABLE = float("inf")


def edge_cost(rel: str, props: dict | None = None) -> float | None:
    """Remediation cost for cutting an edge of this type. None = uncuttable.

    GRANTS_ADMIN is nuanced: cutting the edge on a *sufficient-alone primitive* means
    scoping that one action (moderate), but cutting it on real AdministratorAccess means
    taking admin away from someone who legitimately holds it (expensive). full_admin
    splits the two."""
    costs = load_policy()["remediation_costs"]
    if rel == "GRANTS_ADMIN" and props and props.get("full_admin"):
        return 10  # removing real administrator access — maximum disruption
    return costs.get(rel)


def _flow_graph(paths: list[AttackPath]) -> tuple[nx.DiGraph, dict]:
    """Build the capacitated flow graph from the discovered paths. Returns the graph and
    a map from (u, v) -> the representative edge dict (for reporting the cut)."""
    g = nx.DiGraph()
    edge_info: dict = {}
    for p in paths:
        g.add_edge(SUPER_SOURCE, p.source.uid, capacity=UNCUTTABLE)
        for h in p.hops:
            cost = edge_cost(h.rel, {"full_admin": _full_admin_hint(h)})
            cap = UNCUTTABLE if cost is None else float(cost)
            if g.has_edge(h.frm, h.to):
                # keep the cheapest representative; capacities of parallel path-edges don't
                # sum here because one remediation cuts the relationship regardless
                if cap < g[h.frm][h.to]["capacity"]:
                    g[h.frm][h.to]["capacity"] = cap
                    edge_info[(h.frm, h.to)] = h
            else:
                g.add_edge(h.frm, h.to, capacity=cap)
                edge_info[(h.frm, h.to)] = h
        g.add_edge(p.sink.uid, SUPER_SINK, capacity=UNCUTTABLE)
    return g, edge_info


def _full_admin_hint(hop) -> bool:
    return hop.rel == "GRANTS_ADMIN" and "AdministratorAccess" in (hop.frm or "")


def minimum_cut(paths: list[AttackPath]) -> dict:
    """The cheapest set of edges that breaks every path."""
    if not paths:
        return {"edges": [], "total_cost": 0, "paths_cut": 0, "paths_total": 0}
    g, edge_info = _flow_graph(paths)
    cut_value, (reachable, _) = nx.minimum_cut(g, SUPER_SOURCE, SUPER_SINK)

    cut_edges = []
    for u in reachable:
        for v in g.successors(u):
            if v not in reachable and g[u][v]["capacity"] != UNCUTTABLE:
                h = edge_info.get((u, v))
                if h:
                    cut_edges.append(_describe(h))
    return {
        "edges": cut_edges,
        "total_cost": sum(e["cost"] for e in cut_edges),
        "paths_cut": len(paths),          # a full cut breaks all of them
        "paths_total": len(paths),
    }


def best_single_fix(paths: list[AttackPath]) -> list[dict]:
    """Every cuttable edge, ranked by paths-broken-per-unit-cost. The top row is the demo
    headline. An edge breaks a path if it appears on it."""
    fixes: dict[tuple, dict] = {}
    for p in paths:
        for h in p.hops:
            cost = edge_cost(h.rel, {"full_admin": _full_admin_hint(h)})
            if cost is None:
                continue
            key = (h.frm, h.to, h.rel)
            entry = fixes.setdefault(key, {**_describe(h), "paths_cut": 0})
            entry["paths_cut"] += 1
    ranked = list(fixes.values())
    for e in ranked:
        e["efficiency"] = round(e["paths_cut"] / e["cost"], 3)
    # Headline claim is "one change breaks the MOST paths", so paths_cut leads; cost is the
    # tiebreak (cheaper wins), efficiency is kept as a secondary lens, not the sort key.
    ranked.sort(key=lambda e: (-e["paths_cut"], e["cost"], -e["efficiency"]))
    total = len(paths)
    for e in ranked:
        e["paths_total"] = total
    return ranked


def _describe(hop) -> dict:
    fixes = load_policy()["remediation_fixes"]
    cost = edge_cost(hop.rel, {"full_admin": _full_admin_hint(hop)})
    return {
        "frm": hop.frm, "to": hop.to, "rel": hop.rel,
        "cost": cost,
        "fix": fixes.get(hop.rel, "review and scope this permission"),
        "evidence": hop.evidence,
    }
