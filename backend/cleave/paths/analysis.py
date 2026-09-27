"""Analysis assembly — the whole engine behind one call (Phase 5/6 bridge).

`analyze(g)` runs sources -> sinks -> search -> rank -> cut on a graph and returns one
structured result. The CLI (paths.run) and the API (api.service) both call it, so they can
never drift. `path_subgraph` extracts the drawable neighbourhood of a single path for the
Phase 6 Cytoscape viewer.
"""
from __future__ import annotations
import datetime as _dt
from .endpoints import find_sinks, find_sources
from .model import EXTERNAL
from .search import MAX_HOPS, K_PER_PAIR, find_paths
from .ranking import rank
from .cut import minimum_cut, best_single_fix


def analyze(g, max_hops: int = MAX_HOPS, k: int = K_PER_PAIR) -> dict:
    sources = find_sources(g)
    sinks = find_sinks(g)
    paths = find_paths(g, sources, sinks, max_hops=max_hops, k=k)
    ranked = rank(paths, g)
    cut = minimum_cut(paths)
    fixes = best_single_fix(paths)

    ext = sum(1 for s in sources if s.kind == EXTERNAL)
    return {
        "generated_at": _dt.datetime.now(_dt.timezone.utc).isoformat(),
        "graph": {"nodes": g.number_of_nodes(), "connected_pairs": g.number_of_edges()},
        "summary": {
            "sources": len(sources),
            "sources_external": ext,
            "sources_assumed_compromise": len(sources) - ext,
            "sinks": len(sinks),
            "sinks_admin": sum(1 for s in sinks if s.kind == "ADMIN"),
            "sinks_sensitive_data": sum(1 for s in sinks if s.kind == "SENSITIVE_DATA"),
            "paths_found": len(ranked),
            "top_score": ranked[0]["ranking"]["score"] if ranked else 0,
            "best_single_fix": (
                {"fix": fixes[0]["fix"], "breaks": fixes[0]["paths_cut"],
                 "of": fixes[0]["paths_total"], "cost": fixes[0]["cost"]}
                if fixes else None),
        },
        "paths": ranked,
        "minimum_cut": cut,
        "best_single_fix": fixes,
    }


def _node_view(g, uid: str) -> dict:
    data = g.nodes.get(uid, {})
    rec = data.get("record") or {}
    name = rec.get("Name") or rec.get("UserName") or rec.get("RoleName") \
        or rec.get("PolicyName") or rec.get("DBInstanceIdentifier") \
        or (uid.split("/")[-1] if "/" in uid else uid)
    return {"id": uid, "label": data.get("label", "?"), "name": name}


def path_subgraph(g, ranked_path: dict, cut_edges: list[dict] | None = None) -> dict:
    """The drawable neighbourhood of one path: the path nodes plus one hop of context, and
    every edge among them. Rendering constraint (handbook Phase 6): never the full graph.

    Edges are flagged `on_path` (part of this route) and `in_cut` (part of the minimum
    cut), so the viewer can highlight the route and paint the cut red.
    """
    on_path_nodes = list(ranked_path["nodes"])
    cut_set = {(e["frm"], e["to"], e["rel"]) for e in (cut_edges or [])}
    on_path_edges = {(h["frm"], h["to"], h["rel"]) for h in ranked_path["hops"]}

    # one hop of context: immediate neighbours of the path nodes
    ctx = set(on_path_nodes)
    for n in on_path_nodes:
        if n in g:
            ctx.update(g.successors(n))
            ctx.update(g.predecessors(n))

    nodes = [{**_node_view(g, uid),
              "on_path": uid in set(on_path_nodes),
              "is_source": uid == ranked_path["source"]["uid"],
              "is_sink": uid == ranked_path["sink"]["uid"]}
             for uid in ctx]

    edges = []
    ctx_set = set(ctx)
    for a in ctx_set:
        if a not in g:
            continue
        for b in g.successors(a):
            if b not in ctx_set:
                continue
            for c in g[a][b]["candidates"]:
                rel = c["rel"]
                edges.append({
                    "frm": a, "to": b, "rel": rel,
                    "reason": c.get("reason", ""),
                    "confidence": c.get("confidence", "Possible"),
                    "on_path": (a, b, rel) in on_path_edges,
                    "in_cut": (a, b, rel) in cut_set,
                })
    return {"nodes": nodes, "edges": edges}
