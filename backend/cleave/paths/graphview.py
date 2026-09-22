"""The NetworkX view of the graph that path search runs on (Phase 4).

Why NetworkX and not a Cypher query: Phase 5's minimum cut is
`networkx.minimum_edge_cut` over the subgraph of discovered paths, and Phase 4's lazy
`CAN_READ`/`CAN_WRITE` evaluation (increment 2) calls the Python IAM evaluator during
traversal. Doing search in Cypher now would mean rewriting it in three weeks. Neo4j
remains the store and the thing the Phase 6 UI queries.

Two builders, one shape:
  * `graph_from_records` — pure, no database. Used by the fixture suite and by
    `--from-raw`; this is what makes the ground-truth tests possible.
  * `graph_from_neo4j`   — reads the loaded graph, so the CLI sees exactly what `./load.sh`
    put in the database.

Parallel edges (kerrigan --CAN_PASS_ROLE--> role and --CAN_LAUNCH_AS--> role both exist)
collapse onto one DiGraph edge carrying a `candidates` list — same as Neo4j's MERGE, and
traversal only cares that the two nodes are connected. Which candidate to *show* is
decided when a path is materialised.
"""
from __future__ import annotations
import json
import logging
import networkx as nx
from ..graph.loader import derive_structural_edges, stub_nodes
from ..graph.evaluated import compute_evaluated_edges

log = logging.getLogger("cleave.paths")

SYNTHETIC_NODES = {"internet": "Internet", "admin": "Admin"}


def _add_edge(g: nx.DiGraph, e: dict) -> None:
    if e["frm"] not in g or e["to"] not in g:
        log.debug("dropping edge with a missing endpoint: %s", e)
        return
    cand = {"rel": e["rel"], **(e.get("props") or {})}
    if g.has_edge(e["frm"], e["to"]):
        existing = g[e["frm"]][e["to"]]["candidates"]
        if any(c["rel"] == cand["rel"] for c in existing):
            return  # same pair + same type == one relationship, as Neo4j MERGE has it
        existing.append(cand)
    else:
        g.add_edge(e["frm"], e["to"], candidates=[cand])


def graph_from_records(records: list[dict], cred_findings=()) -> nx.DiGraph:
    """Build the graph straight from normalised collector records. No AWS, no Neo4j."""
    by_id = {r["_id"]: r for r in records}
    edges = list(derive_structural_edges(records))
    edges += compute_evaluated_edges(records, cred_findings)

    g = nx.DiGraph()
    for uid, label in SYNTHETIC_NODES.items():
        g.add_node(uid, label=label, record={})
    for r in records:
        g.add_node(r["_id"], label=r["_type"], record=r)
    for stub in stub_nodes(edges, by_id):
        if stub["uid"] not in g:
            g.add_node(stub["uid"], label=stub["label"], record=stub["props"])
    for e in edges:
        _add_edge(g, e)
    return g


def graph_from_neo4j(driver) -> nx.DiGraph:
    """Read the loaded graph back out of Neo4j into the same shape."""
    g = nx.DiGraph()
    with driver.session() as s:
        for rec in s.run("MATCH (n) RETURN n.uid AS uid, labels(n)[0] AS label, n._raw AS raw"):
            raw = rec["raw"]
            try:
                record = json.loads(raw) if raw else {}
            except (TypeError, ValueError):
                record = {}
            g.add_node(rec["uid"], label=rec["label"], record=record)
        for rec in s.run("MATCH (a)-[r]->(b) "
                         "RETURN a.uid AS frm, b.uid AS to, type(r) AS rel, "
                         "properties(r) AS props"):
            _add_edge(g, {"frm": rec["frm"], "to": rec["to"], "rel": rec["rel"],
                          "props": dict(rec["props"])})
    return g


def rels_between(g: nx.DiGraph, a: str, b: str) -> set[str]:
    """The relationship types connecting a -> b (empty if not connected)."""
    if not g.has_edge(a, b):
        return set()
    return {c["rel"] for c in g[a][b]["candidates"]}
