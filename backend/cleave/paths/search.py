"""Path search (Phase 4 v1) — find the routes from a source to admin.

v1 searches the edges the graph already holds. Both Phase 0 ground-truth scenarios are
reachable that way (rollback is HAS_ATTACHED -> GRANTS_ADMIN; attachment is
CAN_LAUNCH_AS -> HAS_ATTACHED -> GRANTS_ADMIN), so lazy CAN_READ/CAN_WRITE evaluation is
NOT needed yet. It arrives in increment 2, where credential-theft paths
(attacker -> CAN_READ -> bucket -> CONTAINS_CREDENTIAL -> victim) need the read hop
evaluated during traversal.

Hop limit 6, K=5 shortest simple paths per source-sink pair (Yen's algorithm, via
networkx.shortest_simple_paths). If a scenario finds nothing, the edges are wrong —
raising the hop limit is the handbook's named trap.
"""
from __future__ import annotations
import networkx as nx
from .endpoints import find_sinks, find_sources
from .model import AttackPath, Hop, Sink, Source

MAX_HOPS = 6
K_PER_PAIR = 5

# ---- what an attacker may walk -------------------------------------------------------
# An edge is traversable only if using it is itself an attacker action. The structural
# edges belong here: a principal reaches its powers *through* them
# (cleave-dev -HAS_ATTACHED-> AdministratorAccess -GRANTS_ADMIN-> Admin), and dropping
# them would disconnect every IAM path in the graph.
TRAVERSABLE = {
    "HAS_ATTACHED":         "the identity holds every permission this policy grants",
    "IN_GROUP":             "the user inherits the group's attached policies",
    "HAS_INSTANCE_PROFILE": "own the instance, read the profile's role credentials from IMDS",
    "CONTAINS_ROLE":        "the instance profile hands this role to whatever runs with it",
    "EXECUTES_AS":          "invoke or compromise the function and you act as its role",
    "CAN_ASSUME":           "sts:AssumeRole into the role",
    # NOTE: PassRole alone does not yield the role — it needs a compute action to land on
    # something. CAN_LAUNCH_AS is that completed form and outranks it when both exist.
    # Kept traversable so a PassRole-only route is reported rather than silently dropped.
    "CAN_PASS_ROLE":        "hand the role to a service you launch",
    "CAN_LAUNCH_AS":        "boot a resource carrying the role, then read its credentials",
    "GRANTS_ADMIN":         "this policy is administrator-equivalent",
    "CAN_REACH":            "a network packet can arrive from the internet",
    "CONTAINS_CREDENTIAL":  "a credential stored here unlocks this principal",
}

# Context, never a step. These exist so CAN_REACH can be *computed*; walking them would
# produce paths like "instance -> subnet -> vpc" that no attacker can traverse.
CONTEXT_ONLY = {
    "IN_SUBNET":          "locates a resource for the reachability chain",
    "IN_VPC":             "topology only",
    "PROTECTED_BY":       "the firewall is an input to CAN_REACH, not a step",
    "ROUTES_VIA":         "routing is an input to CAN_REACH, not a step",
    "HAS_INTERNET_ROUTE": "routing is an input to CAN_REACH, not a step",
}

# When two nodes are connected by several relationship types, show the most damning one.
REL_RANK = {rel: i for i, rel in enumerate([
    "CAN_LAUNCH_AS", "CAN_ASSUME", "CONTAINS_CREDENTIAL", "CAN_REACH",
    "HAS_INSTANCE_PROFILE", "CONTAINS_ROLE", "EXECUTES_AS",
    "GRANTS_ADMIN", "HAS_ATTACHED", "IN_GROUP", "CAN_PASS_ROLE",
])}


def traversable_subgraph(g: nx.DiGraph) -> nx.DiGraph:
    """Drop context-only edges. Search runs on what's left."""
    sub = nx.DiGraph()
    sub.add_nodes_from(g.nodes(data=True))
    for a, b, d in g.edges(data=True):
        keep = [c for c in d["candidates"] if c["rel"] in TRAVERSABLE]
        if keep:
            sub.add_edge(a, b, candidates=keep)
    return sub


def _best_candidate(candidates: list[dict]) -> dict:
    """Certain beats Possible; then the rank above."""
    return min(candidates, key=lambda c: (c.get("confidence") != "Certain",
                                          REL_RANK.get(c["rel"], 99)))


def _materialise(g: nx.DiGraph, nodes: list[str], source: Source, sink: Sink) -> AttackPath:
    hops = []
    for a, b in zip(nodes, nodes[1:]):
        candidates = g[a][b]["candidates"]
        c = _best_candidate(candidates)
        hops.append(Hop(
            frm=a, to=b, rel=c["rel"],
            reason=c.get("reason", ""), evidence=c.get("evidence", ""),
            confidence=c.get("confidence", "Possible"),
            discovered_by=c.get("discovered_by", ""),
            alternatives=tuple(x["rel"] for x in candidates if x is not c),
        ))
    return AttackPath(source=source, sink=sink, nodes=list(nodes), hops=hops)


def find_paths(g: nx.DiGraph, sources=None, sinks=None,
               max_hops: int = MAX_HOPS, k: int = K_PER_PAIR) -> list[AttackPath]:
    """All routes (up to k per source-sink pair, up to max_hops long) from a source to a
    sink. Sorted shortest-first; ranking and deduplication are Phase 5."""
    sub = traversable_subgraph(g)
    sources = find_sources(g) if sources is None else sources
    sinks = find_sinks(g) if sinks is None else sinks

    found: list[AttackPath] = []
    for src in sources:
        if src.uid not in sub:
            continue
        for sink in sinks:
            if sink.uid not in sub or src.uid == sink.uid:
                continue
            try:
                taken = 0
                for nodes in nx.shortest_simple_paths(sub, src.uid, sink.uid):
                    if len(nodes) - 1 > max_hops:
                        break  # yielded shortest-first, so everything after is longer too
                    found.append(_materialise(sub, nodes, src, sink))
                    taken += 1
                    if taken >= k:
                        break
            except (nx.NetworkXNoPath, nx.NodeNotFound):
                continue

    found.sort(key=lambda p: (p.length, p.source.kind, p.source.uid))
    return found
