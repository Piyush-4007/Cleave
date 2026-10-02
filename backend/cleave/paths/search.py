"""Path search — find the routes from a source to admin.

Increment 1 searched only the edges the graph already held; both Phase 0 ground-truth
scenarios are reachable that way (rollback is HAS_ATTACHED -> GRANTS_ADMIN; attachment is
CAN_LAUNCH_AS -> HAS_ATTACHED -> GRANTS_ADMIN). Increment 2 adds CAN_READ/CAN_WRITE,
computed on demand before the search (see paths/access.py), which is what makes
credential-theft paths visible:
    attacker -> CAN_READ -> bucket -> CONTAINS_CREDENTIAL -> victim -> ... -> Admin

Hop limit 6, K=5 shortest simple paths per source-sink pair (Yen's algorithm, via
networkx.shortest_simple_paths). If a scenario finds nothing, the edges are wrong —
raising the hop limit is the handbook's named trap.
"""
from __future__ import annotations
import networkx as nx
from .access import access_edges, expansion_targets
from .endpoints import PRINCIPAL_LABELS, find_sinks, find_sources, holds_full_admin
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
    "CAN_LAUNCH_AS":        "boot a resource carrying the role, then read its credentials",
    "CAN_TAKE_OVER":        "mint an access key or set the password of the user, then act as it",
    "CAN_JOIN_GROUP":       "add yourself to the group and inherit its policies",
    "CAN_REWRITE_TRUST":    "rewrite the role's trust policy to trust yourself, then assume it",
    "GRANTS_ADMIN":         "this policy is administrator-equivalent",
    "CAN_REACH":            "a network packet can arrive from the internet",
    "ROUTES_TO":            "an unauthenticated API route invokes this function",
    "CONTAINS_CREDENTIAL":  "a credential stored here unlocks this principal",
    "CAN_READ":             "read the resource — its contents, including any credential in them",
    "CAN_WRITE":            "modify the resource — e.g. overwrite function code that runs as a role",
}

# Context, never a step. These exist so CAN_REACH can be *computed*; walking them would
# produce paths like "instance -> subnet -> vpc" that no attacker can traverse.
CONTEXT_ONLY = {
    # PassRole alone does NOT hand you the role -- it only permits handing it to a service,
    # which needs a compute action (RunInstances / CreateFunction) to land anywhere. Walking
    # it would emit a route nobody can actually take, and a reviewer who clicks such a path
    # and finds it unexploitable has falsified the claim that every edge is a real attacker
    # move. The exploitable form is CAN_LAUNCH_AS, which is PassRole *plus* that compute
    # action; the edge stays in the graph as evidence of the primitive.
    "CAN_PASS_ROLE":      "a permission, not a completed step -- CAN_LAUNCH_AS is the walkable form",
    "IN_SUBNET":          "locates a resource for the reachability chain",
    "IN_VPC":             "topology only",
    "PROTECTED_BY":       "the firewall is an input to CAN_REACH, not a step",
    "ROUTES_VIA":         "routing is an input to CAN_REACH, not a step",
    "HAS_INTERNET_ROUTE": "routing is an input to CAN_REACH, not a step",
}

# When two nodes are connected by several relationship types, show the most damning one.
REL_RANK = {rel: i for i, rel in enumerate([
    "CAN_LAUNCH_AS", "CAN_TAKE_OVER", "CAN_REWRITE_TRUST", "CAN_ASSUME",
    "CAN_JOIN_GROUP", "CONTAINS_CREDENTIAL", "CAN_REACH",
    "HAS_INSTANCE_PROFILE", "CONTAINS_ROLE", "EXECUTES_AS",
    "CAN_WRITE", "CAN_READ",
    "GRANTS_ADMIN", "HAS_ATTACHED", "IN_GROUP",
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


def _expand_access(sub: nx.DiGraph, sources, sinks) -> int:
    """Add the CAN_READ/CAN_WRITE edges that could matter to the *search* graph.

    Demand-driven: only resources that lead somewhere, only candidate source principals.
    Runs before the search so traversal still operates on a static graph.
    """
    from .graphview import _add_edge
    sink_uids = frozenset(s.uid for s in sinks)
    targets = expansion_targets(sub, set(TRAVERSABLE), sink_uids)
    if not targets:
        return 0
    edges = access_edges(sub, [s.uid for s in sources], targets)
    for e in edges:
        _add_edge(sub, e)
    return len(edges)


def search_graph(g: nx.DiGraph, sources, sinks, expand: bool = True) -> nx.DiGraph:
    """The graph a search actually runs on: context edges dropped, access edges added.

    Always a fresh copy — `g` is never modified. Searching the same graph twice must give
    the same answer, and Phase 6 will hold one graph and query it repeatedly.
    """
    sub = traversable_subgraph(g)
    if expand:
        _expand_access(sub, sources, sinks)
    return sub


def _stops_at_first_admin(sub: nx.DiGraph, nodes, already_admin) -> bool:
    """True if the route's only full-admin identity is where it hands over to the sink:
    `X -> admin-role -> its admin policy -> Admin` is the finding itself, not a detour."""
    first = next(i for i, n in enumerate(nodes[1:-1], 1) if n in already_admin)
    rest = nodes[first + 1:]
    # after the admin identity, only its own policy link(s) down to the sink may follow
    return all(sub.nodes[n].get("label") not in PRINCIPAL_LABELS
               and sub.nodes[n].get("label") not in ("LambdaFunction", "Ec2Instance", "S3Bucket")
               for n in rest[:-1])


def find_paths(g: nx.DiGraph, sources=None, sinks=None,
               max_hops: int = MAX_HOPS, k: int = K_PER_PAIR,
               expand: bool = True) -> list[AttackPath]:
    """All routes (up to k per source-sink pair, up to max_hops long) from a source to a
    sink. Sorted shortest-first; ranking and deduplication are Phase 5.

    `expand=False` skips CAN_READ/CAN_WRITE expansion — useful to isolate which edges a
    result came from."""
    sources = find_sources(g) if sources is None else sources
    sinks = find_sinks(g) if sinks is None else sinks
    sub = search_graph(g, sources, sinks, expand=expand)
    # An attacker holding a full-admin identity has already won: a route that passes
    # through one and keeps going is the shorter finding counted again (seen in the 30 Sep
    # CloudGoat demo). Such routes are skipped, and do not use up the k per pair.
    already_admin = {uid for uid, d in g.nodes(data=True)
                     if d.get("label") in PRINCIPAL_LABELS and holds_full_admin(g, uid)}

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
                    if already_admin.intersection(nodes[1:-1]) and                             not _stops_at_first_admin(sub, nodes, already_admin):
                        continue
                    found.append(_materialise(sub, nodes, src, sink))
                    taken += 1
                    if taken >= k:
                        break
            except (nx.NetworkXNoPath, nx.NodeNotFound):
                continue

    found.sort(key=lambda p: (p.length, p.source.kind, p.source.uid))
    return found
