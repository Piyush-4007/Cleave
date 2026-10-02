"""Measure one engine version on one scan (Phase 7: v1 vs v2).

Run *inside* the backend whose behaviour you want measured — `compare.py` does this
for you with PYTHONPATH pointing at a git worktree of the reference version — so the
same script measures v1 and v2 without either knowing about it. It only touches
public, long-lived entry points (graph_from_records, find_sources/sinks, search_graph,
find_paths), which is why it can run against an older commit.

    python eval/measure.py <corpus-item>      # prints JSON to stdout

A corpus item is either a raw scan directory (the collectors' data/raw layout) or a
path-fixture JSON file (`records` + optional `cred_findings`).
"""
from __future__ import annotations
import json
import logging
import pathlib
import sys

logging.disable(logging.WARNING)


def load_item(p: pathlib.Path) -> tuple[list[dict], list[dict]]:
    if p.is_dir():
        records: list[dict] = []
        for f in sorted(p.glob("*.json")):
            if f.name.startswith("_"):
                continue
            data = json.loads(f.read_text(encoding="utf-8"))
            if isinstance(data, list):
                records.extend(data)
        cred = p / "_credentials.json"
        creds = json.loads(cred.read_text(encoding="utf-8")) if cred.exists() else []
        return records, creds
    fx = json.loads(p.read_text(encoding="utf-8"))
    return fx["records"], fx.get("cred_findings", [])


def measure(p: pathlib.Path) -> dict:
    from cleave.paths.graphview import graph_from_records
    from cleave.paths.endpoints import find_sources, find_sinks
    from cleave.paths.search import search_graph, find_paths, TRAVERSABLE

    records, creds = load_item(p)
    g = graph_from_records(records, creds)
    sources, sinks = find_sources(g), find_sinks(g)
    sub = search_graph(g, sources, sinks)  # includes on-demand CAN_READ/CAN_WRITE

    edges = set()
    for graph, scope in ((g, "graph"), (sub, "search")):
        for a, b, d in graph.edges(data=True):
            for c in d["candidates"]:
                edges.add((c["rel"], a, b, c.get("confidence", "?")))
    paths = find_paths(g, sources, sinks)
    return {
        "item": p.name,
        "edges": sorted(edges),
        "attack_edges": sorted(e for e in edges if e[0] in TRAVERSABLE),
        "sources": sorted((s.uid, s.kind) for s in sources),
        "sinks": sorted((s.uid, s.kind) for s in sinks),
        "paths": sorted({(pa.source.uid, pa.sink.uid, tuple(pa.nodes),
                          tuple(h.rel for h in pa.hops),
                          "Certain" if all(h.confidence == "Certain" for h in pa.hops)
                          else "Possible") for pa in paths}),
    }


if __name__ == "__main__":
    print(json.dumps(measure(pathlib.Path(sys.argv[1])), default=list))
