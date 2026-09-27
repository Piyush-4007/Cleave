"""Find attack paths in the loaded graph.

    python -m cleave.paths.run              # read the graph from Neo4j
    python -m cleave.paths.run --from-raw   # skip Neo4j, build from CLEAVE_OUTPUT_DIR
    python -m cleave.paths.run --json       # machine-readable (Phase 6 will use the API)
"""
from __future__ import annotations
import argparse
import json
import logging
import pathlib
from ..config import settings
from .endpoints import find_sinks, find_sources
from .graphview import graph_from_neo4j, graph_from_records
from .model import EXTERNAL
from .search import MAX_HOPS, K_PER_PAIR, find_paths
from .ranking import rank
from .cut import minimum_cut, best_single_fix


def _records_from_raw(raw_dir: str) -> tuple[list[dict], list[dict]]:
    raw = pathlib.Path(raw_dir)
    records: list[dict] = []
    for f in sorted(raw.glob("*.json")):
        if f.name.startswith("_"):
            continue
        data = json.loads(f.read_text())
        if isinstance(data, list):
            records.extend(data)
    cred_path = raw / "_credentials.json"
    creds = json.loads(cred_path.read_text()) if cred_path.exists() else []
    return records, creds


def run(from_raw: bool = False, as_json: bool = False,
        max_hops: int = MAX_HOPS, k: int = K_PER_PAIR) -> list[dict]:
    if from_raw:
        records, creds = _records_from_raw(settings.cleave_output_dir)
        g = graph_from_records(records, creds)
    else:
        from neo4j import GraphDatabase
        driver = GraphDatabase.driver(settings.neo4j_uri,
                                      auth=(settings.neo4j_user, settings.neo4j_password))
        try:
            g = graph_from_neo4j(driver)
        finally:
            driver.close()

    sources, sinks = find_sources(g), find_sinks(g)
    paths = find_paths(g, sources, sinks, max_hops=max_hops, k=k)

    ranked = rank(paths, g)
    cut = minimum_cut(paths)
    fixes = best_single_fix(paths)

    if as_json:
        out = {"paths": ranked, "minimum_cut": cut, "best_single_fix": fixes}
        print(json.dumps(out, indent=2))
        return out

    ext = sum(1 for s in sources if s.kind == EXTERNAL)
    print(f"graph: {g.number_of_nodes()} nodes, {g.number_of_edges()} connected pairs")
    print(f"sources: {len(sources)} ({ext} external, {len(sources) - ext} assumed-compromise)"
          f" · sinks: {len(sinks)} · hop limit {max_hops}, K={k}")
    print(f"\n{len(ranked)} attack path(s) found (ranked)\n")
    by_key = {p.dedup_key: p for p in paths}
    for d in ranked:
        r = d["ranking"]
        print(f"--- {d['id']}  score {r['score']}/10  {d['length']} hops  [{d['confidence']}] ---")
        if r["technique"]:
            print(f"    technique: {r['technique']}")
        key = (d["source"]["uid"], d["sink"]["uid"], tuple(h["rel"] for h in d["hops"]))
        print(by_key[key].narrate())
        if d["variants"] > 1:
            print(f"    (+{d['variants'] - 1} variant route(s) collapsed here)")
        print()

    if not ranked:
        print("No path from any source to admin. If a known-vulnerable scenario is "
              "deployed, the edges are wrong — do not raise the hop limit.")
        return {"paths": [], "minimum_cut": cut, "best_single_fix": fixes}

    if fixes:
        top = fixes[0]
        print(f"BEST SINGLE FIX — {top['fix']}")
        print(f"    breaks {top['paths_cut']} of {top['paths_total']} paths, "
              f"remediation cost {top['cost']}/10  ({top['rel']} "
              f"{top['frm'].split('/')[-1]} -> {top['to'].split('/')[-1]})")
    print(f"\nMINIMUM CUT — breaks all {cut['paths_total']} paths, total cost {cut['total_cost']}")
    for e in cut["edges"]:
        print(f"    cut {e['rel']} ({e['frm'].split('/')[-1]} -> {e['to'].split('/')[-1]}), "
              f"cost {e['cost']}: {e['fix']}")
    return {"paths": ranked, "minimum_cut": cut, "best_single_fix": fixes}


def main() -> None:
    logging.basicConfig(level=logging.INFO, format="%(levelname)s %(name)s: %(message)s")
    ap = argparse.ArgumentParser(description="Cleave — attack path search")
    ap.add_argument("--from-raw", action="store_true",
                    help="build the graph from the raw JSON dump instead of Neo4j")
    ap.add_argument("--json", action="store_true", help="emit JSON")
    ap.add_argument("--max-hops", type=int, default=MAX_HOPS)
    ap.add_argument("-k", type=int, default=K_PER_PAIR)
    a = ap.parse_args()
    run(from_raw=a.from_raw, as_json=a.json, max_hops=a.max_hops, k=a.k)


if __name__ == "__main__":
    main()
