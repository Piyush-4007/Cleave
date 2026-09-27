"""Analysis service — loads the graph once and serves the cached analysis to the API.

The graph source is Neo4j (what ./load.sh populates after a scan). In dev, if Neo4j is not
up, it falls back to the raw JSON dump so the API still works from a scan alone. The result
is cached: analysis is deterministic, so recomputing per request is wasted work. `refresh`
rebuilds after a new scan/load.
"""
from __future__ import annotations
import json
import logging
import pathlib
import threading
from ..config import settings
from ..paths.analysis import analyze, path_subgraph
from ..paths.graphview import graph_from_neo4j, graph_from_records

log = logging.getLogger("cleave.api")

_LOCK = threading.Lock()
_STATE: dict = {"graph": None, "analysis": None, "source": None}


def _records_from_raw(raw_dir: str):
    raw = pathlib.Path(raw_dir)
    records = []
    for f in sorted(raw.glob("*.json")):
        if f.name.startswith("_"):
            continue
        data = json.loads(f.read_text())
        if isinstance(data, list):
            records.extend(data)
    cred = raw / "_credentials.json"
    creds = json.loads(cred.read_text()) if cred.exists() else []
    return records, creds


def build_graph():
    """Neo4j if reachable, else the raw dump. Returns (graph, source_label)."""
    try:
        from neo4j import GraphDatabase
        driver = GraphDatabase.driver(
            settings.neo4j_uri, auth=(settings.neo4j_user, settings.neo4j_password))
        try:
            g = graph_from_neo4j(driver)
            if g.number_of_nodes() > 0:
                return g, "neo4j"
            log.warning("neo4j reachable but empty — falling back to raw dump")
        finally:
            driver.close()
    except Exception as e:  # noqa: BLE001 - dev fallback, not a product failure
        log.warning("neo4j unavailable (%s) — using raw dump", type(e).__name__)
    records, creds = _records_from_raw(settings.cleave_output_dir)
    return graph_from_records(records, creds), "raw"


def get_state(refresh: bool = False) -> dict:
    with _LOCK:
        if refresh or _STATE["analysis"] is None:
            g, source = build_graph()
            _STATE.update(graph=g, analysis=analyze(g), source=source)
            log.info("analysis built from %s: %d paths", source,
                     _STATE["analysis"]["summary"]["paths_found"])
        return _STATE


def get_analysis(refresh: bool = False) -> dict:
    st = get_state(refresh)
    return {"source": st["source"], **st["analysis"]}


def get_path(path_id: str) -> dict | None:
    st = get_state()
    match = next((d for d in st["analysis"]["paths"] if d["id"] == path_id), None)
    if match is None:
        return None
    sub = path_subgraph(st["graph"], match, st["analysis"]["minimum_cut"]["edges"])
    return {"path": match, "subgraph": sub}
