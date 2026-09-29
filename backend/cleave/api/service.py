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
_STATE: dict = {"graph": None, "analysis": None, "source": None, "account": None,
                "connected": False, "mode": None, "scanning": False}


def _meta_from_raw(raw_dir: str) -> dict:
    """Who the dump on disk belongs to (written by write_raw), or {} for an older dump."""
    f = pathlib.Path(raw_dir) / "_meta.json"
    try:
        return json.loads(f.read_text()) if f.exists() else {}
    except ValueError:
        return {}


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
    """Neo4j if configured and reachable, else the raw dump. Returns (graph, source_label).
    The desktop app sets CLEAVE_GRAPH_STORE=memory and never touches Neo4j."""
    if settings.cleave_graph_store == "memory":
        records, creds = _records_from_raw(settings.cleave_output_dir)
        return graph_from_records(records, creds), "raw"
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
            if source == "raw" and not _STATE["account"]:
                _STATE["account"] = _meta_from_raw(settings.cleave_output_dir).get("account")
            log.info("analysis built from %s: %d paths", source,
                     _STATE["analysis"]["summary"]["paths_found"])
        return _STATE


def run_scan(mode: str, role_arn: str | None = None) -> dict:
    """Scan an AWS account on demand and make its analysis the current one.

    mode "login" uses the machine's ambient AWS credentials; mode "role" assumes the
    read-only role at `role_arn`. Both are local-first: no credential leaves the machine,
    and Cleave only ever makes read calls. Returns the connection status.
    """
    from datetime import datetime, timezone
    from .. import aws_session, collect

    with _LOCK:
        _STATE["scanning"] = True
    try:
        session = aws_session.build_session_for(role_arn if mode == "role" else None)
        scan = collect.collect_records(session, credscan=settings.cleave_credscan)
        # Persist it, so a restart (or the desktop app reopening) shows this scan again.
        # A write failure costs persistence, never the scan result.
        try:
            collect.write_raw(pathlib.Path(settings.cleave_output_dir), scan["by_collector"],
                              scan["cred_findings"], meta={
                                  "account": scan["account"], "arn": scan["arn"], "mode": mode,
                                  "scanned_at": datetime.now(timezone.utc).isoformat()})
        except OSError as e:
            log.warning("could not persist scan to %s: %s", settings.cleave_output_dir, e)
        g = graph_from_records(scan["records"], scan["cred_findings"])
        analysis = analyze(g)
        with _LOCK:
            _STATE.update(graph=g, analysis=analysis, source="scan",
                          account=scan["account"], connected=True, mode=mode, scanning=False)
        log.info("scan (%s) of %s: %d paths", mode, scan["account"],
                 analysis["summary"]["paths_found"])
    except Exception:
        with _LOCK:
            _STATE["scanning"] = False
        raise
    return connection_status()


def connection_status() -> dict:
    return {
        "connected": _STATE["connected"],
        "scanning": _STATE["scanning"],
        "account": _STATE["account"],
        "mode": _STATE["mode"],
        "paths_found": (_STATE["analysis"] or {}).get("summary", {}).get("paths_found")
        if _STATE["analysis"] else None,
        # The scan saved on disk (account, mode, scanned_at), if any — lets the desktop app
        # open straight on the last result instead of the connect screen.
        "last_scan": _meta_from_raw(settings.cleave_output_dir) or None,
    }


def get_analysis(refresh: bool = False) -> dict:
    st = get_state(refresh)
    account = st.get("account")
    out = {"source": st["source"], **st["analysis"]}
    if account:
        out["account"] = account
    # When/how the shown scan was taken, so the UI can say "scan complete" rather than
    # leave a clean result looking like nothing happened.
    meta = _meta_from_raw(settings.cleave_output_dir)
    if meta and meta.get("account") == account:
        out["last_scan"] = meta
    return out


def get_path(path_id: str) -> dict | None:
    st = get_state()
    match = next((d for d in st["analysis"]["paths"] if d["id"] == path_id), None)
    if match is None:
        return None
    sub = path_subgraph(st["graph"], match, st["analysis"]["minimum_cut"]["edges"])
    return {"path": match, "subgraph": sub}
