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
import time
from ..config import settings
from ..paths.analysis import analyze, path_subgraph
from ..paths.graphview import graph_from_neo4j, graph_from_records
from ..identity import caller_identity

log = logging.getLogger("cleave.api")

_LOCK = threading.Lock()
_STATE: dict = {"graph": None, "analysis": None, "source": None, "account": None,
                "connected": False, "mode": None, "scanning": False}


def _meta_from_raw(raw_dir: str) -> dict:
    """Who the dump on disk belongs to (written by write_raw), or {} for an older dump.

    Scans saved before identity was recorded still carry the caller ARN, and the name is
    in it; derive the identity fields so the UI never shows 'unknown identity' for them."""
    f = pathlib.Path(raw_dir) / "_meta.json"
    try:
        meta = json.loads(f.read_text()) if f.exists() else {}
    except ValueError:
        return {}
    if meta.get("arn") and not meta.get("principal_type"):
        meta = {**caller_identity(meta["arn"]), **meta}
    return meta


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
        started = time.perf_counter()
        session = aws_session.build_session_for(role_arn if mode == "role" else None)
        scan = collect.collect_records(session, credscan=settings.cleave_credscan)
        g = graph_from_records(scan["records"], scan["cred_findings"])
        analysis = analyze(g)
        # Who/what was scanned, for the connected-account panel. Saved with the dump so a
        # restart shows the same panel without re-scanning.
        meta = {
            "account": scan["account"], "alias": scan.get("alias"), "mode": mode,
            "role_arn": role_arn if mode == "role" else None,
            "scanned_at": datetime.now(timezone.utc).isoformat(),
            "duration_s": round(time.perf_counter() - started, 1),
            "resources": len(scan["records"]),
            **caller_identity(scan["arn"], g),
        }
        # Persist it, so a restart (or the desktop app reopening) shows this scan again.
        # A write failure costs persistence, never the scan result.
        try:
            collect.write_raw(pathlib.Path(settings.cleave_output_dir), scan["by_collector"],
                              scan["cred_findings"], meta=meta)
        except OSError as e:
            log.warning("could not persist scan to %s: %s", settings.cleave_output_dir, e)
        # ...and add it to the history. Like persistence, a failure here never fails a scan.
        try:
            from .. import history
            meta["scan_id"] = history.record(meta, analysis)
        except Exception as e:  # noqa: BLE001
            log.warning("could not record scan history: %s", e)
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
        if meta.get("admin_credentials") is None and meta.get("arn") and st.get("graph") is not None:
            meta["admin_credentials"] = caller_identity(meta["arn"], st["graph"])["admin_credentials"]
        out["last_scan"] = meta
    return out


def run_gate(plan: dict, refresh: bool = False) -> dict:
    """Run the merge gate (Phase 9): diff the live account against the Terraform plan and
    report the attack paths the PR would introduce, plus a rendered PR comment. Reuses the
    live records the current analysis was built from."""
    from ..gate.diff import gate
    from ..gate.comment import render_comment
    get_state(refresh)  # ensure the account id is resolved
    records, creds = _records_from_raw(settings.cleave_output_dir)
    account = _STATE.get("account") or "PLAN"
    result = gate(records, plan, account, creds)
    result["account"] = account
    result["comment"] = render_comment(result)
    return result


def get_remediation(refresh: bool = False) -> dict:
    """The fixes for the current analysis: one per minimum-cut edge (Phase 8).

    Each fix carries corrected Terraform (when Cleave can generate it exactly) or guidance,
    its blast radius, and a confidence. Cleave never applies anything — the user reviews
    and applies, then rescans to confirm. `files` is the ready-to-download .tf bundle.
    """
    from ..remediation.generate import generate_for_result
    from ..remediation.bundle import bundle_files
    st = get_state(refresh)
    fixes = generate_for_result(st["analysis"], st["graph"])
    return {
        "fixes": fixes,
        "templated": sum(1 for f in fixes if f["confidence"] == "templated"),
        "guidance": sum(1 for f in fixes if f["confidence"] == "guidance"),
        "files": bundle_files(fixes),   # {filename: contents} for a client-side download
    }


def open_remediation_pr(dry_run: bool = False) -> dict:
    """Open (or preview) the current remediation as a GitHub PR. Credentials come from the
    environment only; see cleave.remediation.pr."""
    from ..remediation.pr import open_pr
    fixes = get_remediation()["fixes"]
    return open_pr(fixes, repo=settings.cleave_github_repo,
                   token=settings.cleave_github_token, base=settings.cleave_pr_base,
                   dry_run=dry_run)


def disconnect(forget_history: bool = False) -> dict:
    """Forget the connected account on this machine.

    Cleave never holds AWS credentials, so there is nothing to revoke: disconnecting clears
    the current scan (memory + the saved raw dump) and, if asked, that account's history.
    The user's own AWS login is untouched.
    """
    from .. import history
    account = _STATE.get("account") or _meta_from_raw(settings.cleave_output_dir).get("account")
    with _LOCK:
        _STATE.update(graph=None, analysis=None, source=None, account=None,
                      connected=False, mode=None, scanning=False)
        raw = pathlib.Path(settings.cleave_output_dir)
        removed = 0
        for f in raw.glob("*.json"):
            f.unlink()
            removed += 1
    deleted = history.forget(account) if (forget_history and account) else 0
    log.info("disconnected %s (%d files removed, %d history scans deleted)", account, removed, deleted)
    return {"disconnected": True, "account": account, "history_deleted": deleted}


def actual_spend_now() -> dict:
    """Run Cost Explorer for the connected account. Opt-in + billed (~$0.01/request), so
    this is only ever called from the explicit /cost/actual route, never from a scan."""
    from datetime import date
    from .. import aws_session
    from ..cost import explorer
    mode = _STATE.get("mode") or "login"
    role_arn = _meta_from_raw(settings.cleave_output_dir).get("role_arn")
    session = aws_session.build_session_for(role_arn if mode == "role" else None)
    out = explorer.actual_spend(session, today=date.today())
    out["account"] = _STATE.get("account")
    return out


def get_path(path_id: str) -> dict | None:
    st = get_state()
    match = next((d for d in st["analysis"]["paths"] if d["id"] == path_id), None)
    if match is None:
        return None
    sub = path_subgraph(st["graph"], match, st["analysis"]["minimum_cut"]["edges"])
    return {"path": match, "subgraph": sub}
