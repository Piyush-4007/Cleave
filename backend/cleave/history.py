"""Scan history — every scan's results, kept in SQLite, and the diff between scans.

Why SQLite: the desktop app ships no database server, and history is small (a scan is a
few hundred rows). Python's built-in sqlite3 needs no dependency, and the file lives next
to the scan data (`<data>/cleave.db`), so "forget this account" is a local delete.

What is stored per scan: who/when/how, the headline counts, and every finding and path
under a STABLE key. Finding key = check + resource: the evidence text is not part of it,
because it changes as time passes ("key created 161 days ago" -> "162 days"). Path key =
the node sequence. With stable keys, two scans diff cleanly into new / resolved.
"""
from __future__ import annotations
import json
import pathlib
import sqlite3
import threading
from contextlib import contextmanager

from .config import settings

_LOCK = threading.Lock()

SCHEMA = """
CREATE TABLE IF NOT EXISTS scans (
    id              INTEGER PRIMARY KEY AUTOINCREMENT,
    account         TEXT NOT NULL,
    alias           TEXT,
    arn             TEXT,
    principal_name  TEXT,
    principal_type  TEXT,
    mode            TEXT,
    scanned_at      TEXT NOT NULL,
    duration_s      REAL,
    resources       INTEGER,
    paths_found     INTEGER,
    top_score       REAL,
    findings_total  INTEGER,
    on_path         INTEGER,
    by_severity     TEXT,           -- JSON {critical: n, ...}
    checks          TEXT            -- JSON [check ids that ran]: what this scan could see
);
CREATE INDEX IF NOT EXISTS scans_account ON scans(account, id);
CREATE TABLE IF NOT EXISTS scan_findings (
    scan_id       INTEGER NOT NULL REFERENCES scans(id) ON DELETE CASCADE,
    key           TEXT NOT NULL,
    check_id      TEXT, resource TEXT, resource_name TEXT, title TEXT,
    severity      TEXT, reachability TEXT, evidence TEXT
);
CREATE INDEX IF NOT EXISTS scan_findings_scan ON scan_findings(scan_id);
CREATE TABLE IF NOT EXISTS scan_paths (
    scan_id  INTEGER NOT NULL REFERENCES scans(id) ON DELETE CASCADE,
    key      TEXT NOT NULL,
    path_id  TEXT, title TEXT, score REAL, source_kind TEXT, sink_kind TEXT
);
CREATE INDEX IF NOT EXISTS scan_paths_scan ON scan_paths(scan_id);
"""


def db_path() -> pathlib.Path:
    """CLEAVE_DB_PATH if set, else cleave.db beside the raw-dump folder."""
    if settings.cleave_db_path:
        return pathlib.Path(settings.cleave_db_path)
    return pathlib.Path(settings.cleave_output_dir).parent / "cleave.db"


@contextmanager
def _db():
    path = db_path()
    path.parent.mkdir(parents=True, exist_ok=True)
    with _LOCK:
        con = sqlite3.connect(path)
        con.row_factory = sqlite3.Row
        con.execute("PRAGMA foreign_keys = ON")
        try:
            con.executescript(SCHEMA)
            _migrate(con)
            yield con
            con.commit()
        finally:
            con.close()


def finding_key(f: dict) -> str:
    return f"{f['check']}|{f['resource']}"


def path_key(p: dict) -> str:
    return "|".join(p["nodes"])


def _migrate(con) -> None:
    """Add columns introduced after a database was first created."""
    cols = {r[1] for r in con.execute("PRAGMA table_info(scans)")}
    if "checks" not in cols:
        con.execute("ALTER TABLE scans ADD COLUMN checks TEXT")


def record(meta: dict, analysis: dict, checks: list[str] | None = None) -> int:
    """Store one completed scan. Returns its id. `checks` = the check ids that ran (default:
    every check this build has), so a later diff can tell 'newly introduced' from 'newly
    checked'."""
    if checks is None:
        from .findings.checks import CHECKS
        checks = sorted(CHECKS)
    fs = analysis.get("findings") or []
    summ = analysis.get("findings_summary") or {}
    s = analysis["summary"]
    with _db() as con:
        cur = con.execute(
            """INSERT INTO scans (account, alias, arn, principal_name, principal_type, mode,
                   scanned_at, duration_s, resources, paths_found, top_score, findings_total,
                   on_path, by_severity, checks)
               VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)""",
            (meta.get("account"), meta.get("alias"), meta.get("arn"), meta.get("principal_name"),
             meta.get("principal_type"), meta.get("mode"), meta.get("scanned_at"),
             meta.get("duration_s"), meta.get("resources"), s.get("paths_found"), s.get("top_score"),
             summ.get("total", len(fs)), (summ.get("by_reachability") or {}).get("on_path", 0),
             json.dumps(summ.get("by_severity") or {}), json.dumps(sorted(checks))))
        sid = cur.lastrowid
        con.executemany(
            "INSERT INTO scan_findings VALUES (?,?,?,?,?,?,?,?,?)",
            [(sid, finding_key(f), f["check"], f["resource"], f.get("resource_name"), f.get("title"),
              f["severity"], f.get("reachability"), f.get("evidence")) for f in fs])
        con.executemany(
            "INSERT INTO scan_paths VALUES (?,?,?,?,?,?,?)",
            [(sid, path_key(p), p.get("id"), p.get("title"), (p.get("ranking") or {}).get("score"),
              (p.get("source") or {}).get("kind"), (p.get("sink") or {}).get("kind")) for p in analysis["paths"]])
        return sid


def _scan_row(r: sqlite3.Row) -> dict:
    d = dict(r)
    d["by_severity"] = json.loads(d["by_severity"] or "{}")
    d["checks"] = json.loads(d["checks"]) if d.get("checks") else None
    return d


def _keys(con, table: str, sid: int) -> set[str]:
    return {r[0] for r in con.execute(f"SELECT key FROM {table} WHERE scan_id=?", (sid,))}


def _previous_id(con, sid: int, account: str) -> int | None:
    r = con.execute("SELECT id FROM scans WHERE account=? AND id<? ORDER BY id DESC LIMIT 1",
                    (account, sid)).fetchone()
    return r[0] if r else None


def list_scans(account: str | None = None, limit: int = 200) -> list[dict]:
    """Newest first, each with its change vs the previous scan of the same account."""
    with _db() as con:
        q = "SELECT * FROM scans" + (" WHERE account=?" if account else "") + " ORDER BY id DESC LIMIT ?"
        rows = con.execute(q, (account, limit) if account else (limit,)).fetchall()
        out = []
        for r in rows:
            d = _scan_row(r)
            prev = _previous_id(con, d["id"], d["account"])
            if prev is None:
                d["delta"] = None
            else:
                fa, fb = _keys(con, "scan_findings", prev), _keys(con, "scan_findings", d["id"])
                pr = con.execute("SELECT checks FROM scans WHERE id=?", (prev,)).fetchone()[0]
                before = set(json.loads(pr)) if pr else None
                # findings from checks the previous scan never ran are not "new"
                fb_comparable = {k for k in fb if before is not None and k.split("|", 1)[0] in before}
                newly_checked = len(fb - fa) - len(fb_comparable - fa)
                pa, pb = _keys(con, "scan_paths", prev), _keys(con, "scan_paths", d["id"])
                d["delta"] = {"previous_id": prev,
                              "findings_new": len(fb_comparable - fa), "findings_newly_checked": newly_checked,
                              "findings_resolved": len(fa - fb),
                              "paths_new": len(pb - pa), "paths_resolved": len(pa - pb)}
            out.append(d)
        return out


def diff(scan_id: int) -> dict | None:
    """One scan against the previous scan of the same account: what appeared, what went."""
    with _db() as con:
        r = con.execute("SELECT * FROM scans WHERE id=?", (scan_id,)).fetchone()
        if r is None:
            return None
        scan = _scan_row(r)
        prev = _previous_id(con, scan_id, scan["account"])

        def rows(table, sid):
            return {x["key"]: {k: x[k] for k in x.keys() if k not in ("scan_id",)}
                    for x in con.execute(f"SELECT * FROM {table} WHERE scan_id=?", (sid,))}

        f_now, p_now = rows("scan_findings", scan_id), rows("scan_paths", scan_id)
        f_before = rows("scan_findings", prev) if prev is not None else {}
        p_before = rows("scan_paths", prev) if prev is not None else {}
        previous = _scan_row(con.execute("SELECT * FROM scans WHERE id=?", (prev,)).fetchone()) if prev is not None else None
    # A finding from a check the previous scan did not run was not "introduced": the
    # previous scan simply could not see it. Label it, so the diff never overclaims.
    before_checks = set(previous["checks"]) if previous and previous.get("checks") else None
    newly_checked = set()
    for v in f_now.values():
        v["newly_checked"] = before_checks is not None and v["check_id"] not in before_checks \
            or (previous is not None and before_checks is None)
        if v["newly_checked"]:
            newly_checked.add(v["key"])
    sev = ("critical", "high", "medium", "low", "info")
    order = lambda f: (sev.index(f["severity"]) if f["severity"] in sev else 9, f["key"])  # noqa: E731
    now_checks = set(scan["checks"] or [])
    return {
        "scan": scan,
        "previous": previous,
        "coverage_changed": previous is not None and (before_checks is None or before_checks != now_checks),
        "findings": {
            "new": sorted((v for k, v in f_now.items() if k not in f_before), key=order),
            "resolved": sorted((v for k, v in f_before.items() if k not in f_now), key=order),
            "unchanged": len(f_now.keys() & f_before.keys()),
        },
        "paths": {
            "new": [v for k, v in p_now.items() if k not in p_before],
            "resolved": [v for k, v in p_before.items() if k not in p_now],
            "unchanged": len(p_now.keys() & p_before.keys()),
        },
    }


def forget(account: str) -> int:
    """Delete every stored scan of one account. Returns how many scans were removed."""
    with _db() as con:
        return con.execute("DELETE FROM scans WHERE account=?", (account,)).rowcount
