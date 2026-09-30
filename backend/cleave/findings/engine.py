"""Findings engine: run the checks, then rank them the Cleave way.

A conventional scanner stops at severity. Cleave adds the one question a flat list can't
answer: can an attacker actually reach this? Every finding gets a reachability tag,
computed from the attack paths the same scan found:

  on_path        a node the finding concerns lies on a ranked attack path (with path ids)
  entry_point    it concerns an external entry point (e.g. a public bucket) that leads
                 nowhere worse yet
  account        an account-wide setting (password policy, CloudTrail, root)
  not_reachable  none of the above: a real weakness, but no computed route uses it

Ranking: on_path first, then entry_point, account, not_reachable; within each, by
severity. A critical nobody can reach sorts below a medium on a live path. That ordering
is the thesis, applied to the findings list.
"""
from __future__ import annotations
import hashlib
import json
import pathlib

from .checks import CHECKS, Ctx

CATALOG_PATH = pathlib.Path(__file__).with_name("catalog.json")
SEVERITIES = ("critical", "high", "medium", "low", "info")
TAGS = ("on_path", "entry_point", "account", "not_reachable")


def load_catalog() -> dict:
    cat = json.loads(CATALOG_PATH.read_text(encoding="utf-8"))
    cat.pop("_about", None)
    return cat


def run_checks(g, now=None) -> list[dict]:
    """Every check over one scan's graph. No AWS calls, deterministic order."""
    catalog = load_catalog()
    ctx = Ctx(g, now=now)
    out: list[dict] = []
    for cid in sorted(CHECKS):
        meta = catalog[cid]
        for hit in CHECKS[cid](ctx):
            fid = hashlib.sha1(f"{cid}|{hit.resource}|{hit.evidence}".encode()).hexdigest()[:10]
            out.append({
                "id": f"F-{fid}",
                "check": cid,
                "title": meta["title"],
                "service": meta["service"],
                "severity": hit.severity or meta["severity"],
                "base_severity": meta["severity"],
                "severity_reason": hit.severity_reason,
                "cis": meta.get("cis"),
                "caveat": meta.get("caveat"),
                "remediation": meta["remediation"],
                "resource": hit.resource,
                "resource_name": hit.name or hit.resource.split("/")[-1],
                "region": hit.region,
                "evidence": hit.evidence,
                "nodes": list(dict.fromkeys(hit.nodes)),
            })
    return out


def tag_and_rank(findings: list[dict], ranked_paths: list[dict], sources) -> list[dict]:
    """Attach the reachability tag (+ the paths a finding sits on) and sort."""
    on_paths: dict[str, list[str]] = {}
    for p in ranked_paths:
        for uid in p["nodes"]:
            on_paths.setdefault(uid, []).append(p["id"])
    external = {s.uid for s in sources if s.kind == "EXTERNAL"}

    for f in findings:
        paths = sorted({pid for n in f["nodes"] for pid in on_paths.get(n, [])},
                       key=lambda pid: next(i for i, p in enumerate(ranked_paths) if p["id"] == pid))
        if paths:
            tag = "on_path"
        elif any(n in external for n in f["nodes"]):
            tag = "entry_point"
        elif f["resource"] == "account":
            tag = "account"
        else:
            tag = "not_reachable"
        f["reachability"], f["paths"] = tag, paths

    findings.sort(key=lambda f: (TAGS.index(f["reachability"]), SEVERITIES.index(f["severity"]),
                                 f["check"], f["resource"]))
    for i, f in enumerate(findings, 1):
        f["rank"] = i
    return findings


def summarize(findings: list[dict]) -> dict:
    by_sev = {s: 0 for s in SEVERITIES}
    by_tag = {t: 0 for t in TAGS}
    for f in findings:
        by_sev[f["severity"]] += 1
        by_tag[f["reachability"]] += 1
    return {"total": len(findings), "by_severity": by_sev, "by_reachability": by_tag,
            "checks_run": len(CHECKS), "checks_failed": len({f["check"] for f in findings})}
