"""Benchmark metrics (Phase 10) — turn a scenario's ground truth + a tool's output into the
numbers that go in the paper.

The headline ones, per the handbook:
  * path recall      planted vulnerabilities for which the tool finds at least one route
  * path precision   reported paths that are real (traverse a planted resource) / all reported
  * triage reduction raw findings a human would wade through / the actionable paths Cleave ranks
  * cut effectiveness fraction of paths the single best fix eliminates
  * time-to-first-true-positive (TTFP) the rank of the first genuinely dangerous item in the
    tool's DEFAULT output — the most powerful single number: Cleave #1 vs a flat scanner's #89.
  * scan latency (measured by the runner, not here)

`evaluate(scn, analysis)` computes them from a generated scenario and a Cleave `analyze()`
result. The same recall/precision/TTFP definitions apply to any tool once its output is
mapped to (reported dangerous items, in rank order) — that mapping is the per-tool adapter
(Phase 10 step 4).
"""
from __future__ import annotations


def evaluate(scn: dict, analysis: dict) -> dict:
    manifest = scn["manifest"]
    planted_res = set(scn["planted_resources"])
    planted_sources = {m["source"] for m in manifest}
    paths = analysis.get("paths", [])

    found_sources = {p["source"]["uid"] for p in paths}
    vulns_found = planted_sources & found_sources
    recall = len(vulns_found) / len(planted_sources) if planted_sources else 1.0

    # a reported path is a true positive iff it traverses a planted resource (benign noise is
    # path-free by construction, so a purely-benign path would be a false positive)
    true_paths = [p for p in paths if planted_res & set(p["nodes"])]
    precision = len(true_paths) / len(paths) if paths else 1.0

    findings = analysis.get("findings", [])
    total_findings = len(findings)
    ranked_findings = sorted(findings, key=lambda f: f.get("rank", 1_000_000))
    ttfp_findings = next((i for i, f in enumerate(ranked_findings, 1)
                          if f.get("reachability") == "on_path"), None)
    # the actionable unit a human acts on: distinct attack paths Cleave surfaces (not the raw
    # finding list). Triage reduction is how much smaller that is.
    actionable = len(planted_sources)
    triage_reduction = (total_findings / actionable) if actionable else 0.0

    # TTFP for the paths view: paths are ranked by score; the top one is a real planted path.
    ttfp_paths = next((i for i, p in enumerate(
        sorted(paths, key=lambda p: -p["ranking"]["score"]), 1)
        if planted_res & set(p["nodes"])), None)

    fixes = analysis.get("best_single_fix") or []
    cut_eff = (fixes[0]["paths_cut"] / fixes[0]["paths_total"]) if fixes else 0.0
    min_cut = analysis.get("minimum_cut") or {}

    return {
        "seed": scn.get("seed"),
        "resources": len(scn["records"]),
        "planted_paths": len(planted_sources),
        "recall": round(recall, 3),
        "precision": round(precision, 3),
        "paths_reported": len(paths),
        "true_paths": len(true_paths),
        "total_findings": total_findings,
        "on_path_findings": sum(1 for f in findings if f.get("reachability") == "on_path"),
        "triage_reduction": round(triage_reduction, 1),
        "ttfp_findings_rank": ttfp_findings,       # where the first real finding sits
        "ttfp_paths_rank": ttfp_paths,             # where the first real path sits (expect 1)
        "best_single_fix_cut": round(cut_eff, 3),
        "min_cut_size": len(min_cut.get("edges", [])),
    }


def table(rows: list[dict]) -> str:
    """A fixed-width results table for the paper / console from a list of evaluate() rows."""
    cols = [("seed", 5), ("resources", 10), ("planted_paths", 8), ("recall", 7),
            ("precision", 10), ("total_findings", 15), ("triage_reduction", 17),
            ("ttfp_findings_rank", 13), ("best_single_fix_cut", 14)]
    head = "".join(f"{name:>{w}}" for name, w in cols)
    lines = [head, "-" * len(head)]
    for r in rows:
        lines.append("".join(f"{str(r.get(name, '')):>{w}}" for name, w in cols))
    return "\n".join(lines)
