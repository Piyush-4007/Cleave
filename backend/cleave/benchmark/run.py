"""Run the full offline benchmark and emit the results tables (Phase 10).

    python -m cleave.benchmark.run                 # print the tables
    python -m cleave.benchmark.run --md report.md  # also write a markdown report

Covers everything that needs no AWS and no third-party tools: Cleave's recall / precision /
triage-reduction / TTFP / cut-effectiveness across account sizes, scan latency by size, and
the merge-gate detection / false-positive rates over the 30-PR corpus. The cross-tool columns
(Prowler, ScoutSuite, …) and the CloudGoat reality-check are filled in during the live run.
"""
from __future__ import annotations
import argparse
import time

from ..paths.analysis import analyze
from ..paths.graphview import graph_from_records
from .corpus import evaluate_gate
from .generate import generate
from .metrics import evaluate, table

SIZES = [(1, 120), (2, 180), (3, 240), (4, 300)]   # (seed, benign-resource count)


def run() -> dict:
    rows, latencies = [], []
    for seed, nb in SIZES:
        scn = generate(seed=seed, n_benign=nb, n_paths=5)
        g = graph_from_records(scn["records"], scn["cred_findings"])
        t0 = time.perf_counter()
        analysis = analyze(g)
        dt = time.perf_counter() - t0
        m = evaluate(scn, analysis)
        m["scan_seconds"] = round(dt, 2)
        rows.append(m)
        latencies.append((m["resources"], round(dt, 2)))
    gate = evaluate_gate()
    return {"metrics": rows, "latency": latencies, "gate": gate}


def _md(res: dict) -> str:
    rows = res["metrics"]
    g = res["gate"]
    out = ["# Cleave — Phase 10 benchmark (offline results)\n",
           "Synthetic accounts with a known ground truth (planted paths among path-free benign "
           "noise), so recall and precision are exact. Reproduce with `python -m "
           "cleave.benchmark.run`. Cross-tool columns and the CloudGoat reality-check are added "
           "in the live run.\n",
           "## Detection quality vs. account size\n",
           "| resources | planted | recall | precision | raw findings | triage reduction | "
           "TTFP (findings) | best-fix cut | scan (s) |",
           "|---|---|---|---|---|---|---|---|---|"]
    for r in rows:
        out.append(f"| {r['resources']} | {r['planted_paths']} | {r['recall']} | "
                   f"{r['precision']} | {r['total_findings']} | {r['triage_reduction']}x | "
                   f"#{r['ttfp_findings_rank']} | {int(r['best_single_fix_cut']*100)}% | "
                   f"{r['scan_seconds']} |")
    out += ["\n## Merge-gate accuracy (30-PR corpus)\n",
            f"- PRs that introduce a path: **{g['bad']}** — detected: "
            f"**{g['true_positives']}** (detection rate **{g['detection_rate']}**)",
            f"- Benign-but-similar PRs: **{g['benign']}** — false alarms: "
            f"**{g['false_positives']}** (false-positive rate **{g['false_positive_rate']}**)",
            "\nThe benign-but-similar half (scoped PassRole, PassRole-only, a 0.0.0.0/0 port "
            "with nothing behind it, a GitHub-OIDC role on a scoped policy, a private "
            "credential bucket) is identical in shape to the dangerous PRs — a linter flags "
            "them; Cleave passes them.\n",
            "## Headline\n",
            f"On the largest account ({rows[-1]['resources']} resources): "
            f"**{rows[-1]['total_findings']} raw findings → {rows[-1]['planted_paths']} "
            f"actionable attack paths** ({rows[-1]['triage_reduction']}x reduction), the first "
            f"genuinely dangerous finding ranked **#{rows[-1]['ttfp_findings_rank']}**, and the "
            f"single best fix cuts **{int(rows[-1]['best_single_fix_cut']*100)}%** of paths.\n"]
    return "\n".join(out) + "\n"


def main(argv: list[str] | None = None) -> None:
    ap = argparse.ArgumentParser(description="Run the Cleave offline benchmark")
    ap.add_argument("--md", help="write a markdown report to this path")
    a = ap.parse_args(argv)
    res = run()
    print(table(res["metrics"]))
    g = res["gate"]
    print(f"\ngate: detection {g['detection_rate']} ({g['true_positives']}/{g['bad']}), "
          f"false-positive {g['false_positive_rate']} ({g['false_positives']}/{g['benign']})")
    print("latency by size:", res["latency"])
    if a.md:
        import pathlib
        pathlib.Path(a.md).write_text(_md(res), encoding="utf-8")
        print(f"\nreport -> {a.md}")


if __name__ == "__main__":
    main()
