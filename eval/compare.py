"""v1 vs v2 — the Phase 7 measurement (handbook: "that delta is a paper figure").

Runs `measure.py` twice over the same corpus: once against a reference commit (v1,
checked out into a temporary git worktree) and once against the working tree (v2),
then diffs edge sets, sources and paths.

    python eval/compare.py [--ref v1-evaluator] [--out eval/results/<name>.json] ITEM...

ITEM is a raw scan directory or a path-fixture JSON (see measure.py). Results stay local
(eval/results/ is gitignored): they contain account ids and ARNs.
"""
from __future__ import annotations
import argparse
import json
import os
import pathlib
import subprocess
import sys
import tempfile

HERE = pathlib.Path(__file__).resolve().parent
REPO = HERE.parent
MEASURE = HERE / "measure.py"


def run_measure(backend: pathlib.Path, item: pathlib.Path) -> dict:
    out = subprocess.run([sys.executable, str(MEASURE), str(item.resolve())],
                         cwd=backend, env={**os.environ, "PYTHONPATH": str(backend)},
                         capture_output=True, text=True, encoding="utf-8")
    if out.returncode:
        raise SystemExit(f"measure failed in {backend} on {item}:\n{out.stderr}")
    return json.loads(out.stdout)


def _t(rows):
    return {tuple(tuple(x) if isinstance(x, list) else x for x in r) for r in rows}


def diff(v1: dict, v2: dict) -> dict:
    def split(key):
        a, b = _t(v1[key]), _t(v2[key])
        return {"v1": len(a), "v2": len(b), "only_v1": sorted(a - b), "only_v2": sorted(b - a)}

    def conf(rows, i):
        return {c: sum(1 for r in rows if r[i] == c) for c in ("Certain", "Possible")}

    return {
        "item": v1["item"],
        "attack_edges": split("attack_edges"),
        "sources": split("sources"),
        "paths": split("paths"),
        "path_confidence": {"v1": conf(v1["paths"], 4), "v2": conf(v2["paths"], 4)},
    }


def main() -> None:
    ap = argparse.ArgumentParser()
    ap.add_argument("items", nargs="+", type=pathlib.Path)
    ap.add_argument("--ref", default="v1-evaluator", help="git ref of the baseline engine")
    ap.add_argument("--out", type=pathlib.Path)
    a = ap.parse_args()

    results = []
    with tempfile.TemporaryDirectory(prefix="cleave-v1-") as tmp:
        wt = pathlib.Path(tmp) / "wt"
        subprocess.run(["git", "-C", str(REPO), "worktree", "add", "--detach", str(wt), a.ref],
                       check=True, capture_output=True)
        try:
            for item in a.items:
                v1 = run_measure(wt / "backend", item)
                v2 = run_measure(REPO / "backend", item)
                results.append(diff(v1, v2))
        finally:
            subprocess.run(["git", "-C", str(REPO), "worktree", "remove", "--force", str(wt)],
                           capture_output=True)

    print(f"{'item':48} {'edges v1>v2':>12} {'paths v1>v2':>12} {'certain v1>v2':>14}")
    for r in results:
        e, p, c = r["attack_edges"], r["paths"], r["path_confidence"]
        print(f"{r['item'][:48]:48} {e['v1']:>5} > {e['v2']:<5} {p['v1']:>5} > {p['v2']:<5}"
              f" {c['v1']['Certain']:>6} > {c['v2']['Certain']:<6}")
    if a.out:
        a.out.parent.mkdir(parents=True, exist_ok=True)
        a.out.write_text(json.dumps(results, indent=1, default=list), encoding="utf-8")
        print(f"\nfull diff -> {a.out}")


if __name__ == "__main__":
    main()
