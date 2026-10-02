"""Run the merge gate from the command line (Phase 9).

    terraform show -json tfplan > plan.json
    python -m cleave.gate.run --plan plan.json --live <raw-dump-dir> --account 1234567890

Exits non-zero when the PR introduces a new attack path, so a CI step fails the check.
`--live` is a raw collector dump (the same layout GET /analysis reads); omit it to gate the
plan against an empty account (useful for a from-scratch environment).
"""
from __future__ import annotations
import argparse
import json
import pathlib
import sys

from .diff import gate


def _live_from_raw(raw_dir: str) -> tuple[list[dict], list[dict]]:
    raw = pathlib.Path(raw_dir)
    records: list[dict] = []
    for f in sorted(raw.glob("*.json")):
        if f.name.startswith("_"):
            continue
        data = json.loads(f.read_text(encoding="utf-8"))
        if isinstance(data, list):
            records.extend(data)
    cred = raw / "_credentials.json"
    creds = json.loads(cred.read_text(encoding="utf-8")) if cred.exists() else []
    return records, creds


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(description="Cleave merge gate — block PRs that open attack paths")
    ap.add_argument("--plan", required=True, help="terraform show -json output")
    ap.add_argument("--live", help="raw collector dump of the live account (default: empty)")
    ap.add_argument("--account", default="PLAN", help="live account id (for ARN alignment)")
    ap.add_argument("--json", action="store_true", help="emit the full result as JSON")
    a = ap.parse_args(argv)

    plan = json.loads(pathlib.Path(a.plan).read_text(encoding="utf-8"))
    live, creds = _live_from_raw(a.live) if a.live else ([], [])
    result = gate(live, plan, a.account, creds)

    if a.json:
        print(json.dumps(result, indent=2))
    else:
        n = result["introduced"]
        if n:
            print(f"BLOCKED — this change introduces {n} new attack path(s):\n")
            for np in result["new_paths_narrated"]:
                print(np)
                print()
            print(f"(account had {result['paths_before']} path(s) before, "
                  f"{result['paths_after']} after)")
        else:
            print(f"OK — no new attack paths. "
                  f"({result['paths_before']} before, {result['paths_after']} after"
                  + (f", {result['paths_removed']} removed" if result['paths_removed'] else "")
                  + ")")
    return 1 if result["blocked"] else 0


if __name__ == "__main__":
    sys.exit(main())
