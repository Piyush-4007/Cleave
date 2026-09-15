"""Scan runner: assume CleaveAudit, run every registered collector, write raw JSON.

    python -m cleave.collect

Raw output goes to CLEAVE_OUTPUT_DIR so the graph can be rebuilt without re-hitting AWS.
"""
from __future__ import annotations
import json
import logging
import pathlib
from .config import settings
from .aws_session import build_session
from .collectors import base
from . import collectors as _collectors  # noqa: F401 - imports register the collectors


def run() -> dict[str, int]:
    logging.basicConfig(level=logging.INFO, format="%(levelname)s %(name)s: %(message)s")
    log = logging.getLogger("cleave.collect")

    session = build_session()
    ident = session.client("sts").get_caller_identity()
    log.info("scanning as %s", ident["Arn"])

    ctx = base.Context(session)
    outdir = pathlib.Path(settings.cleave_output_dir)
    outdir.mkdir(parents=True, exist_ok=True)

    summary: dict[str, int] = {}
    for name, fn in base.COLLECTORS.items():
        records = base.safe(name, lambda fn=fn: fn(ctx))
        (outdir / f"{name}.json").write_text(json.dumps(records, indent=2, default=str))
        summary[name] = len(records)
        log.info("  %-12s %d records", name, len(records))

    (outdir / "_summary.json").write_text(json.dumps(summary, indent=2))
    log.info("wrote %d collectors -> %s", len(summary), outdir)
    return summary


if __name__ == "__main__":
    run()
