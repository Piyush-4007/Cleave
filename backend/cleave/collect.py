"""Scan runner: assume CleaveAudit, run every registered collector, write raw JSON.

    python -m cleave.collect

Raw output goes to CLEAVE_OUTPUT_DIR so the graph can be rebuilt without re-hitting AWS.
"""
from __future__ import annotations
import json
import logging
import pathlib
import time
from concurrent.futures import ThreadPoolExecutor
from .config import settings
from .aws_session import build_session
from .collectors import base
from . import collectors as _collectors  # noqa: F401 - imports register the collectors

log = logging.getLogger("cleave.collect")


def run_collectors(ctx: base.Context) -> dict[str, list]:
    """Run every registered collector concurrently, each isolated by `base.safe`.

    Collectors are independent reads of different services, so they overlap; inside each,
    regions / principals fan out too (Context.per_region, Context.map). The result dict is
    in registration order whatever finishes first, so output is deterministic.
    """
    # Resolve regions once up front rather than raced by eight collectors. If it is denied,
    # carry on: the regional collectors each fail inside `safe`, IAM/S3 still run — the
    # same outcome as the serial scan.
    base.safe("regions", lambda: ctx.regions())

    def one(item):
        name, fn = item
        t = time.perf_counter()
        records = base.safe(name, lambda: fn(ctx))
        log.info("  %-12s %4d records  %5.1fs", name, len(records), time.perf_counter() - t)
        return name, records

    items = list(base.COLLECTORS.items())
    workers = len(items) if ctx.workers > 1 else 1
    with ThreadPoolExecutor(max_workers=max(1, workers)) as pool:
        return dict(pool.map(one, items))


def collect_records(session, credscan: bool = False) -> dict:
    """Run every collector against a session and return everything in memory (no files
    written). This is what the API's on-demand scan uses; the CLI `run()` wraps it and
    also writes the raw JSON dump. Returns account id, flat record list, and cred findings.
    """
    ident = session.client("sts").get_caller_identity()
    log.info("scanning as %s", ident["Arn"])
    t = time.perf_counter()
    collected = run_collectors(base.Context(session))
    log.info("collected in %.1fs", time.perf_counter() - t)

    findings: list = []
    if credscan:
        from . import credscan as _cs
        owners = _cs.access_key_owners(collected.get("iam", []))
        findings = base.safe("credscan",
                             lambda: _cs.scan_buckets(session, collected.get("s3", []), owners))

    records = [r for recs in collected.values() for r in recs]
    return {
        "account": ident.get("Account", ""),
        "arn": ident.get("Arn", ""),
        "records": records,
        "cred_findings": findings,
        "counts": {name: len(recs) for name, recs in collected.items()},
    }


def run() -> dict[str, int]:
    logging.basicConfig(level=logging.INFO, format="%(levelname)s %(name)s: %(message)s")
    log = logging.getLogger("cleave.collect")

    session = build_session()
    ident = session.client("sts").get_caller_identity()
    log.info("scanning as %s", ident["Arn"])

    ctx = base.Context(session)
    outdir = pathlib.Path(settings.cleave_output_dir)
    outdir.mkdir(parents=True, exist_ok=True)

    t = time.perf_counter()
    collected = run_collectors(ctx)
    log.info("collected in %.1fs", time.perf_counter() - t)
    summary: dict[str, int] = {}
    for name, records in collected.items():
        (outdir / f"{name}.json").write_text(json.dumps(records, indent=2, default=str))
        summary[name] = len(records)

    # Credential-in-content scan. OFF by default: it reads S3 object bodies (s3:GetObject),
    # which the default read-only role does not grant, so running it unconditionally would
    # spray AccessDenied. The user opts in (docs/opt-in-credscan.md) once they have added
    # the grant. Findings map a leaked key to its owning principal; the secret is never
    # stored (credscan keeps only the key ID).
    if settings.cleave_credscan:
        from . import credscan
        owners = credscan.access_key_owners(collected.get("iam", []))
        findings = base.safe("credscan",
                             lambda: credscan.scan_buckets(session, collected.get("s3", []), owners))
        log.info("  %-12s %d findings", "credscan", len(findings))
    else:
        findings = []
        log.info("  %-12s disabled (set CLEAVE_CREDSCAN=true + grant s3:GetObject to enable)",
                 "credscan")
    (outdir / "_credentials.json").write_text(json.dumps(findings, indent=2, default=str))
    summary["credscan_findings"] = len(findings)

    (outdir / "_summary.json").write_text(json.dumps(summary, indent=2))
    log.info("wrote %d collectors -> %s", len(summary), outdir)
    return summary


if __name__ == "__main__":
    run()
