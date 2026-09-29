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

log = logging.getLogger("cleave.collect")


def collect_records(session, credscan: bool = False) -> dict:
    """Run every collector against a session and return everything in memory (no files
    written). This is what the API's on-demand scan uses; the CLI `run()` wraps it and
    also writes the raw JSON dump. Returns account id, flat record list, and cred findings.
    """
    ident = session.client("sts").get_caller_identity()
    log.info("scanning as %s", ident["Arn"])
    ctx = base.Context(session)

    collected: dict[str, list] = {}
    for name, fn in base.COLLECTORS.items():
        collected[name] = base.safe(name, lambda fn=fn: fn(ctx))
        log.info("  %-12s %d records", name, len(collected[name]))

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

    summary: dict[str, int] = {}
    collected: dict[str, list] = {}
    for name, fn in base.COLLECTORS.items():
        records = base.safe(name, lambda fn=fn: fn(ctx))
        collected[name] = records
        (outdir / f"{name}.json").write_text(json.dumps(records, indent=2, default=str))
        summary[name] = len(records)
        log.info("  %-12s %d records", name, len(records))

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
