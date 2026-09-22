"""Credential-in-content detection (Phase 3).

Scans S3 object contents for AWS access-key IDs and maps each to the principal it belongs
to, producing CONTAINS_CREDENTIAL edges (bucket -> principal).

Hard rules (handbook):
  - NEVER store the secret value — only the key *id*, its location, and the owning principal.
  - Extension allowlist + size cap; log every object read.
"""
from __future__ import annotations
import logging
import re

log = logging.getLogger("cleave.credscan")

# AWS access-key IDs: AKIA (long-term), ASIA (temporary), AROA (role) + 16 base32 chars.
AWS_KEY_RE = re.compile(r"\b((AKIA|ASIA|AROA)[A-Z0-9]{16})\b")

# Only fetch files that plausibly hold credentials.
ALLOWED_SUFFIXES = (".env", ".tfvars", ".json", ".yml", ".yaml", ".txt", ".config",
                    ".cfg", ".ini", ".properties", "credentials", ".sh", ".py")
MAX_OBJECT_BYTES = 256 * 1024  # don't pull large blobs


def scan_text(text: str) -> list[dict]:
    """Return the key IDs found in `text`. Never returns surrounding secret material."""
    seen = {}
    for kid, ktype in AWS_KEY_RE.findall(text):
        seen[kid] = {"key_id": kid, "key_type": ktype}
    return list(seen.values())


def access_key_owners(iam_records: list[dict]) -> dict[str, str]:
    """Map every known AccessKeyId -> the ARN of the user that owns it."""
    owners = {}
    for r in iam_records:
        if r.get("_type") == "IamUser":
            for k in r.get("AccessKeys", []):
                if k.get("AccessKeyId"):
                    owners[k["AccessKeyId"]] = r["_id"]
    return owners


def _wanted(key: str, size: int) -> bool:
    return size <= MAX_OBJECT_BYTES and key.lower().endswith(ALLOWED_SUFFIXES)


def scan_buckets(session, bucket_records: list[dict], owners: dict[str, str]) -> list[dict]:
    """Live scan: list+get eligible objects, find key IDs, map to owners.
    Returns findings; each is {bucket_id, object_key, key_id, key_type, owner_arn|None}."""
    s3 = session.client("s3")
    findings: list[dict] = []
    for b in bucket_records:
        if b.get("_type") != "S3Bucket":
            continue
        name = b["Name"]
        try:
            paginator = s3.get_paginator("list_objects_v2")
            for page in paginator.paginate(Bucket=name):
                for obj in page.get("Contents", []):
                    if not _wanted(obj["Key"], obj.get("Size", 0)):
                        continue
                    log.info("credscan: reading s3://%s/%s (%dB)", name, obj["Key"], obj.get("Size", 0))
                    try:
                        body = s3.get_object(Bucket=name, Key=obj["Key"])["Body"].read(MAX_OBJECT_BYTES)
                        text = body.decode("utf-8", errors="ignore")
                    except Exception:  # noqa: BLE001 - one object must not sink the scan
                        continue
                    for hit in scan_text(text):
                        findings.append({
                            "bucket_id": b["_id"], "object_key": obj["Key"],
                            "key_id": hit["key_id"], "key_type": hit["key_type"],
                            "owner_arn": owners.get(hit["key_id"]),
                        })
        except Exception as e:  # noqa: BLE001
            log.warning("credscan: bucket %s skipped: %s", name, e)
    return findings


def credential_edges(findings: list[dict]) -> list[dict]:
    """Turn findings into CONTAINS_CREDENTIAL edges (bucket -> owning principal).
    Only emits an edge when the key maps to a known principal."""
    edges = []
    for f in findings:
        if not f.get("owner_arn"):
            continue  # unknown key (foreign account / rotated) — recorded but no principal to link
        edges.append({"frm": f["bucket_id"], "to": f["owner_arn"], "rel": "CONTAINS_CREDENTIAL",
                      "props": {
                          "reason": f"{f['key_type']} access key for the owner found in an object",
                          "evidence": f"{f['bucket_id']}#{f['object_key']} (key {f['key_id']})",
                          "confidence": "Certain", "discovered_by": "credscan"}})
    return edges
