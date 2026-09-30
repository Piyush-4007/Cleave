"""CloudTrail collector — trails and whether they are logging. Reads only.

describe_trails with includeShadowTrails=True, called once, returns every trail visible
to the account (multi-region trails appear once with their home region). Status is read
from each trail's home region. A `CloudTrailStatus` record marks that the read itself
succeeded, so "no trails" (a finding) can be told apart from "could not read" (unknown).
"""
from __future__ import annotations
from .base import collector


@collector("cloudtrail")
def collect(ctx) -> list[dict]:
    ct = ctx.client("cloudtrail")
    trails = ct.describe_trails(includeShadowTrails=True).get("trailList", [])
    out: list[dict] = []
    seen: set[str] = set()
    for t in trails:
        arn = t.get("TrailARN")
        if not arn or arn in seen:
            continue
        seen.add(arn)
        logging = None
        try:
            logging = ctx.client("cloudtrail", t.get("HomeRegion")).get_trail_status(
                Name=arn).get("IsLogging")
        except Exception:  # noqa: BLE001 - status unknown, trail still recorded
            pass
        out.append({
            "_type": "CloudTrailTrail", "_id": arn, "Name": t.get("Name"),
            "HomeRegion": t.get("HomeRegion"),
            "IsMultiRegionTrail": t.get("IsMultiRegionTrail"),
            "IsOrganizationTrail": t.get("IsOrganizationTrail"),
            "LogFileValidationEnabled": t.get("LogFileValidationEnabled"),
            "KmsKeyId": t.get("KmsKeyId"), "S3BucketName": t.get("S3BucketName"),
            "IsLogging": logging,
        })
    out.append({"_type": "CloudTrailStatus", "_id": "account:cloudtrail", "Trails": len(out)})
    return out
