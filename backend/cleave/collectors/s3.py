"""S3 collector — buckets + bucket policy, ACL, public-access-block, encryption.
Bucket-level calls only (free). Reads and normalises only."""
from __future__ import annotations
from .base import collector
from ._util import as_doc


def _try(fn):
    try:
        return fn()
    except Exception:  # noqa: BLE001 - a per-bucket permission gap must not sink the collector
        return None


@collector("s3")
def collect(ctx) -> list[dict]:
    s3 = ctx.client("s3")
    out: list[dict] = []
    for b in s3.list_buckets().get("Buckets", []):
        name = b["Name"]
        loc = _try(lambda: s3.get_bucket_location(Bucket=name).get("LocationConstraint")) or "us-east-1"
        policy = _try(lambda: as_doc(s3.get_bucket_policy(Bucket=name)["Policy"]))
        pab = _try(lambda: s3.get_public_access_block(Bucket=name)
                   .get("PublicAccessBlockConfiguration"))
        acl = _try(lambda: s3.get_bucket_acl(Bucket=name).get("Grants"))
        enc = _try(lambda: s3.get_bucket_encryption(Bucket=name)
                   .get("ServerSideEncryptionConfiguration"))
        # Tags are read, not judged — the sink layer decides what a tag means. Untagged
        # buckets raise NoSuchTagSet, which _try swallows to {}.
        tagset = _try(lambda: s3.get_bucket_tagging(Bucket=name).get("TagSet")) or []
        tags = {t["Key"]: t["Value"] for t in tagset}
        out.append({
            "_type": "S3Bucket", "_id": f"arn:aws:s3:::{name}", "Name": name,
            "Region": loc, "CreationDate": b.get("CreationDate"),
            "Policy": policy, "PublicAccessBlock": pab, "Acl": acl, "Encryption": enc,
            "Tags": tags,
        })
    return out
