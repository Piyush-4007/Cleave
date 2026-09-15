"""KMS collector — keys + key policies. Regional. Reads only."""
from __future__ import annotations
from .base import collector, paginate
from ._util import as_doc


@collector("kms")
def collect(ctx) -> list[dict]:
    out: list[dict] = []
    for region in ctx.regions():
        try:
            kms = ctx.client("kms", region)
            for k in paginate(kms, "list_keys", "Keys"):
                kid = k["KeyId"]
                meta, policy = {}, None
                try:
                    meta = kms.describe_key(KeyId=kid).get("KeyMetadata", {})
                except Exception:  # noqa: BLE001
                    pass
                if meta.get("KeyManager") == "AWS":
                    continue  # AWS-managed keys are noise; keep customer-managed only
                try:
                    policy = as_doc(kms.get_key_policy(KeyId=kid, PolicyName="default")["Policy"])
                except Exception:  # noqa: BLE001
                    pass
                out.append({
                    "_type": "KmsKey", "_id": meta.get("Arn") or kid, "Region": region,
                    "KeyId": kid, "Arn": meta.get("Arn"),
                    "KeyManager": meta.get("KeyManager"), "Policy": policy,
                })
        except Exception:  # noqa: BLE001
            continue
    return out
