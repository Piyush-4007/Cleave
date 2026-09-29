"""Secrets collector — Secrets Manager secrets + SSM parameters (metadata only).
NEVER reads secret values — only names, ARNs, and resource policies. Regional."""
from __future__ import annotations
from .base import collector, paginate
from ._util import as_doc


@collector("secrets")
def collect(ctx) -> list[dict]:
    def in_region(region: str) -> list[dict]:
        out: list[dict] = []
        # Secrets Manager
        try:
            sm = ctx.client("secretsmanager", region)
            for s in paginate(sm, "list_secrets", "SecretList"):
                policy = None
                try:
                    policy = as_doc(sm.get_resource_policy(SecretId=s["ARN"]).get("ResourcePolicy"))
                except Exception:  # noqa: BLE001
                    pass
                out.append({
                    "_type": "SecretsManagerSecret", "_id": s["ARN"], "Region": region,
                    "Name": s.get("Name"), "Arn": s["ARN"], "ResourcePolicy": policy,
                })
        except Exception:  # noqa: BLE001
            pass
        # SSM Parameter Store (metadata only, never GetParameter values)
        try:
            ssm = ctx.client("ssm", region)
            for p in paginate(ssm, "describe_parameters", "Parameters"):
                out.append({
                    "_type": "SsmParameter", "_id": f"{region}:{p['Name']}", "Region": region,
                    "Name": p.get("Name"), "ParamType": p.get("Type"),
                    "Tier": p.get("Tier"),
                })
        except Exception:  # noqa: BLE001
            pass
        return out

    return ctx.per_region(in_region)
