"""EKS collector — clusters and their AWS-visible settings. Regional. Reads only.

IMPORTANT LIMIT: a read-only IAM role sees only the AWS side of EKS — the cluster's own
config (API endpoint exposure, the cluster IAM role, the OIDC provider used for IRSA). It
CANNOT see the in-cluster access model (the aws-auth ConfigMap, Kubernetes RBAC) or which
pods assume which IRSA roles, because that needs Kubernetes API credentials the role does
not hold. Every EKS finding therefore carries a caveat; privilege escalation inside the
cluster may exist that this cannot see. This is a deliberate boundary (no cluster creds),
not an oversight.
"""
from __future__ import annotations
from .base import collector, paginate


@collector("eks")
def collect(ctx) -> list[dict]:
    def in_region(region: str) -> list[dict]:
        out: list[dict] = []
        eks = ctx.client("eks", region)
        for name in paginate(eks, "list_clusters", "clusters"):
            try:
                c = eks.describe_cluster(name=name)["cluster"]
            except Exception:  # noqa: BLE001
                continue
            vpc = c.get("resourcesVpcConfig") or {}
            out.append({
                "_type": "EksCluster", "_id": c.get("arn") or name, "Region": region,
                "Name": name, "Version": c.get("version"), "Role": c.get("roleArn"),
                "EndpointPublicAccess": vpc.get("endpointPublicAccess"),
                "PublicAccessCidrs": vpc.get("publicAccessCidrs") or [],
                "OidcIssuer": (((c.get("identity") or {}).get("oidc")) or {}).get("issuer"),
            })
        return out
    return ctx.per_region(in_region)
