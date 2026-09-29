"""RDS collector — instances, public accessibility, subnet groups. Regional."""
from __future__ import annotations
from .base import collector, paginate


@collector("rds")
def collect(ctx) -> list[dict]:
    def in_region(region: str) -> list[dict]:
        out: list[dict] = []
        try:
            rds = ctx.client("rds", region)
            for db in paginate(rds, "describe_db_instances", "DBInstances"):
                out.append({
                    "_type": "RdsInstance", "_id": db["DBInstanceArn"], "Region": region,
                    "DBInstanceIdentifier": db.get("DBInstanceIdentifier"),
                    "Arn": db["DBInstanceArn"], "Engine": db.get("Engine"),
                    "PubliclyAccessible": db.get("PubliclyAccessible"),
                    "Endpoint": (db.get("Endpoint") or {}).get("Address"),
                    "VpcSecurityGroups": [g.get("VpcSecurityGroupId")
                                          for g in db.get("VpcSecurityGroups", [])],
                    "SubnetGroup": (db.get("DBSubnetGroup") or {}).get("DBSubnetGroupName"),
                    "Tags": {t["Key"]: t["Value"] for t in db.get("TagList", [])},
                })
        except Exception:  # noqa: BLE001
            pass  # keep what this region yielded before the failure
        return out

    return ctx.per_region(in_region)
