"""DynamoDB collector — tables + resource-based policies. Regional. Reads only.

Tables can carry a resource-based policy (added 2024); one naming Principal '*' exposes the
table to any AWS account. Same public-exposure shape as SNS/SQS/ECR. get_resource_policy
needs dynamodb:GetResourcePolicy; if denied it stays None (unknown, never a false finding).
"""
from __future__ import annotations
from .base import collector, paginate
from ._util import as_doc


@collector("dynamodb")
def collect(ctx) -> list[dict]:
    def in_region(region: str) -> list[dict]:
        out: list[dict] = []
        ddb = ctx.client("dynamodb", region)
        for name in paginate(ddb, "list_tables", "TableNames"):
            arn, tags, policy = None, {}, None
            try:
                t = ddb.describe_table(TableName=name)["Table"]
                arn = t.get("TableArn")
            except Exception:  # noqa: BLE001
                pass
            if arn:
                try:
                    policy = as_doc(ddb.get_resource_policy(ResourceArn=arn).get("Policy"))
                except Exception:  # noqa: BLE001 - PolicyNotFound / denied -> unknown
                    pass
                try:
                    tags = {t["Key"]: t["Value"] for t in
                            ddb.list_tags_of_resource(ResourceArn=arn).get("Tags", [])}
                except Exception:  # noqa: BLE001
                    pass
            out.append({
                "_type": "DynamoDbTable", "_id": arn or f"table/{region}/{name}",
                "Region": region, "Name": name, "Policy": policy, "Tags": tags,
            })
        return out
    return ctx.per_region(in_region)
