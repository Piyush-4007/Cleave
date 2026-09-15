"""EC2 collector — instances, public IPs, instance profiles, IMDS settings.
Regional. Reads and normalises only."""
from __future__ import annotations
from .base import collector, paginate


@collector("ec2")
def collect(ctx) -> list[dict]:
    out: list[dict] = []
    for region in ctx.regions():
        try:
            ec2 = ctx.client("ec2", region)
            for res in paginate(ec2, "describe_instances", "Reservations"):
                for i in res.get("Instances", []):
                    if i.get("State", {}).get("Name") == "terminated":
                        continue
                    out.append({
                        "_type": "Ec2Instance", "_id": i["InstanceId"], "Region": region,
                        "InstanceId": i["InstanceId"], "InstanceType": i.get("InstanceType"),
                        "State": i.get("State", {}).get("Name"),
                        "PublicIpAddress": i.get("PublicIpAddress"),
                        "PrivateIpAddress": i.get("PrivateIpAddress"),
                        "PublicDnsName": i.get("PublicDnsName") or None,
                        "SubnetId": i.get("SubnetId"), "VpcId": i.get("VpcId"),
                        "SecurityGroups": [g["GroupId"] for g in i.get("SecurityGroups", [])],
                        "IamInstanceProfile": (i.get("IamInstanceProfile") or {}).get("Arn"),
                        "ImdsHttpTokens": (i.get("MetadataOptions") or {}).get("HttpTokens"),
                        "ImageId": i.get("ImageId"),
                    })
        except Exception:  # noqa: BLE001 - skip disabled/failed regions, keep going
            continue
    return out
