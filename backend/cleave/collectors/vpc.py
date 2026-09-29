"""VPC collector — security groups, NACLs, route tables, subnets, VPCs, IGWs.
Regional. Each object type becomes its own normalised record. Reads only."""
from __future__ import annotations
from .base import collector, paginate


@collector("vpc")
def collect(ctx) -> list[dict]:
    def in_region(region: str) -> list[dict]:
        out: list[dict] = []
        try:
            ec2 = ctx.client("ec2", region)

            for sg in paginate(ec2, "describe_security_groups", "SecurityGroups"):
                out.append({
                    "_type": "SecurityGroup", "_id": sg["GroupId"], "Region": region,
                    "GroupId": sg["GroupId"], "GroupName": sg.get("GroupName"),
                    "VpcId": sg.get("VpcId"),
                    "IngressRules": sg.get("IpPermissions", []),
                    "EgressRules": sg.get("IpPermissionsEgress", []),
                })

            for nacl in paginate(ec2, "describe_network_acls", "NetworkAcls"):
                out.append({
                    "_type": "NetworkAcl", "_id": nacl["NetworkAclId"], "Region": region,
                    "NetworkAclId": nacl["NetworkAclId"], "VpcId": nacl.get("VpcId"),
                    "Entries": nacl.get("Entries", []),
                    "Associations": [a.get("SubnetId") for a in nacl.get("Associations", [])],
                })

            for rt in paginate(ec2, "describe_route_tables", "RouteTables"):
                out.append({
                    "_type": "RouteTable", "_id": rt["RouteTableId"], "Region": region,
                    "RouteTableId": rt["RouteTableId"], "VpcId": rt.get("VpcId"),
                    "Routes": rt.get("Routes", []),
                    "Associations": [
                        {"SubnetId": a.get("SubnetId"), "Main": a.get("Main")}
                        for a in rt.get("Associations", [])
                    ],
                })

            for sn in paginate(ec2, "describe_subnets", "Subnets"):
                out.append({
                    "_type": "Subnet", "_id": sn["SubnetId"], "Region": region,
                    "SubnetId": sn["SubnetId"], "VpcId": sn.get("VpcId"),
                    "CidrBlock": sn.get("CidrBlock"),
                    "MapPublicIpOnLaunch": sn.get("MapPublicIpOnLaunch"),
                    "AvailabilityZone": sn.get("AvailabilityZone"),
                })

            for vpc in paginate(ec2, "describe_vpcs", "Vpcs"):
                out.append({
                    "_type": "Vpc", "_id": vpc["VpcId"], "Region": region,
                    "VpcId": vpc["VpcId"], "CidrBlock": vpc.get("CidrBlock"),
                    "IsDefault": vpc.get("IsDefault"),
                })

            for igw in paginate(ec2, "describe_internet_gateways", "InternetGateways"):
                out.append({
                    "_type": "InternetGateway", "_id": igw["InternetGatewayId"], "Region": region,
                    "InternetGatewayId": igw["InternetGatewayId"],
                    "AttachedVpcs": [a.get("VpcId") for a in igw.get("Attachments", [])],
                })
        except Exception:  # noqa: BLE001
            pass  # keep what this region yielded before the failure
        return out

    return ctx.per_region(in_region)
