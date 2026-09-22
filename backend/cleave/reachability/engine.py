"""Network reachability — computes CAN_REACH edges (Internet -> resource).

Works backwards from each resource and requires ALL of the following to hold, as a chain
of small, independently-testable predicates (handbook Phase 3):

    public IP/DNS  AND  a security group open to 0.0.0.0/0 on some port  AND
    the subnet routes to an internet gateway (public subnet)

Reads normalised collector records only — no AWS calls, no judgment about severity.
"""
from __future__ import annotations

PUBLIC_CIDRS = {"0.0.0.0/0", "::/0"}
# ports worth calling out in the reason (everything else is reported generically)
NOTABLE_PORTS = {22: "SSH", 3389: "RDP", 3306: "MySQL", 5432: "Postgres",
                 80: "HTTP", 443: "HTTPS", 6379: "Redis", 27017: "MongoDB"}


# ---- predicates ----------------------------------------------------------------------

def sg_public_ingress(sg: dict) -> list[dict]:
    """Ingress rules on this security group open to the whole internet."""
    out = []
    for rule in sg.get("IngressRules", []):
        cidrs = {r.get("CidrIp") for r in rule.get("IpRanges", [])}
        cidrs |= {r.get("CidrIpv6") for r in rule.get("Ipv6Ranges", [])}
        if cidrs & PUBLIC_CIDRS:
            out.append({"proto": rule.get("IpProtocol"),
                        "from": rule.get("FromPort"), "to": rule.get("ToPort")})
    return out


def subnet_routes_to_igw(subnet_id: str, vpc_id: str, route_tables: list[dict]) -> bool:
    """Public subnet == a route table with 0.0.0.0/0 -> igw-... reaches it.

    Prefer a route table explicitly associated with the subnet; else fall back to the
    VPC's main route table (that's what an unassociated subnet uses)."""
    explicit = None
    main = None
    for rt in route_tables:
        assocs = rt.get("Associations", [])
        if any(a.get("SubnetId") == subnet_id for a in assocs):
            explicit = rt
        if rt.get("VpcId") == vpc_id and any(a.get("Main") for a in assocs):
            main = rt
    rt = explicit or main
    if not rt:
        return False
    for route in rt.get("Routes", []):
        gw = str(route.get("GatewayId", ""))
        if gw.startswith("igw-") and route.get("DestinationCidrBlock") == "0.0.0.0/0":
            return True
    return False


def _ports_label(open_rules: list[dict]) -> str:
    labels = []
    for r in open_rules:
        fp, tp = r.get("from"), r.get("to")
        if fp is None:
            labels.append("all")
        elif fp == tp:
            labels.append(NOTABLE_PORTS.get(fp, str(fp)))
        else:
            labels.append(f"{fp}-{tp}")
    return ", ".join(sorted(set(labels))) or "unknown"


# ---- edge computation ----------------------------------------------------------------

def compute_reach(records: list[dict]) -> list[dict]:
    """Return CAN_REACH edges: Internet -> resource, for internet-exposed EC2/RDS."""
    by_id = {r["_id"]: r for r in records}
    route_tables = [r for r in records if r["_type"] == "RouteTable"]
    edges: list[dict] = []

    for r in records:
        if r["_type"] == "Ec2Instance":
            if not r.get("PublicIpAddress"):
                continue
            open_rules = [rule for sg_id in r.get("SecurityGroups", [])
                          if (sg := by_id.get(sg_id))
                          for rule in sg_public_ingress(sg)]
            if not open_rules:
                continue
            if not subnet_routes_to_igw(r.get("SubnetId"), r.get("VpcId"), route_tables):
                continue
            edges.append(_reach_edge(r["_id"], _ports_label(open_rules),
                                     f"{r['_id']}#PublicIpAddress+SecurityGroups+subnet-route"))

        elif r["_type"] == "RdsInstance" and r.get("PubliclyAccessible"):
            open_rules = [rule for sg_id in r.get("VpcSecurityGroups", [])
                          if (sg := by_id.get(sg_id))
                          for rule in sg_public_ingress(sg)]
            if open_rules:
                edges.append(_reach_edge(r["_id"], _ports_label(open_rules),
                                         f"{r['_id']}#PubliclyAccessible+VpcSecurityGroups"))

    return edges


def _reach_edge(to: str, ports: str, evidence: str) -> dict:
    return {"frm": "internet", "to": to, "rel": "CAN_REACH", "props": {
        "reason": f"internet-reachable on port(s): {ports}", "evidence": evidence,
        "confidence": "Certain", "discovered_by": "reachability",
    }}
