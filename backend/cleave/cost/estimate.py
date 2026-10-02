"""Cost estimate — "what is running and billing right now", from data already collected.

This is the FREE half of the cost view: no pricing API, no billing permission, no extra
cost to run. It walks the billable resources Cleave already reads (EC2 instances, EBS
volumes, RDS instances, Elastic IPs, NAT gateways), multiplies by bundled on-demand LIST
prices (cost/prices.json), and returns a per-resource estimate plus a monthly total.

It is deliberately an ESTIMATE and says so: list prices, us-east-1 baseline, no
reservations/savings plans, no data-transfer or per-request charges. The actual invoice
comes from the opt-in Cost Explorer panel (cost/explorer.py). Keeping this half free and
offline is the point — a security tool should not need billing access to answer "what can
I turn off".
"""
from __future__ import annotations
import json
import pathlib

PRICES_PATH = pathlib.Path(__file__).with_name("prices.json")


def load_prices() -> dict:
    p = json.loads(PRICES_PATH.read_text(encoding="utf-8"))
    p.pop("_about", None)
    return p


def _price(table: dict, key: str | None) -> float:
    return table.get(key or "", table.get("_default", 0.0))


def estimate(g, prices: dict | None = None) -> dict:
    """Monthly-cost estimate for every running/billable resource in the graph."""
    prices = prices or load_prices()
    hpm = prices["_meta"]["hours_per_month"]
    ec2p, ebsp = prices["ec2_instance_hourly"], prices["ebs_gb_month"]
    rdsp, rds_store = prices["rds_instance_hourly"], prices["rds_storage_gb_month"]
    flat = prices["flat_monthly"]

    items: list[dict] = []

    def add(resource, name, rtype, region, monthly, note=""):
        items.append({"resource": resource, "name": name, "type": rtype, "region": region,
                      "monthly": round(monthly, 2), "note": note})

    for uid, d in g.nodes(data=True):
        rec, label = d.get("record") or {}, d.get("label")
        region = rec.get("Region")
        if label == "Ec2Instance":
            if rec.get("State") != "running":
                continue  # stopped instances bill only for their EBS, counted below
            it = rec.get("InstanceType")
            add(uid, rec.get("InstanceId") or uid, f"EC2 {it}", region, _price(ec2p, it) * hpm,
                "" if it in ec2p else "unknown instance type — default rate")
        elif label == "EbsVolume":
            vt, size = rec.get("VolumeType"), rec.get("Size") or 0
            add(uid, rec.get("VolumeId") or uid, f"EBS {vt} {size}GiB", region, _price(ebsp, vt) * size)
        elif label == "RdsInstance":
            if rec.get("DBInstanceStatus") in ("stopped",):
                continue
            cls = rec.get("DBInstanceClass")
            storage = (rec.get("AllocatedStorage") or 0) * _price(rds_store, rec.get("StorageType"))
            monthly = _price(rdsp, cls) * hpm + storage
            if rec.get("MultiAZ"):
                monthly *= 2
            add(uid, rec.get("DBInstanceIdentifier") or uid,
                f"RDS {cls}{' Multi-AZ' if rec.get('MultiAZ') else ''}", region, monthly,
                "" if cls in rdsp else "unknown instance class — default rate")
        elif label == "ElasticIp":
            add(uid, rec.get("PublicIp") or uid, "Elastic IP", region, flat["elastic_ip"],
                "idle — not attached to anything" if not rec.get("Associated") else "")
        elif label == "NatGateway":
            add(uid, uid, "NAT gateway", region, flat["nat_gateway"],
                "plus per-GB data processing (not estimated)")

    items.sort(key=lambda i: i["monthly"], reverse=True)
    by_type: dict[str, float] = {}
    for i in items:
        family = i["type"].split()[0]
        by_type[family] = round(by_type.get(family, 0.0) + i["monthly"], 2)
    total = round(sum(i["monthly"] for i in items), 2)
    return {
        "monthly_total": total,
        "by_type": by_type,
        "items": items,
        "estimated": True,
        "basis": f"on-demand list prices, {prices['_meta']['region_baseline']} baseline, "
                 f"{prices['_meta']['currency']}/month; excludes reservations, data transfer, "
                 "and per-request charges",
        "idle_elastic_ips": sum(1 for i in items if "idle" in i["note"]),
    }
