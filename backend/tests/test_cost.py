"""Cost view: the free estimate, and the opt-in Cost Explorer half.

The estimate is computed from collected data with bundled list prices (no AWS call). The
Cost Explorer half is parsed from a canned response (no AWS call, no charge) and its
endpoint is proven to stay OFF unless explicitly enabled.
"""
import datetime as dt
import pytest
from fastapi.testclient import TestClient

from cleave.api.main import app
from cleave.config import settings
from cleave.cost import estimate, load_prices
from cleave.cost.explorer import parse_mtd
from cleave.paths.graphview import graph_from_records


def g(*recs):
    return graph_from_records(list(recs))


def ec2(it="t3.micro", state="running"):
    return {"_type": "Ec2Instance", "_id": f"i-{it}-{state}", "Region": "us-east-1",
            "State": state, "InstanceType": it, "SecurityGroups": []}


def test_running_instance_is_priced_stopped_is_not():
    e = estimate(g(ec2(state="running"), ec2(state="stopped")))
    rows = [i for i in e["items"] if i["type"].startswith("EC2")]
    assert len(rows) == 1 and rows[0]["monthly"] > 0


def test_unknown_instance_type_uses_default_and_says_so():
    e = estimate(g(ec2(it="x9.mega")))
    row = next(i for i in e["items"] if i["type"].startswith("EC2"))
    assert "default rate" in row["note"]
    assert row["monthly"] == round(load_prices()["ec2_instance_hourly"]["_default"] * 730, 2)


def test_idle_elastic_ip_flagged():
    e = estimate(g({"_type": "ElasticIp", "_id": "eip-1", "Region": "us-east-1",
                    "PublicIp": "1.2.3.4", "Associated": False}))
    assert e["idle_elastic_ips"] == 1
    assert "idle" in e["items"][0]["note"]


def test_nat_and_multi_az_rds():
    rds = {"_type": "RdsInstance", "_id": "db-1", "Region": "us-east-1", "DBInstanceIdentifier": "d",
           "DBInstanceClass": "db.t3.small", "AllocatedStorage": 100, "StorageType": "gp2",
           "MultiAZ": True, "DBInstanceStatus": "available"}
    nat = {"_type": "NatGateway", "_id": "nat-1", "Region": "us-east-1", "State": "available"}
    e = estimate(g(rds, nat))
    rds_row = next(i for i in e["items"] if i["type"].startswith("RDS"))
    single = load_prices()["rds_instance_hourly"]["db.t3.small"] * 730 + 100 * load_prices()["rds_storage_gb_month"]["gp2"]
    assert rds_row["monthly"] == round(single * 2, 2)  # Multi-AZ doubles it
    assert "Multi-AZ" in rds_row["type"]
    assert any(i["type"] == "NAT gateway" for i in e["items"])


def test_total_and_sorting():
    e = estimate(g(ec2("t3.micro"), {"_type": "NatGateway", "_id": "nat-1", "Region": "us-east-1",
                                     "State": "available"}))
    assert e["items"][0]["type"] == "NAT gateway"  # most expensive first
    assert e["monthly_total"] == round(sum(i["monthly"] for i in e["items"]), 2)
    assert e["estimated"] is True and "list prices" in e["basis"]


def test_estimate_is_in_analysis():
    from cleave.paths.analysis import analyze
    a = analyze(g(ec2()))
    assert "cost" in a and a["cost"]["monthly_total"] > 0


# ---- Cost Explorer (opt-in, parsed from a canned response) ------------------------------

CE_RESPONSE = {"ResultsByTime": [{"Groups": [
    {"Keys": ["Amazon Relational Database Service"], "Metrics": {"UnblendedCost": {"Amount": "12.3400", "Unit": "USD"}}},
    {"Keys": ["EC2 - Other"], "Metrics": {"UnblendedCost": {"Amount": "3.1000", "Unit": "USD"}}},
    {"Keys": ["AWS Key Management Service"], "Metrics": {"UnblendedCost": {"Amount": "0.0000", "Unit": "USD"}}},
]}]}


def test_parse_month_to_date_drops_zeroes_and_sorts():
    out = parse_mtd(CE_RESPONSE, dt.date(2026, 10, 2))
    assert out["month_to_date"] == 15.44
    assert [s["service"] for s in out["by_service"]] == [
        "Amazon Relational Database Service", "EC2 - Other"]  # zero-cost KMS dropped, sorted
    assert out["currency"] == "USD" and out["period"]["start"] == "2026-10-01"


def test_cost_explorer_endpoint_is_off_by_default(monkeypatch):
    monkeypatch.setattr(settings, "cleave_cost_explorer", False)
    monkeypatch.setattr(settings, "cleave_api_token", "")
    r = TestClient(app).post("/cost/actual")
    assert r.status_code == 403 and "off" in r.json()["detail"].lower()


def test_cost_explorer_endpoint_runs_when_enabled(monkeypatch):
    monkeypatch.setattr(settings, "cleave_cost_explorer", True)
    monkeypatch.setattr(settings, "cleave_api_token", "")
    from cleave.api import service
    monkeypatch.setattr(service, "actual_spend_now", lambda: {"month_to_date": 15.44, "by_service": []})
    r = TestClient(app).post("/cost/actual")
    assert r.status_code == 200 and r.json()["month_to_date"] == 15.44
