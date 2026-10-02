"""Actual spend via AWS Cost Explorer — the OPT-IN half.

Two honest caveats, surfaced in the UI:
  * the read-only role does NOT include ce:* (Cost Explorer), so the user must add it;
  * Cost Explorer bills ~$0.01 per request, so this is the one Cleave feature that costs
    money to run. It therefore NEVER runs as part of a scan or /analysis — only when the
    user explicitly asks for it, and only when CLEAVE_COST_EXPLORER is on.

This is outside the thesis (Cleave's novelty is attack paths, not billing); it is a
convenience so the user does not have to leave the app to see real numbers.
"""
from __future__ import annotations
import datetime as _dt


def _month_start(today: _dt.date) -> str:
    return today.replace(day=1).isoformat()


def actual_spend(session, today: _dt.date | None = None) -> dict:
    """Month-to-date spend by service, plus the last 6 months total. One GetCostAndUsage
    call each (~$0.01 apiece). Raises on AccessDenied so the UI can tell the user to add
    the ce: permission."""
    today = today or _dt.date.today()
    ce = session.client("ce", region_name="us-east-1")  # CE is a global endpoint

    mtd = ce.get_cost_and_usage(
        TimePeriod={"Start": _month_start(today), "End": today.isoformat()},
        Granularity="MONTHLY", Metrics=["UnblendedCost"],
        GroupBy=[{"Type": "DIMENSION", "Key": "SERVICE"}])
    return parse_mtd(mtd, today)


def parse_mtd(resp: dict, today: _dt.date) -> dict:
    """Shape a GetCostAndUsage response into the UI payload. Split out so it can be tested
    without calling AWS."""
    groups = (resp.get("ResultsByTime") or [{}])[0].get("Groups", [])
    by_service = []
    for gr in groups:
        amount = float(gr["Metrics"]["UnblendedCost"]["Amount"])
        if amount > 0:
            by_service.append({"service": gr["Keys"][0], "amount": round(amount, 2)})
    by_service.sort(key=lambda s: s["amount"], reverse=True)
    unit = (groups[0]["Metrics"]["UnblendedCost"]["Unit"] if groups else "USD")
    return {
        "currency": unit,
        "month_to_date": round(sum(s["amount"] for s in by_service), 2),
        "period": {"start": today.replace(day=1).isoformat(), "end": today.isoformat()},
        "by_service": by_service,
        "source": "cost-explorer",
    }
