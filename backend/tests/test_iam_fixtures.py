"""Runs every fixture in iam_fixtures/ through the evaluator. This suite is the ONLY
defence against a silently-broken IAM evaluator -- grow it as v1/v2 evolve (handbook).

A fixture declares one or more expectations:
  `query` + `expect`        -> is_allowed(policies, action, resource, ...)
                               optional `resource_policy` (doc) and `query.principal`
                               (caller ARN) bring in the resource-based side;
                               optional `query.context` adds request-context keys
                               (e.g. iam:PassedToService) on top of the derived ones
  `expect_grants_admin`     -> grants_admin(policies[0])      (is this policy a route to admin?)
  `expect_full_admin`       -> is_full_admin(policies[0])     (is it literally `*:*`?)

The last two matter from Phase 4 onward: `grants_admin` draws the GRANTS_ADMIN edge that
every path ends on, and `is_full_admin` decides who is excluded as a path source.
"""
import json
import pathlib
import pytest
from cleave.iam.evaluator import is_allowed, grants_admin, is_full_admin, Decision, Confidence

FIX_DIR = pathlib.Path(__file__).parent / "iam_fixtures"
FIXTURES = sorted(FIX_DIR.glob("*.json"))


@pytest.mark.parametrize("path", FIXTURES, ids=[p.stem for p in FIXTURES])
def test_fixture(path):
    fx = json.loads(path.read_text())
    checked = False

    if "query" in fx:
        q, exp = fx["query"], fx["expect"]
        res = is_allowed(fx["policies"], q["action"], q["resource"],
                         resource_policy=fx.get("resource_policy"),
                         principal=q.get("principal"), context=q.get("context"))
        assert res.decision.value == exp["decision"], f"{fx['name']}: {res.reason}"
        assert res.confidence.value == exp["confidence"], f"{fx['name']}: {res.reason}"
        checked = True

    if "expect_grants_admin" in fx:
        exp = fx["expect_grants_admin"]
        res = grants_admin(fx["policies"][0])
        assert res.decision.value == exp["decision"], f"{fx['name']}: {res.reason}"
        assert res.confidence.value == exp["confidence"], f"{fx['name']}: {res.reason}"
        checked = True

    if "expect_full_admin" in fx:
        assert is_full_admin(fx["policies"][0]) is fx["expect_full_admin"], fx["name"]
        checked = True

    assert checked, f"{path.name} declares no expectation"


def test_have_enough_fixtures():
    # handbook: ~20 fixtures by end of Phase 3. Fail if the suite ever shrinks.
    assert len(FIXTURES) >= 58


def test_decision_and_confidence_are_the_only_vocabulary():
    """Guard the three-bucket contract (Certain | Possible | Denied) the graph relies on."""
    assert {d.value for d in Decision} == {"ALLOW", "DENY"}
    assert {c.value for c in Confidence} == {"CERTAIN", "POSSIBLE"}
