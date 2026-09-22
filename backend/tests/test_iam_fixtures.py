"""Runs every fixture in iam_fixtures/ through the evaluator. This suite is the ONLY
defence against a silently-broken IAM evaluator — grow it as v1/v2 evolve (handbook)."""
import json
import pathlib
import pytest
from cleave.iam.evaluator import is_allowed, grants_admin, Decision, Confidence

FIX_DIR = pathlib.Path(__file__).parent / "iam_fixtures"
FIXTURES = sorted(FIX_DIR.glob("*.json"))


@pytest.mark.parametrize("path", FIXTURES, ids=[p.stem for p in FIXTURES])
def test_fixture(path):
    fx = json.loads(path.read_text())
    q = fx["query"]
    res = is_allowed(fx["policies"], q["action"], q["resource"])
    exp = fx["expect"]
    assert res.decision.value == exp["decision"], f"{fx['name']}: {res.reason}"
    assert res.confidence.value == exp["confidence"], f"{fx['name']}: {res.reason}"


def test_have_enough_fixtures():
    # handbook: ~20 fixtures by end of Phase 3. Start now, fail if the suite shrinks.
    assert len(FIXTURES) >= 9


# --- grants_admin() spot checks (catalogue coverage) ---
def test_grants_admin_star():
    p = {"Statement": [{"Effect": "Allow", "Action": "*", "Resource": "*"}]}
    assert grants_admin(p).decision is Decision.ALLOW
    assert grants_admin(p).confidence is Confidence.CERTAIN


def test_grants_admin_sneaky_passrole():
    # not *:*, but PassRole on * is admin-equivalent (Phase 0 scenario 2)
    p = {"Statement": [{"Effect": "Allow", "Action": "iam:PassRole", "Resource": "*"}]}
    assert grants_admin(p).decision is Decision.ALLOW


def test_grants_admin_setdefaultpolicyversion():
    # Phase 0 scenario 1's enabling permission
    p = {"Statement": [{"Effect": "Allow", "Action": "iam:SetDefaultPolicyVersion",
                        "Resource": "*"}]}
    assert grants_admin(p).decision is Decision.ALLOW


def test_grants_admin_benign_readonly():
    p = {"Statement": [{"Effect": "Allow", "Action": ["s3:GetObject", "ec2:DescribeInstances"],
                        "Resource": "*"}]}
    assert grants_admin(p).decision is Decision.DENY
