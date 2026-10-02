"""Phase 7 (IAM evaluator v2) at graph level: each stage's effect on edges and paths.

The iam_fixtures/ suite pins the evaluator's answers one query at a time. These tests pin
what those answers do to the graph, because that is where a v1 false positive actually
became a reported attack path. Every removal has a positive control beside it.
"""
from cleave.paths.graphview import graph_from_records, rels_between
from cleave.paths.search import find_paths

A = "arn:aws:iam::1:"
ADMIN = {
    "_type": "IamPolicy", "_id": "arn:aws:iam::aws:policy/AdministratorAccess",
    "PolicyName": "AdministratorAccess", "ManagedBy": "AWS",
    "Document": {"Statement": [{"Effect": "Allow", "Action": "*", "Resource": "*"}]},
}


def user(name, *statements, groups=()):
    return {"_type": "IamUser", "_id": f"{A}user/{name}", "UserName": name,
            "AttachedPolicies": [], "Groups": list(groups), "AccessKeys": [],
            "InlinePolicies": {"p": {"Statement": list(statements)}}}


def allow(actions, resource="*", condition=None):
    st = {"Effect": "Allow", "Action": actions, "Resource": resource}
    if condition:
        st["Condition"] = condition
    return st


def admin_role(name, trust_principal):
    return {"_type": "IamRole", "_id": f"{A}role/{name}", "RoleName": name,
            "AttachedPolicies": [ADMIN["_id"]], "InlinePolicies": {},
            "TrustPolicy": {"Statement": [{"Effect": "Allow", "Principal": trust_principal,
                                           "Action": "sts:AssumeRole"}]}}


# ---- stage 1: conditions ---------------------------------------------------------------

LAMBDA_ROLE = admin_role("fn-admin", {"Service": "lambda.amazonaws.com"})


def test_passrole_scoped_to_another_service_cannot_launch():
    """PassRole limited to EC2 via iam:PassedToService cannot hand a role to Lambda,
    even with lambda:CreateFunction. v1 drew a POSSIBLE CAN_LAUNCH_AS here."""
    u = user("dev", allow(["lambda:CreateFunction"]),
             allow("iam:PassRole", "*",
                   {"StringEquals": {"iam:PassedToService": "ec2.amazonaws.com"}}))
    g = graph_from_records([u, LAMBDA_ROLE, ADMIN])
    assert "CAN_LAUNCH_AS" not in rels_between(g, u["_id"], LAMBDA_ROLE["_id"])
    assert find_paths(g) == []


def test_passrole_scoped_to_the_right_service_is_certain():
    """Positive control: the same scoping, for the service the role trusts."""
    u = user("dev", allow(["lambda:CreateFunction"]),
             allow("iam:PassRole", "*",
                   {"StringEquals": {"iam:PassedToService": "lambda.amazonaws.com"}}))
    g = graph_from_records([u, LAMBDA_ROLE, ADMIN])
    cands = [c for c in g[u["_id"]][LAMBDA_ROLE["_id"]]["candidates"]
             if c["rel"] == "CAN_LAUNCH_AS"]
    assert cands and cands[0]["confidence"] == "Certain"
    assert len(find_paths(g)) == 1


def test_condition_naming_another_principal_draws_no_edge():
    """A grant gated on aws:PrincipalArn = someone else is not this user's grant."""
    u = user("dev", allow(["lambda:CreateFunction", "iam:PassRole"], "*",
                          {"ArnEquals": {"aws:PrincipalArn": f"{A}user/someone-else"}}))
    g = graph_from_records([u, LAMBDA_ROLE, ADMIN])
    assert not rels_between(g, u["_id"], LAMBDA_ROLE["_id"])
