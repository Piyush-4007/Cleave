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


# ---- stage 2: precise takeover edges ---------------------------------------------------
# v1 treated CreateAccessKey / Create|UpdateLoginProfile / AddUserToGroup /
# UpdateAssumeRolePolicy as admin-equivalent on their own (a GRANTS_ADMIN edge). They are
# not: each makes you a SPECIFIC principal, which is admin only if that principal is.

def admin_user(name, keys=0):
    return {"_type": "IamUser", "_id": f"{A}user/{name}", "UserName": name,
            "AttachedPolicies": [ADMIN["_id"]], "Groups": [], "InlinePolicies": {},
            "AccessKeys": [{"AccessKeyId": f"AK{i}", "Status": "Active"} for i in range(keys)]}


def plain_user(name):
    return {"_type": "IamUser", "_id": f"{A}user/{name}", "UserName": name,
            "AttachedPolicies": [], "Groups": [], "InlinePolicies": {}, "AccessKeys": []}


def cred_report(*rows):
    return {"_type": "IamCredentialReport", "_id": "account:credential-report",
            "Rows": [{"user": u, "arn": f"{A}user/{u}", "password_enabled": pw,
                      "mfa_active": mfa} for u, pw, mfa in rows]}


ADMINS_GROUP = {"_type": "IamGroup", "_id": f"{A}group/admins", "GroupName": "admins",
                "AttachedPolicies": [ADMIN["_id"]], "InlinePolicies": {}}


def rel_conf(g, a, b, rel):
    if not g.has_edge(a, b):
        return None
    for c in g[a][b]["candidates"]:
        if c["rel"] == rel:
            return c["confidence"]
    return None


def test_create_access_key_alone_is_not_admin():
    """v1: GRANTS_ADMIN on the policy -> a Certain path to admin with nobody to become."""
    dev = user("dev", allow("iam:CreateAccessKey"))
    g = graph_from_records([dev, plain_user("intern"), ADMIN])
    assert "GRANTS_ADMIN" not in rels_between(g, f"{dev['_id']}#inline/p", "admin")
    assert find_paths(g) == []


def test_create_access_key_on_an_admin_user_is_a_path():
    dev, boss = user("dev", allow("iam:CreateAccessKey")), admin_user("boss")
    g = graph_from_records([dev, boss, ADMIN])
    assert rel_conf(g, dev["_id"], boss["_id"], "CAN_TAKE_OVER") == "Certain"
    paths = find_paths(g)
    assert len(paths) == 1 and paths[0].nodes[:2] == [dev["_id"], boss["_id"]]


def test_two_existing_keys_block_create_access_key():
    """AWS allows two access keys per user; a third CreateAccessKey fails."""
    dev, boss = user("dev", allow("iam:CreateAccessKey")), admin_user("boss", keys=2)
    g = graph_from_records([dev, boss, ADMIN])
    assert rel_conf(g, dev["_id"], boss["_id"], "CAN_TAKE_OVER") is None
    # ... unless the attacker can delete one first
    dev2 = user("dev", allow(["iam:CreateAccessKey", "iam:DeleteAccessKey"]))
    g2 = graph_from_records([dev2, boss, ADMIN])
    assert rel_conf(g2, dev2["_id"], boss["_id"], "CAN_TAKE_OVER") == "Certain"


def test_self_service_key_policy_is_not_takeover():
    dev = user("dev", allow("iam:CreateAccessKey", f"{A}user/${{aws:username}}"))
    g = graph_from_records([dev, admin_user("boss"), ADMIN])
    assert find_paths(g) == []


def test_login_profile_takeover_follows_the_credential_report():
    dev, boss = user("dev", allow("iam:UpdateLoginProfile")), admin_user("boss")
    # boss has a console password and no MFA: resetting it is a working takeover
    g = graph_from_records([dev, boss, ADMIN, cred_report(("boss", "true", "false"))])
    assert rel_conf(g, dev["_id"], boss["_id"], "CAN_TAKE_OVER") == "Certain"
    # boss has MFA: a new password alone does not get you in
    g = graph_from_records([dev, boss, ADMIN, cred_report(("boss", "true", "true"))])
    assert rel_conf(g, dev["_id"], boss["_id"], "CAN_TAKE_OVER") is None
    # boss has no password: UpdateLoginProfile fails (CreateLoginProfile would be needed)
    g = graph_from_records([dev, boss, ADMIN, cred_report(("boss", "false", "false"))])
    assert rel_conf(g, dev["_id"], boss["_id"], "CAN_TAKE_OVER") is None
    # no credential report: the call may or may not work
    g = graph_from_records([dev, boss, ADMIN])
    assert rel_conf(g, dev["_id"], boss["_id"], "CAN_TAKE_OVER") == "Possible"


def test_add_user_to_group_joins_that_group():
    dev = user("dev", allow("iam:AddUserToGroup", ADMINS_GROUP["_id"]))
    g = graph_from_records([dev, ADMINS_GROUP, ADMIN])
    assert rel_conf(g, dev["_id"], ADMINS_GROUP["_id"], "CAN_JOIN_GROUP") == "Certain"
    assert len(find_paths(g)) == 1


def test_a_role_cannot_add_itself_to_a_group():
    role = {"_type": "IamRole", "_id": f"{A}role/ops", "RoleName": "ops",
            "AttachedPolicies": [], "InlinePolicies": {"p": {"Statement": [
                allow("iam:AddUserToGroup")]}},
            "TrustPolicy": {"Statement": [{"Effect": "Allow", "Action": "sts:AssumeRole",
                                           "Principal": {"AWS": f"{A}user/x"}}]}}
    g = graph_from_records([role, ADMINS_GROUP, ADMIN])
    assert rel_conf(g, role["_id"], ADMINS_GROUP["_id"], "CAN_JOIN_GROUP") is None


def test_update_assume_role_policy_rewrites_trust_into_admin_role():
    ec2_admin = admin_role("mighty", {"Service": "ec2.amazonaws.com"})
    dev = user("dev", allow("iam:UpdateAssumeRolePolicy", ec2_admin["_id"]))
    g = graph_from_records([dev, ec2_admin, ADMIN])
    assert rel_conf(g, dev["_id"], ec2_admin["_id"], "CAN_REWRITE_TRUST") == "Certain"
    assert len(find_paths(g)) == 1


def test_service_linked_role_trust_cannot_be_rewritten():
    slr = admin_role("aws-service-role/x.amazonaws.com/AWSServiceRoleForX",
                     {"Service": "x.amazonaws.com"})
    dev = user("dev", allow("iam:UpdateAssumeRolePolicy"))
    g = graph_from_records([dev, slr, ADMIN])
    assert rel_conf(g, dev["_id"], slr["_id"], "CAN_REWRITE_TRUST") is None


def test_explicit_deny_on_assume_role_blocks_trust_rewrite():
    ec2_admin = admin_role("mighty", {"Service": "ec2.amazonaws.com"})
    dev = user("dev", allow("iam:UpdateAssumeRolePolicy"),
               {"Effect": "Deny", "Action": "sts:AssumeRole", "Resource": "*"})
    g = graph_from_records([dev, ec2_admin, ADMIN])
    assert rel_conf(g, dev["_id"], ec2_admin["_id"], "CAN_REWRITE_TRUST") is None


def test_full_admin_identities_get_no_takeover_edges():
    """An admin can take over anyone, but it has already won: such edges add nothing to
    any path (search stops at the first admin) and would only inflate edge counts."""
    boss = admin_user("boss")
    g = graph_from_records([boss, plain_user("intern"), ADMIN])
    assert not rels_between(g, boss["_id"], f"{A}user/intern")
