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


# ---- stage 3: permissions boundaries and SCPs ------------------------------------------

def policy(name, *statements):
    return {"_type": "IamPolicy", "_id": f"{A}policy/{name}", "PolicyName": name,
            "Document": {"Statement": list(statements)}}


S3_ONLY = policy("s3-only", allow("s3:*"))


def bounded(rec, boundary):
    return {**rec, "PermissionsBoundary": boundary["_id"]}


def org(levels=None, account="1", management="999", in_org=True):
    return {"_type": "Organization", "_id": "account:organization", "InOrganization": in_org,
            "OrgId": "o-test", "Account": account, "ManagementAccountId": management,
            "ScpEnabled": True, "ScpLevels": levels}


def test_boundary_caps_an_attach_policy_escalation():
    """v1 ignored boundaries: AttachUserPolicy under an S3-only boundary was a path."""
    dev = bounded(user("dev", allow("iam:AttachUserPolicy")), S3_ONLY)
    assert find_paths(graph_from_records([dev, S3_ONLY, ADMIN])) == []
    # positive control: a boundary that covers IAM leaves the escalation intact
    iam_ok = policy("iam-ok", allow("iam:*"), allow("s3:*"))
    dev2 = bounded(user("dev", allow("iam:AttachUserPolicy")), iam_ok)
    assert len(find_paths(graph_from_records([dev2, iam_ok, ADMIN]))) == 1


def test_bounded_administrator_is_not_baseline_admin():
    """AdministratorAccess under an S3-only boundary is not full admin: it is a source
    (a credential worth assessing), and it has no route to Admin."""
    from cleave.paths.endpoints import find_sources, holds_full_admin
    boss = bounded(admin_user("boss"), S3_ONLY)
    g = graph_from_records([boss, S3_ONLY, ADMIN])
    assert not holds_full_admin(g, boss["_id"])
    assert boss["_id"] in {s.uid for s in find_sources(g)}
    assert find_paths(g) == []


def test_removable_boundary_is_no_guardrail():
    """A principal that may delete its own boundary is one API call from uncapped."""
    cap = policy("cap", allow("s3:*"), allow("iam:DeleteUserPermissionsBoundary"))
    dev = bounded(user("dev", allow(["iam:AttachUserPolicy",
                                     "iam:DeleteUserPermissionsBoundary"])), cap)
    assert len(find_paths(graph_from_records([dev, cap, ADMIN]))) == 1


def test_unreadable_boundary_keeps_the_path_but_only_possible():
    dev = {**user("dev", allow("iam:AttachUserPolicy")),
           "PermissionsBoundary": f"{A}policy/not-collected"}
    paths = find_paths(graph_from_records([dev, ADMIN]))
    assert len(paths) == 1 and paths[0].confidence == "Possible"


def test_boundary_caps_data_access():
    bucket = {"_type": "S3Bucket", "_id": "arn:aws:s3:::payroll", "Name": "payroll",
              "Tags": {"environment": "production"}, "PublicAccessBlock": None, "Acl": []}
    ec2_only = policy("ec2-only", allow("ec2:*"))
    reader = bounded(user("reader", allow("s3:GetObject")), ec2_only)
    assert find_paths(graph_from_records([reader, ec2_only, bucket])) == []
    plain = user("reader", allow("s3:GetObject"))
    assert len(find_paths(graph_from_records([plain, bucket]))) == 1


def test_scp_deny_blocks_escalation_in_a_member_account():
    dev = user("dev", allow("iam:AttachUserPolicy"))
    deny_iam = {"Statement": [allow("*"), {"Effect": "Deny", "Action": "iam:*", "Resource": "*"}]}
    assert find_paths(graph_from_records([dev, ADMIN, org([[deny_iam]])])) == []
    # controls: not in an organization, or the management account itself
    assert len(find_paths(graph_from_records([dev, ADMIN, org(in_org=False)]))) == 1
    assert len(find_paths(graph_from_records(
        [dev, ADMIN, org([[deny_iam]], account="999")]))) == 1


def test_unreadable_scps_are_a_scan_caveat_not_a_downgrade():
    from cleave.paths.analysis import analyze
    dev = user("dev", allow("iam:AttachUserPolicy"))
    g = graph_from_records([dev, ADMIN, org(levels=None)])
    result = analyze(g)
    assert len(result["paths"]) == 1 and result["paths"][0]["confidence"] == "Certain"
    assert result["summary"]["scp_status"] == "unreadable"


# ---- stage 3: the Organizations collector (fake client, no AWS) ------------------------

class _FakeOrg:
    """Just enough of the organizations client for read_organization()."""
    def __init__(self, member_denied=False, not_in_org=False, mgmt="999"):
        self.member_denied, self.not_in_org, self.mgmt = member_denied, not_in_org, mgmt

    def _deny(self, code="AccessDeniedException"):
        from botocore.exceptions import ClientError
        raise ClientError({"Error": {"Code": code, "Message": "x"}}, "op")

    def describe_organization(self):
        if self.not_in_org:
            self._deny("AWSOrganizationsNotInUseException")
        return {"Organization": {"Id": "o-1", "MasterAccountId": self.mgmt, "FeatureSet": "ALL"}}

    def list_roots(self):
        if self.member_denied:
            self._deny()
        return {"Roots": [{"Id": "r-1", "PolicyTypes": [
            {"Type": "SERVICE_CONTROL_POLICY", "Status": "ENABLED"}]}]}

    def list_parents(self, ChildId):
        return {"Parents": [{"Id": "ou-1", "Type": "ORGANIZATIONAL_UNIT"}]} if ChildId == "1" \
            else {"Parents": [{"Id": "r-1", "Type": "ROOT"}]}

    def get_paginator(self, name):
        org = self

        class P:
            def paginate(self, TargetId, Filter):
                yield {"Policies": [{"Id": f"p-{TargetId}"}]}
        return P()

    def describe_policy(self, PolicyId):
        import json
        return {"Policy": {"Content": json.dumps({"Statement": [
            {"Effect": "Allow", "Action": "*", "Resource": "*", "Sid": PolicyId}]})}}


def test_org_collector_reads_the_scp_hierarchy_root_first():
    from cleave.collectors.organizations import read_organization
    rec = read_organization(_FakeOrg(), "1")
    assert rec["InOrganization"] and rec["OrgId"] == "o-1" and rec["ScpEnabled"]
    sids = [lvl[0]["Statement"][0]["Sid"] for lvl in rec["ScpLevels"]]
    assert sids == ["p-r-1", "p-ou-1", "p-1"]


def test_org_collector_member_account_cannot_read_scps():
    from cleave.collectors.organizations import read_organization
    from cleave.iam.guardrails import scp_status
    rec = read_organization(_FakeOrg(member_denied=True), "1")
    assert rec["InOrganization"] and rec["ScpLevels"] is None
    assert scp_status(rec) == "unreadable"


def test_org_collector_standalone_account():
    from cleave.collectors.organizations import read_organization
    from cleave.iam.guardrails import scp_status
    rec = read_organization(_FakeOrg(not_in_org=True), "1")
    assert rec["InOrganization"] is False
    assert scp_status(rec) == "not_in_organization"
