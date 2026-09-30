"""Who a scan ran as — the connected-account panel's data.

Parsed from sts:GetCallerIdentity, no extra AWS calls except the (free, read-only)
account alias. `admin_credentials` lets the panel say plainly when the credentials used
are full admin: Cleave still only reads, but a read-only role is the safer habit.
"""
from cleave.identity import caller_identity, principal_uid
from cleave.paths.graphview import graph_from_records

ADMIN = {"_type": "IamPolicy", "_id": "arn:aws:iam::aws:policy/AdministratorAccess",
         "PolicyName": "AdministratorAccess",
         "Document": {"Statement": [{"Effect": "Allow", "Action": "*", "Resource": "*"}]}}


def test_parses_a_user():
    i = caller_identity("arn:aws:iam::111122223333:user/team/cleave-dev")
    assert (i["principal_type"], i["principal_name"]) == ("user", "cleave-dev")


def test_parses_an_assumed_role_with_session():
    i = caller_identity("arn:aws:sts::111122223333:assumed-role/CleaveAudit/cleave-scan")
    assert (i["principal_type"], i["principal_name"], i["session"]) == \
           ("role", "CleaveAudit", "cleave-scan")


def test_parses_root():
    assert caller_identity("arn:aws:iam::111122223333:root")["principal_type"] == "root"


def test_principal_uid_finds_the_role_despite_its_path():
    """An assumed-role ARN drops the role's path; match the role node by name."""
    role = {"_type": "IamRole", "_id": "arn:aws:iam::1:role/service/CleaveAudit",
            "RoleName": "CleaveAudit", "AttachedPolicies": [], "InlinePolicies": {},
            "TrustPolicy": {}}
    g = graph_from_records([role])
    assert principal_uid(g, "arn:aws:sts::1:assumed-role/CleaveAudit/s") == role["_id"]


def test_admin_credentials_flagged():
    u = {"_type": "IamUser", "_id": "arn:aws:iam::1:user/cleave-dev", "UserName": "cleave-dev",
         "AttachedPolicies": [ADMIN["_id"]], "Groups": [], "InlinePolicies": {}}
    g = graph_from_records([u, ADMIN])
    assert caller_identity(u["_id"], g)["admin_credentials"] is True


def test_read_only_role_not_flagged_and_root_is():
    role = {"_type": "IamRole", "_id": "arn:aws:iam::1:role/CleaveAudit",
            "RoleName": "CleaveAudit", "AttachedPolicies": [], "InlinePolicies": {},
            "TrustPolicy": {}}
    g = graph_from_records([role])
    assert caller_identity("arn:aws:sts::1:assumed-role/CleaveAudit/s", g)["admin_credentials"] is False
    assert caller_identity("arn:aws:iam::1:root", g)["admin_credentials"] is True
