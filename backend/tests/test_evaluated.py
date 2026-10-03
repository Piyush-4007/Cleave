"""Integration test for evaluated-edge derivation (pure, no Neo4j)."""
from cleave.graph.evaluated import compute_evaluated_edges

ROLE = "arn:aws:iam::111:role/mighty"
EC2_TRUST = {"Statement": [{"Effect": "Allow", "Principal": {"Service": "ec2.amazonaws.com"},
                            "Action": "sts:AssumeRole"}]}

def test_passrole_launchas_and_grants_admin():
    records = [
        {"_type": "IamUser", "_id": "arn:aws:iam::111:user/attacker", "UserName": "attacker",
         "AttachedPolicies": [], "Groups": [],
         "InlinePolicies": {"p": {"Statement": [
             {"Effect": "Allow", "Action": "iam:PassRole", "Resource": ROLE},
             {"Effect": "Allow", "Action": "ec2:RunInstances", "Resource": "*"}]}}},
        # EC2 can carry the role: it trusts ec2.amazonaws.com and sits in a profile.
        {"_type": "IamRole", "_id": ROLE, "RoleName": "mighty", "TrustPolicy": EC2_TRUST},
        {"_type": "IamInstanceProfile", "_id": "arn:aws:iam::111:instance-profile/p",
         "InstanceProfileName": "p", "Roles": [ROLE]},
        {"_type": "IamPolicy", "_id": "arn:aws:iam::111:policy/adminpol", "PolicyName": "adminpol",
         "Document": {"Statement": [{"Effect": "Allow", "Action": "*", "Resource": "*"}]}},
    ]
    rels = {(e["frm"].split("/")[-1], e["to"].split("/")[-1], e["rel"])
            for e in compute_evaluated_edges(records)}
    assert ("attacker", "mighty", "CAN_PASS_ROLE") in rels
    assert ("attacker", "mighty", "CAN_LAUNCH_AS") in rels
    assert ("adminpol", "admin", "GRANTS_ADMIN") in rels


def test_launchas_needs_a_role_the_service_can_carry():
    """The pre-30-Sep version of the test above expected CAN_LAUNCH_AS to a role with an
    empty trust policy and no instance profile -- which EC2 cannot actually carry. PassRole
    alone is still recorded as evidence."""
    records = [
        {"_type": "IamUser", "_id": "arn:aws:iam::111:user/attacker", "UserName": "attacker",
         "AttachedPolicies": [], "Groups": [],
         "InlinePolicies": {"p": {"Statement": [
             {"Effect": "Allow", "Action": ["iam:PassRole", "ec2:RunInstances"],
              "Resource": "*"}]}}},
        {"_type": "IamRole", "_id": ROLE, "RoleName": "mighty", "TrustPolicy": {}},
    ]
    rels = {e["rel"] for e in compute_evaluated_edges(records)}
    assert "CAN_PASS_ROLE" in rels and "CAN_LAUNCH_AS" not in rels


def test_createpolicyversion_is_admin_only_with_a_policy_to_version():
    """Phase 10 (PMapper comparison): iam:CreatePolicyVersion / SetDefaultPolicyVersion
    escalate the holder only if they have an attached CUSTOMER-MANAGED policy to rewrite
    into admin. An inline-only holder has nothing to version -> no GRANTS_ADMIN edge; the
    same grant with a customer-managed policy attached -> a (non-full-admin) GRANTS_ADMIN
    edge on the granting document."""
    CPV = {"p": {"Statement": [
        {"Effect": "Allow", "Action": "iam:CreatePolicyVersion", "Resource": "*"}]}}
    inline_only = [
        {"_type": "IamUser", "_id": "arn:aws:iam::111:user/u", "UserName": "u",
         "AttachedPolicies": [], "Groups": [], "InlinePolicies": CPV},
    ]
    assert not any(e["rel"] == "GRANTS_ADMIN"
                   for e in compute_evaluated_edges(inline_only))

    CM = "arn:aws:iam::111:policy/cm"
    with_cm = [
        {"_type": "IamUser", "_id": "arn:aws:iam::111:user/u", "UserName": "u",
         "AttachedPolicies": [CM], "Groups": [], "InlinePolicies": CPV},
        {"_type": "IamPolicy", "_id": CM, "PolicyName": "cm", "ManagedBy": "Customer",
         "Document": {"Statement": [
             {"Effect": "Allow", "Action": "s3:GetObject", "Resource": "*"}]}},
    ]
    admin = [e for e in compute_evaluated_edges(with_cm)
             if e["rel"] == "GRANTS_ADMIN" and e["to"] == "admin"]
    assert admin and all(not e["props"].get("full_admin") for e in admin)

    # an AWS-managed policy is immutable: it does not count as something to version
    aws_mgd = [
        {"_type": "IamUser", "_id": "arn:aws:iam::111:user/u", "UserName": "u",
         "AttachedPolicies": ["arn:aws:iam::aws:policy/ReadOnlyAccess"], "Groups": [],
         "InlinePolicies": CPV},
        {"_type": "IamPolicy", "_id": "arn:aws:iam::aws:policy/ReadOnlyAccess",
         "PolicyName": "ReadOnlyAccess", "ManagedBy": "AWS", "Document": {"Statement": [
             {"Effect": "Allow", "Action": "s3:Get*", "Resource": "*"}]}},
    ]
    assert not any(e["rel"] == "GRANTS_ADMIN" for e in compute_evaluated_edges(aws_mgd))


def test_readonly_user_gets_no_escalation():
    records = [
        {"_type": "IamUser", "_id": "arn:aws:iam::111:user/ro", "UserName": "ro",
         "AttachedPolicies": [], "Groups": [],
         "InlinePolicies": {"p": {"Statement": [
             {"Effect": "Allow", "Action": ["s3:GetObject", "ec2:DescribeInstances"],
              "Resource": "*"}]}}},
        {"_type": "IamRole", "_id": ROLE, "RoleName": "mighty", "TrustPolicy": {}},
    ]
    rels = {e["rel"] for e in compute_evaluated_edges(records)}
    assert "CAN_PASS_ROLE" not in rels and "CAN_LAUNCH_AS" not in rels
