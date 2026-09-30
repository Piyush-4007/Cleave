"""False positives found in the 5-scenario CloudGoat demo (30 Sep), pinned as tests.

1. CAN_LAUNCH_AS ignored the target role's trust policy. A role can only be carried by a
   compute service it trusts: kerrigan (EC2, no Lambda) was credited with launching as
   the Lambda-only cg-debug-role, and lambdaManager (Lambda, no EC2) with the EC2-only
   cg-ec2-mighty-role. Neither is possible in AWS.
2. Every non-admin role was an ASSUMED_COMPROMISE source, including AWS service-linked
   roles and service roles no workload runs as (aws-elasticbeanstalk-service-role,
   AWSServiceRoleForAutoScaling). Nobody can obtain their credentials, so a path "from"
   them is not a finding.

Each fix has a positive control so it cannot quietly delete a true path.
"""
from cleave.paths.endpoints import find_sources
from cleave.paths.graphview import graph_from_records, rels_between
from cleave.paths.search import find_paths

A = "arn:aws:iam::1:"
ADMIN = {
    "_type": "IamPolicy", "_id": "arn:aws:iam::aws:policy/AdministratorAccess",
    "PolicyName": "AdministratorAccess", "ManagedBy": "AWS",
    "Document": {"Statement": [{"Effect": "Allow", "Action": "*", "Resource": "*"}]},
}


def user(name, *actions):
    return {"_type": "IamUser", "_id": f"{A}user/{name}", "UserName": name,
            "AttachedPolicies": [], "Groups": [],
            "InlinePolicies": {"p": {"Statement": [
                {"Effect": "Allow", "Action": list(actions), "Resource": "*"}]}}}


def trust(principal):
    return {"Statement": [{"Effect": "Allow", "Principal": principal,
                           "Action": "sts:AssumeRole"}]}


def admin_role(name, principal, path="/"):
    return {"_type": "IamRole", "_id": f"{A}role{path}{name}", "RoleName": name,
            "AttachedPolicies": [ADMIN["_id"]], "InlinePolicies": {},
            "TrustPolicy": trust(principal)}


def profile(name, role_id):
    return {"_type": "IamInstanceProfile", "_id": f"{A}instance-profile/{name}",
            "InstanceProfileName": name, "Roles": [role_id]}


LAMBDA_ROLE = admin_role("debug", {"Service": "lambda.amazonaws.com"})
EC2_ROLE = admin_role("mighty", {"Service": "ec2.amazonaws.com"})


# ---- 1. CAN_LAUNCH_AS must match the role's trust ------------------------------------

def test_ec2_only_principal_cannot_launch_as_a_lambda_only_role():
    """kerrigan -> cg-debug-role, the cross-scenario false positive."""
    g = graph_from_records([user("kerrigan", "ec2:RunInstances", "iam:PassRole",
                                 "iam:AddRoleToInstanceProfile"), LAMBDA_ROLE, ADMIN])
    assert "CAN_LAUNCH_AS" not in rels_between(g, f"{A}user/kerrigan", LAMBDA_ROLE["_id"])
    assert find_paths(g) == []


def test_lambda_only_principal_cannot_launch_as_an_ec2_only_role():
    """lambdaManager -> cg-ec2-mighty-role, even though the role sits in a profile."""
    g = graph_from_records([user("lm", "lambda:CreateFunction", "iam:PassRole"),
                            EC2_ROLE, profile("p", EC2_ROLE["_id"]), ADMIN])
    assert "CAN_LAUNCH_AS" not in rels_between(g, f"{A}user/lm", EC2_ROLE["_id"])
    assert find_paths(g) == []


def test_lambda_principal_launches_as_a_lambda_role():
    """Positive control: lambda_privesc's real route (chris -> lambdaManager -> debug)."""
    g = graph_from_records([user("lm", "lambda:CreateFunction", "iam:PassRole"),
                            LAMBDA_ROLE, ADMIN])
    assert "CAN_LAUNCH_AS" in rels_between(g, f"{A}user/lm", LAMBDA_ROLE["_id"])
    assert len(find_paths(g)) == 1


def test_ec2_needs_an_instance_profile_carrying_the_role():
    """EC2 carries a role only through an instance profile. With no profile holding it and
    no way to put it in one, RunInstances + PassRole reaches nothing."""
    g = graph_from_records([user("u", "ec2:RunInstances", "iam:PassRole"), EC2_ROLE, ADMIN])
    assert "CAN_LAUNCH_AS" not in rels_between(g, f"{A}user/u", EC2_ROLE["_id"])


def test_ec2_route_via_an_existing_profile():
    g = graph_from_records([user("u", "ec2:RunInstances", "iam:PassRole"),
                            EC2_ROLE, profile("p", EC2_ROLE["_id"]), ADMIN])
    assert "CAN_LAUNCH_AS" in rels_between(g, f"{A}user/u", EC2_ROLE["_id"])


def test_ec2_route_by_adding_the_role_to_a_profile():
    """Positive control: the Phase 0 attachment walkthrough. The mighty role is in no
    profile, but kerrigan can AddRoleToInstanceProfile into the meek profile."""
    meek = admin_role("meek", {"Service": "ec2.amazonaws.com"})
    meek["AttachedPolicies"] = []
    g = graph_from_records([user("kerrigan", "ec2:RunInstances", "iam:PassRole",
                                 "iam:AddRoleToInstanceProfile"),
                            EC2_ROLE, meek, profile("meek-profile", meek["_id"]), ADMIN])
    assert "CAN_LAUNCH_AS" in rels_between(g, f"{A}user/kerrigan", EC2_ROLE["_id"])


def test_launch_reason_names_the_service_actually_used():
    g = graph_from_records([user("both", "ec2:RunInstances", "lambda:CreateFunction",
                                 "iam:PassRole"), LAMBDA_ROLE, ADMIN])
    cand = next(c for c in g[f"{A}user/both"][LAMBDA_ROLE["_id"]]["candidates"]
                if c["rel"] == "CAN_LAUNCH_AS")
    assert "lambda:CreateFunction" in cand["reason"] and "RunInstances" not in cand["reason"]


# ---- 2. which roles can be a compromised starting point -------------------------------

def _sources(records):
    return {s.uid for s in find_sources(graph_from_records(records))}


def _escalator_role(name, principal, path="/"):
    """A non-admin role holding an escalation primitive: would be a source if eligible."""
    return {"_type": "IamRole", "_id": f"{A}role{path}{name}", "RoleName": name,
            "AttachedPolicies": [], "TrustPolicy": trust(principal),
            "InlinePolicies": {"p": {"Statement": [
                {"Effect": "Allow", "Action": "iam:SetDefaultPolicyVersion", "Resource": "*"}]}}}


def test_service_linked_role_is_never_a_source():
    r = _escalator_role("AWSServiceRoleForAutoScaling",
                        {"Service": "autoscaling.amazonaws.com"},
                        path="/aws-service-role/autoscaling.amazonaws.com/")
    assert r["_id"] not in _sources([r])


def test_service_role_with_no_workload_is_not_a_source():
    r = _escalator_role("aws-elasticbeanstalk-service-role",
                        {"Service": "elasticbeanstalk.amazonaws.com"})
    assert r["_id"] not in _sources([r])


def test_role_a_lambda_runs_as_is_a_source():
    """policy_applier_lambda1: compromise the function, hold its role."""
    r = _escalator_role("applier", {"Service": "lambda.amazonaws.com"})
    fn = {"_type": "LambdaFunction", "_id": "arn:aws:lambda:us-east-1:1:function:f",
          "FunctionName": "f", "Role": r["_id"], "FunctionUrlAuthType": None}
    assert r["_id"] in _sources([r, fn])


def test_role_an_instance_runs_as_is_a_source():
    r = _escalator_role("meek", {"Service": "ec2.amazonaws.com"})
    p = profile("meek-profile", r["_id"])
    inst = {"_type": "Ec2Instance", "_id": "i-1", "InstanceId": "i-1", "State": "running",
            "IamInstanceProfile": p["_id"], "SecurityGroups": []}
    assert r["_id"] in _sources([r, p, inst])


def test_role_a_principal_can_assume_is_a_source():
    r = _escalator_role("lambdaManager", {"AWS": f"{A}user/chris"})
    assert r["_id"] in _sources([r])


def test_users_are_always_sources():
    u = user("raynor", "iam:SetDefaultPolicyVersion")
    assert u["_id"] in _sources([u])


# ---- 3. a path ends at the first identity that is already full admin -------------------

def test_no_path_continues_through_a_full_admin_identity():
    """Found in the same demo: kerrigan -> mighty (holds *:*) -> debug -> Admin was reported
    alongside kerrigan -> mighty -> Admin. Once an attacker holds a full-admin identity they
    have won; the longer route is the same finding counted twice."""
    both = admin_role("mighty", {"Service": "ec2.amazonaws.com"})
    both["InlinePolicies"] = {"extra": {"Statement": [
        {"Effect": "Allow", "Action": ["lambda:CreateFunction", "iam:PassRole"], "Resource": "*"}]}}
    records = [user("kerrigan", "ec2:RunInstances", "iam:PassRole"),
               both, profile("p", both["_id"]), LAMBDA_ROLE, ADMIN]
    found = find_paths(graph_from_records(records))
    assert [[n.split("/")[-1] for n in p.nodes] for p in found] == \
           [["kerrigan", "mighty", "AdministratorAccess", "admin"]]


# ---- 4. UpdateFunctionCode is only as strong as the function's role ---------------------

def test_update_function_code_alone_is_not_admin():
    """Rewriting a function's code gives you THAT function's role -- admin only if the role
    is. The precise form is CAN_WRITE -> function -> EXECUTES_AS -> role (Phase 4 incr. 2);
    the catalogue also calling it admin-equivalent reported lambdaManager-policy as a
    standalone admin grant in the 30 Sep demo."""
    weak = {"_type": "IamRole", "_id": f"{A}role/weak", "RoleName": "weak",
            "AttachedPolicies": [], "InlinePolicies": {},
            "TrustPolicy": trust({"Service": "lambda.amazonaws.com"})}
    fn = {"_type": "LambdaFunction", "_id": "arn:aws:lambda:us-east-1:1:function:f",
          "FunctionName": "f", "Role": weak["_id"], "FunctionUrlAuthType": None}
    g = graph_from_records([user("dev", "lambda:UpdateFunctionCode"), weak, fn])
    assert find_paths(g) == []


def test_update_function_code_on_an_admin_function_still_reaches_admin():
    """Positive control: the precise route survives."""
    fn = {"_type": "LambdaFunction", "_id": "arn:aws:lambda:us-east-1:1:function:f",
          "FunctionName": "f", "Role": LAMBDA_ROLE["_id"], "FunctionUrlAuthType": None}
    found = find_paths(graph_from_records([user("dev", "lambda:UpdateFunctionCode"),
                                           LAMBDA_ROLE, fn, ADMIN]))
    assert [[h.rel for h in p.hops] for p in found] == \
           [["CAN_WRITE", "EXECUTES_AS", "HAS_ATTACHED", "GRANTS_ADMIN"]]
