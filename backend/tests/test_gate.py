"""Phase 9 — the merge gate: Terraform plan adapter + path diff.

The adapter (gate/plan.py) must emit the SAME records the live collectors do, so the engine
runs unchanged on a proposed change. These tests build small `terraform show -json` plans and
check both that the adapter produces the right records and that the gate reports exactly the
paths a PR would introduce.
"""
import json

from cleave.gate.plan import records_from_plan

ACCT = "111122223333"


def change(rtype, name, after, actions=("create",)):
    return {"address": f"{rtype}.{name}", "mode": "managed", "type": rtype, "name": name,
            "change": {"actions": list(actions), "before": None, "after": after}}


def plan(*changes):
    return {"format_version": "1.2", "resource_changes": list(changes)}


ADMIN_DOC = json.dumps({"Version": "2012-10-17",
                        "Statement": [{"Effect": "Allow", "Action": "iam:AttachUserPolicy",
                                       "Resource": "*"}]})


def _by_type(records):
    out = {}
    for r in records:
        out.setdefault(r["_type"], []).append(r)
    return out


def test_adapter_maps_role_with_inline_policy():
    p = plan(
        change("aws_iam_role", "app", {
            "name": "app-role",
            "assume_role_policy": json.dumps({"Statement": [{"Effect": "Allow",
                "Principal": {"Service": "lambda.amazonaws.com"}, "Action": "sts:AssumeRole"}]})}),
        change("aws_iam_role_policy", "app_inline", {
            "name": "inline", "role": "app-role", "policy": ADMIN_DOC}),
    )
    records, deleted = records_from_plan(p, ACCT)
    by = _by_type(records)
    assert not deleted and len(by["IamRole"]) == 1
    role = by["IamRole"][0]
    assert role["_id"] == f"arn:aws:iam::{ACCT}:role/app-role"
    assert "inline" in role["InlinePolicies"]
    assert role["InlinePolicies"]["inline"]["Statement"][0]["Action"] == "iam:AttachUserPolicy"


def test_adapter_maps_managed_policy_attachment():
    p = plan(
        change("aws_iam_user", "dev", {"name": "dev"}),
        change("aws_iam_policy", "admin", {"name": "admin-pol", "policy": ADMIN_DOC}),
        change("aws_iam_user_policy_attachment", "a", {
            "user": "dev", "policy_arn": f"arn:aws:iam::{ACCT}:policy/admin-pol"}),
    )
    records, _ = records_from_plan(p, ACCT)
    user = _by_type(records)["IamUser"][0]
    assert f"arn:aws:iam::{ACCT}:policy/admin-pol" in user["AttachedPolicies"]


def test_adapter_maps_security_group_ingress():
    p = plan(change("aws_security_group", "web", {
        "id": "sg-new", "name": "web",
        "ingress": [{"protocol": "tcp", "from_port": 22, "to_port": 22,
                     "cidr_blocks": ["0.0.0.0/0"]}]}))
    records, _ = records_from_plan(p, ACCT)
    sg = _by_type(records)["SecurityGroup"][0]
    assert sg["IngressRules"][0]["IpRanges"][0]["CidrIp"] == "0.0.0.0/0"


def test_adapter_records_deletes():
    p = plan({"address": "aws_iam_policy.old", "mode": "managed", "type": "aws_iam_policy",
              "name": "old", "change": {"actions": ["delete"],
              "before": {"arn": f"arn:aws:iam::{ACCT}:policy/old"}, "after": None}})
    records, deleted = records_from_plan(p, ACCT)
    assert records == [] and f"arn:aws:iam::{ACCT}:policy/old" in deleted


# ---- the gate: paths a PR would introduce ----------------------------------------------

from cleave.gate.diff import gate

A = f"arn:aws:iam::{ACCT}:"
ADMIN_MANAGED = {"_type": "IamPolicy", "_id": "arn:aws:iam::aws:policy/AdministratorAccess",
                 "PolicyName": "AdministratorAccess", "ManagedBy": "AWS",
                 "Document": {"Statement": [{"Effect": "Allow", "Action": "*", "Resource": "*"}]}}


def live_account():
    # a benign live account: one low-priv user, the AWS admin policy exists but is attached
    # to nobody reachable.
    return [
        {"_type": "IamUser", "_id": f"{A}user/dev", "UserName": "dev", "AttachedPolicies": [],
         "Groups": [], "InlinePolicies": {"ro": {"Statement": [
             {"Effect": "Allow", "Action": "s3:GetObject", "Resource": "*"}]}}, "AccessKeys": []},
        ADMIN_MANAGED,
    ]


def test_gate_blocks_a_pr_that_introduces_a_path():
    # PR gives the existing live user an escalation primitive (iam:CreatePolicyVersion on *)
    # via a new inline policy -> a new route to admin that did not exist before.
    # (Attaching *full* AdministratorAccess would make the user a baseline admin, which Cleave
    # correctly does NOT count as an escalation path — the primitive is the real finding.)
    p = plan(change("aws_iam_user_policy", "grant", {
        "name": "danger", "user": "dev", "policy": json.dumps({"Statement": [
            {"Effect": "Allow", "Action": "iam:CreatePolicyVersion", "Resource": "*"}]})}))
    r = gate(live_account(), p, ACCT)
    assert r["blocked"] and r["introduced"] == 1
    assert r["paths_before"] == 0 and r["paths_after"] == 1
    assert "dev" in r["new_paths_narrated"][0]


def test_gate_passes_a_benign_pr():
    # PR creates an unused read-only policy attached to nobody -> no new path
    p = plan(
        change("aws_iam_policy", "ro", {"name": "extra-ro", "policy": json.dumps(
            {"Statement": [{"Effect": "Allow", "Action": "s3:ListBucket", "Resource": "*"}]})}),
    )
    r = gate(live_account(), p, ACCT)
    assert not r["blocked"] and r["introduced"] == 0


def test_gate_credits_only_new_paths_not_preexisting():
    # live account ALREADY has a path (dev holds an admin-equivalent inline policy)
    live = [
        {"_type": "IamUser", "_id": f"{A}user/dev", "UserName": "dev", "AttachedPolicies": [],
         "Groups": [], "AccessKeys": [], "InlinePolicies": {"p": {"Statement": [
             {"Effect": "Allow", "Action": "iam:AttachUserPolicy", "Resource": "*"}]}}},
    ]
    # PR adds a SECOND, unrelated over-broad policy -> one NEW path, pre-existing one not recounted
    p = plan(
        change("aws_iam_user", "ops", {"name": "ops"}),
        change("aws_iam_user_policy", "ops_inline", {"name": "p", "user": "ops",
            "policy": json.dumps({"Statement": [{"Effect": "Allow",
                "Action": "iam:CreatePolicyVersion", "Resource": "*"}]})}),
    )
    r = gate(live, p, ACCT)
    assert r["introduced"] == 1 and r["paths_before"] == 1 and r["paths_after"] == 2


# ---- the CLI exit code (CI uses it) -----------------------------------------------------

def test_cli_exits_nonzero_when_blocked(tmp_path):
    from cleave.gate.run import main
    p = plan(change("aws_iam_user", "dev", {"name": "dev"}),
             change("aws_iam_user_policy", "d", {"name": "danger", "user": "dev",
                "policy": json.dumps({"Statement": [{"Effect": "Allow",
                    "Action": "iam:CreatePolicyVersion", "Resource": "*"}]})}))
    pf = tmp_path / "plan.json"
    pf.write_text(json.dumps(p), encoding="utf-8")
    assert main(["--plan", str(pf), "--account", ACCT]) == 1          # blocked
    benign = plan(change("aws_iam_policy", "ro", {"name": "ro", "policy": json.dumps(
        {"Statement": [{"Effect": "Allow", "Action": "s3:ListBucket", "Resource": "*"}]})}))
    bf = tmp_path / "benign.json"
    bf.write_text(json.dumps(benign), encoding="utf-8")
    assert main(["--plan", str(bf), "--account", ACCT]) == 0          # clean
