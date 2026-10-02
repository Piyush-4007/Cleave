"""Gate corpus (Phase 10) — 30 pull requests to measure the merge gate's accuracy.

15 PRs introduce a new attack path; 15 are **benign but superficially similar** — they touch
IAM, add permissions, or open ports, exactly like the dangerous ones, but reach nothing. The
benign-but-similar half is the whole point: anyone can block every PR that touches IAM; the
test is blocking the 15 that matter while passing the 15 that look identical to a linter.

`corpus()` returns [(label, expected_blocked, plan)]. `evaluate_gate(base_records, corpus,
account)` runs the Phase 9 gate on each and returns detection rate + false-positive rate.
"""
from __future__ import annotations
import json

from ..gate.diff import gate

ACCT = "100000000000"
A = f"arn:aws:iam::{ACCT}:"
ADMIN_ARN = "arn:aws:iam::aws:policy/AdministratorAccess"


def _ch(rtype, name, after, actions=("create",)):
    return {"address": f"{rtype}.{name}", "mode": "managed", "type": rtype, "name": name,
            "change": {"actions": list(actions), "before": None, "after": after}}


def _plan(*changes):
    return {"format_version": "1.2", "resource_changes": list(changes)}


def _doc(*statements):
    return json.dumps({"Version": "2012-10-17", "Statement": list(statements)})


def _allow(actions, resource="*", **extra):
    return {"Effect": "Allow", "Action": actions, "Resource": resource, **extra}


# an admin role the dangerous PRs escalate into (present in the base account)
ADMIN_ROLE_LAMBDA = {
    "_type": "IamRole", "_id": f"{A}role/app-admin", "RoleName": "app-admin",
    "AttachedPolicies": [ADMIN_ARN], "InlinePolicies": {},
    "TrustPolicy": {"Statement": [{"Effect": "Allow",
        "Principal": {"Service": "lambda.amazonaws.com"}, "Action": "sts:AssumeRole"}]}}
BASE_ADMIN_POLICY = {
    "_type": "IamPolicy", "_id": ADMIN_ARN, "PolicyName": "AdministratorAccess",
    "ManagedBy": "AWS", "Document": {"Statement": [_allow("*")]}}


def base_account() -> list[dict]:
    """A benign live account the PRs are gated against: an admin role exists (trusted by a
    service, nobody can reach it yet) plus some read-only noise. No path today."""
    recs = [BASE_ADMIN_POLICY, ADMIN_ROLE_LAMBDA]
    for i in range(8):
        recs.append({"_type": "IamUser", "_id": f"{A}user/reader-{i}", "UserName": f"reader-{i}",
                     "AttachedPolicies": [], "Groups": [], "AccessKeys": [],
                     "InlinePolicies": {"p": {"Statement": [_allow(["s3:GetObject"],
                        "arn:aws:s3:::reports-*/*")]}}})
    return recs


# ---- 15 PRs that INTRODUCE a path ------------------------------------------------------

def _bad_prs():
    prs = []
    # 1-4: a user gains an escalation primitive (several primitives)
    for i, prim in enumerate(["iam:CreatePolicyVersion", "iam:PutUserPolicy",
                              "iam:AttachUserPolicy", "iam:SetDefaultPolicyVersion"]):
        prs.append((f"grant {prim}", _plan(
            _ch("aws_iam_user", f"svc{i}", {"name": f"svc{i}"}),
            _ch("aws_iam_user_policy", f"svc{i}p", {"name": "p", "user": f"svc{i}",
                "policy": _doc(_allow([prim], "*"))}))))
    # 5-6: PassRole + a launch action into the admin role that trusts lambda
    for i in range(2):
        prs.append((f"passrole+launch {i}", _plan(
            _ch("aws_iam_user", f"dep{i}", {"name": f"dep{i}"}),
            _ch("aws_iam_user_policy", f"dep{i}p", {"name": "p", "user": f"dep{i}",
                "policy": _doc(_allow(["iam:PassRole", "lambda:CreateFunction"], "*"))}))))
    # 7-8: a role that trusts the whole account + a user that can assume it
    for i in range(2):
        prs.append((f"assume-chain {i}", _plan(
            _ch("aws_iam_role", f"br{i}", {"name": f"br{i}", "assume_role_policy":
                _doc({"Effect": "Allow", "Principal": {"AWS": f"{A}root"}, "Action": "sts:AssumeRole"})}),
            _ch("aws_iam_role_policy_attachment", f"br{i}a", {"role": f"br{i}", "policy_arn": ADMIN_ARN}),
            _ch("aws_iam_user", f"eng{i}", {"name": f"eng{i}"}),
            _ch("aws_iam_user_policy", f"eng{i}p", {"name": "p", "user": f"eng{i}",
                "policy": _doc(_allow(["sts:AssumeRole"], f"{A}role/br{i}"))}))))
    # 9-10: a GitHub-Actions OIDC role with admin
    for i in range(2):
        prs.append((f"github-oidc admin {i}", _plan(
            _ch("aws_iam_role", f"gha{i}", {"name": f"gha{i}", "assume_role_policy": _doc({
                "Effect": "Allow",
                "Principal": {"Federated": f"{A}oidc-provider/token.actions.githubusercontent.com"},
                "Action": "sts:AssumeRoleWithWebIdentity",
                "Condition": {"StringLike": {"token.actions.githubusercontent.com:sub": "repo:acme/x:*"}}})}),
            _ch("aws_iam_role_policy_attachment", f"gha{i}a", {"role": f"gha{i}", "policy_arn": ADMIN_ARN}))))
    # 11-13: take over an existing admin-adjacent user by minting keys (needs a target admin)
    for i in range(3):
        prs.append((f"createaccesskey+admin {i}", _plan(
            _ch("aws_iam_user", f"boss{i}", {"name": f"boss{i}"}),
            _ch("aws_iam_user_policy_attachment", f"boss{i}a",
                {"user": f"boss{i}", "policy_arn": ADMIN_ARN}),
            _ch("aws_iam_user", f"help{i}", {"name": f"help{i}"}),
            _ch("aws_iam_user_policy", f"help{i}p", {"name": "p", "user": f"help{i}",
                "policy": _doc(_allow(["iam:CreateAccessKey"], f"{A}user/boss{i}"))}))))
    # 14-15: a public bucket holding a credential for an escalating user
    for i in range(2):
        prs.append((f"public-bucket-cred {i}", _plan(
            _ch("aws_s3_bucket", f"pub{i}", {"bucket": f"leak-{i}"}),
            _ch("aws_s3_bucket_policy", f"pub{i}p", {"bucket": f"leak-{i}",
                "policy": _doc({"Effect": "Allow", "Principal": "*", "Action": "s3:GetObject",
                                "Resource": f"arn:aws:s3:::leak-{i}/*"})}),
            _ch("aws_iam_user", f"vic{i}", {"name": f"vic{i}"}),
            _ch("aws_iam_user_policy", f"vic{i}p", {"name": "p", "user": f"vic{i}",
                "policy": _doc(_allow(["iam:AttachUserPolicy"], "*"))}))))
    return prs


# ---- 15 benign-but-similar PRs (touch IAM / ports, reach nothing) ----------------------

def _benign_prs():
    prs = []
    # 1-3: add a scoped read-only policy / user — looks like an IAM change, grants nothing
    for i in range(3):
        prs.append((f"scoped read policy {i}", _plan(
            _ch("aws_iam_policy", f"ro{i}", {"name": f"ro{i}",
                "policy": _doc(_allow(["s3:GetObject", "s3:ListBucket"], "arn:aws:s3:::app-logs-*/*"))}))))
    # 4-5: a new user with benign describe perms
    for i in range(2):
        prs.append((f"describe user {i}", _plan(
            _ch("aws_iam_user", f"obs{i}", {"name": f"obs{i}"}),
            _ch("aws_iam_user_policy", f"obs{i}p", {"name": "p", "user": f"obs{i}",
                "policy": _doc(_allow(["ec2:Describe*", "cloudwatch:GetMetricData"], "*"))}))))
    # 6-7: PassRole WITHOUT any launch action (a permission, not a completed path)
    for i in range(2):
        prs.append((f"passrole-only {i}", _plan(
            _ch("aws_iam_user", f"po{i}", {"name": f"po{i}"}),
            _ch("aws_iam_user_policy", f"po{i}p", {"name": "p", "user": f"po{i}",
                "policy": _doc(_allow(["iam:PassRole"], "*"))}))))
    # 8-9: PassRole + launch into a NON-admin role, with PassRole SCOPED to only that role
    # (so it cannot pass the existing admin role) -> reaches no admin. The subtlety a linter
    # misses: PassRole+CreateFunction is identical in shape to the dangerous PR; only the
    # scoped Resource and the target role's low privilege make it safe.
    for i in range(2):
        prs.append((f"launch into non-admin {i}", _plan(
            _ch("aws_iam_role", f"weak{i}", {"name": f"weak{i}", "assume_role_policy": _doc({
                "Effect": "Allow", "Principal": {"Service": "lambda.amazonaws.com"},
                "Action": "sts:AssumeRole"})}),
            _ch("aws_iam_role_policy", f"weak{i}p", {"name": "p", "role": f"weak{i}",
                "policy": _doc(_allow(["s3:GetObject"], "arn:aws:s3:::x-*/*"))}),
            _ch("aws_iam_user", f"lu{i}", {"name": f"lu{i}"}),
            _ch("aws_iam_user_policy", f"lu{i}p", {"name": "p", "user": f"lu{i}",
                "policy": _doc(_allow(["iam:PassRole"], f"{A}role/weak{i}"),
                               _allow(["lambda:CreateFunction"], "*"))}))))
    # 10-11: open a security-group port to 0.0.0.0/0 with nothing reachable behind it
    for i in range(2):
        prs.append((f"open port, nothing behind {i}", _plan(
            _ch("aws_security_group", f"sg{i}", {"id": f"sg-new{i}", "name": f"sg{i}",
                "ingress": [{"protocol": "tcp", "from_port": 8080, "to_port": 8080,
                             "cidr_blocks": ["0.0.0.0/0"]}]}))))
    # 12-13: attach a read-only AWS-managed-ish policy to a user (benign privilege)
    for i in range(2):
        prs.append((f"attach read-only {i}", _plan(
            _ch("aws_iam_user", f"au{i}", {"name": f"au{i}"}),
            _ch("aws_iam_user_policy", f"au{i}p", {"name": "p", "user": f"au{i}",
                "policy": _doc(_allow(["dynamodb:GetItem", "sqs:ReceiveMessage"], "*"))}))))
    # 14: a GitHub-OIDC role attached to a SCOPED (non-admin) policy — a source, no admin path
    prs.append(("github-oidc non-admin", _plan(
        _ch("aws_iam_role", "ghb", {"name": "ghb", "assume_role_policy": _doc({
            "Effect": "Allow",
            "Principal": {"Federated": f"{A}oidc-provider/token.actions.githubusercontent.com"},
            "Action": "sts:AssumeRoleWithWebIdentity",
            "Condition": {"StringLike": {"token.actions.githubusercontent.com:sub": "repo:acme/y:*"}}})}),
        _ch("aws_iam_role_policy", "ghbp", {"name": "p", "role": "ghb",
            "policy": _doc(_allow(["s3:GetObject"], "arn:aws:s3:::deploy-*/*"))}))))
    # 15: a private bucket holding a credential (not public -> not an external source)
    prs.append(("private bucket cred", _plan(
        _ch("aws_s3_bucket", "priv", {"bucket": "private-1"}),
        _ch("aws_s3_bucket_public_access_block", "privpab", {"bucket": "private-1",
            "block_public_acls": True, "ignore_public_acls": True,
            "block_public_policy": True, "restrict_public_buckets": True}))))
    return prs


def corpus() -> list[tuple[str, bool, dict]]:
    return ([(label, True, plan) for label, plan in _bad_prs()]
            + [(label, False, plan) for label, plan in _benign_prs()])


def evaluate_gate(base_records: list[dict] | None = None, account: str = ACCT) -> dict:
    base = base_records if base_records is not None else base_account()
    rows, tp, fn, fp, tn = [], 0, 0, 0, 0
    for label, expect_blocked, plan in corpus():
        blocked = gate(base, plan, account)["blocked"]
        rows.append({"label": label, "expected": expect_blocked, "blocked": blocked,
                     "correct": blocked == expect_blocked})
        if expect_blocked and blocked:
            tp += 1
        elif expect_blocked and not blocked:
            fn += 1
        elif not expect_blocked and blocked:
            fp += 1
        else:
            tn += 1
    n_bad, n_benign = tp + fn, fp + tn
    return {
        "bad": n_bad, "benign": n_benign,
        "detection_rate": round(tp / n_bad, 3) if n_bad else 0.0,
        "false_positive_rate": round(fp / n_benign, 3) if n_benign else 0.0,
        "true_positives": tp, "false_negatives": fn,
        "false_positives": fp, "true_negatives": tn,
        "rows": rows,
    }
