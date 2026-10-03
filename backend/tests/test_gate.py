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
    # PR gives the existing live user a sufficient-alone escalation primitive
    # (iam:AttachUserPolicy on *) via a new inline policy -> a new route to admin that did
    # not exist before. (Attaching *full* AdministratorAccess would make the user a baseline
    # admin, which Cleave correctly does NOT count as an escalation path — the primitive is
    # the real finding. iam:CreatePolicyVersion is holder-conditional and gets its own test.)
    p = plan(change("aws_iam_user_policy", "grant", {
        "name": "danger", "user": "dev", "policy": json.dumps({"Statement": [
            {"Effect": "Allow", "Action": "iam:AttachUserPolicy", "Resource": "*"}]})}))
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
                "Action": "iam:AttachUserPolicy", "Resource": "*"}]})}),
    )
    r = gate(live, p, ACCT)
    assert r["introduced"] == 1 and r["paths_before"] == 1 and r["paths_after"] == 2


# ---- the CLI exit code (CI uses it) -----------------------------------------------------

def test_cli_exits_nonzero_when_blocked(tmp_path):
    from cleave.gate.run import main
    p = plan(change("aws_iam_user", "dev", {"name": "dev"}),
             change("aws_iam_user_policy", "d", {"name": "danger", "user": "dev",
                "policy": json.dumps({"Statement": [{"Effect": "Allow",
                    "Action": "iam:AttachUserPolicy", "Resource": "*"}]})}))
    pf = tmp_path / "plan.json"
    pf.write_text(json.dumps(p), encoding="utf-8")
    assert main(["--plan", str(pf), "--account", ACCT]) == 1          # blocked
    benign = plan(change("aws_iam_policy", "ro", {"name": "ro", "policy": json.dumps(
        {"Statement": [{"Effect": "Allow", "Action": "s3:ListBucket", "Resource": "*"}]})}))
    bf = tmp_path / "benign.json"
    bf.write_text(json.dumps(benign), encoding="utf-8")
    assert main(["--plan", str(bf), "--account", ACCT]) == 0          # clean


# ---- stage 3: rendered comment + API ---------------------------------------------------

def test_comment_renders_path_and_fix():
    from cleave.gate.comment import render_comment
    p = plan(change("aws_iam_user", "dev", {"name": "dev"}),
             change("aws_iam_user_policy", "d", {"name": "danger", "user": "dev",
                "policy": json.dumps({"Statement": [{"Effect": "Allow",
                    "Action": "iam:AttachUserPolicy", "Resource": "*"}]})}))
    r = gate([], p, ACCT)
    md = render_comment(r, age="scanned 10m ago")
    assert "introduces 1 new attack path" in md and "```" in md
    # a remediation is always offered: a templated "Scoped alternative" or guidance blockquote
    assert "Scoped alternative" in md or "> **" in md
    assert "read-only" in md
    # benign -> green comment
    clean = render_comment(gate([], plan(change("aws_iam_policy", "ro",
        {"name": "ro", "policy": json.dumps({"Statement": [{"Effect": "Allow",
            "Action": "s3:ListBucket", "Resource": "*"}]})})), ACCT))
    assert "no new attack paths" in clean


# ---- stage 4a: CI-identity edges — GitHub Actions OIDC roles (no token) -----------------

from cleave.paths.endpoints import github_actions_repos, find_sources
from cleave.paths.graphview import graph_from_records
from cleave.paths.search import find_paths
from cleave.paths.model import ASSUMED_COMPROMISE

GH_OIDC = f"arn:aws:iam::{ACCT}:oidc-provider/token.actions.githubusercontent.com"
ADMIN_P = {"_type": "IamPolicy", "_id": "arn:aws:iam::aws:policy/AdministratorAccess",
           "PolicyName": "AdministratorAccess", "ManagedBy": "AWS",
           "Document": {"Statement": [{"Effect": "Allow", "Action": "*", "Resource": "*"}]}}


def gh_role(name, sub):
    cond = {} if sub is None else {"StringLike": {
        "token.actions.githubusercontent.com:sub": sub}}
    st = {"Effect": "Allow", "Principal": {"Federated": GH_OIDC},
          "Action": "sts:AssumeRoleWithWebIdentity"}
    if cond:
        st["Condition"] = cond
    return {"_type": "IamRole", "_id": f"{A}role/{name}", "RoleName": name,
            "AttachedPolicies": [ADMIN_P["_id"]], "InlinePolicies": {},
            "TrustPolicy": {"Statement": [st]}}


def test_parse_github_actions_repo_from_sub():
    assert github_actions_repos(gh_role("deploy", "repo:octo/infra:ref:refs/heads/main")) == ["octo/infra"]
    assert github_actions_repos(gh_role("deploy", "repo:octo/infra:*")) == ["octo/infra"]
    assert github_actions_repos(gh_role("wild", None)) == ["*"]          # no sub = any repo
    assert github_actions_repos({"TrustPolicy": {"Statement": []}}) == []  # not a GH role


def test_github_actions_role_is_a_source_path_to_admin():
    g = graph_from_records([gh_role("deploy", "repo:octo/infra:ref:refs/heads/main"), ADMIN_P])
    srcs = {s.uid: s for s in find_sources(g)}
    rid = f"{A}role/deploy"
    assert rid in srcs and srcs[rid].kind == ASSUMED_COMPROMISE
    assert "octo/infra" in srcs[rid].reason
    assert len(find_paths(g)) == 1          # CI -> admin


def test_unrestricted_github_role_names_the_misconfig():
    g = graph_from_records([gh_role("wild", None), ADMIN_P])
    src = {s.uid: s for s in find_sources(g)}[f"{A}role/wild"]
    assert "ANY GitHub repository" in src.reason


# ---- stage 4b: GitHub repo collector (fake client) + exposure refinement ----------------

def test_github_collector_reads_visibility_and_protection():
    from cleave.collectors.github import collect_github_repos
    calls = {
        f"{__import__('cleave.collectors.github', fromlist=['API']).API}/repos/octo/infra":
            (200, {"private": False, "default_branch": "main", "archived": False}),
    }

    def fake(url, token):
        if url.endswith("/branches/main/protection"):
            return 200, {"required_pull_request_reviews": {"required_approving_review_count": 0}}
        return calls.get(url, (404, None))

    recs = collect_github_repos(["octo/infra", "*"], token="x", fetch=fake)
    assert len(recs) == 1 and recs[0]["Visibility"] == "public"
    assert recs[0]["RequiredReviews"] == 0 and recs[0]["Repo"] == "octo/infra"


def test_public_unreviewed_repo_sharpens_the_source_note():
    repo_rec = {"_type": "GitHubRepo", "_id": "github:octo/infra", "Repo": "octo/infra",
                "Visibility": "public", "RequiredReviews": 0, "DefaultBranch": "main"}
    g = graph_from_records([gh_role("deploy", "repo:octo/infra:ref:refs/heads/main"),
                            ADMIN_P, repo_rec])
    src = {s.uid: s for s in find_sources(g)}[f"{A}role/deploy"]
    assert "HIGH exposure" in src.reason and "no required reviews" in src.reason
    assert len(find_paths(g)) == 1


def test_github_no_branch_protection_is_zero_required_reviews():
    from cleave.collectors.github import collect_github_repos, API
    def fake(url, token):
        if url == f"{API}/repos/octo/open":
            return 200, {"private": False, "default_branch": "main"}
        if url.endswith("/protection"):
            return 404, None          # branch not protected
        return 404, None
    rec = collect_github_repos(["octo/open"], token="x", fetch=fake)[0]
    assert rec["RequiredReviews"] == 0          # 404 = no protection = 0 reviews, not unknown


def test_github_no_admin_scope_is_unknown_reviews():
    from cleave.collectors.github import collect_github_repos, API
    def fake(url, token):
        if url == f"{API}/repos/octo/priv":
            return 200, {"private": True, "default_branch": "main"}
        if url.endswith("/protection"):
            return 403, None          # token lacks Administration:read
        return 404, None
    rec = collect_github_repos(["octo/priv"], token="x", fetch=fake)[0]
    assert rec["RequiredReviews"] is None       # unknown, not guessed


def test_gate_createpolicyversion_needs_a_managed_policy_to_version():
    # iam:CreatePolicyVersion escalates the holder only if they have an attached customer-
    # managed policy to rewrite into admin. A PR granting it to a holder WITH such a policy
    # opens a path (blocked); to a holder WITHOUT one it does not (Phase 10 / PMapper).
    with_cm = [
        {"_type": "IamUser", "_id": f"{A}user/dev", "UserName": "dev", "AccessKeys": [],
         "AttachedPolicies": [f"{A}policy/dev-cm"], "Groups": [], "InlinePolicies": {}},
        {"_type": "IamPolicy", "_id": f"{A}policy/dev-cm", "PolicyName": "dev-cm",
         "ManagedBy": "Customer", "Document": {"Statement": [
             {"Effect": "Allow", "Action": "s3:GetObject", "Resource": "*"}]}},
        ADMIN_MANAGED,
    ]
    without_cm = live_account()   # dev has only an inline read policy, nothing to version
    cpv = plan(change("aws_iam_user_policy", "grant", {
        "name": "danger", "user": "dev", "policy": json.dumps({"Statement": [
            {"Effect": "Allow", "Action": "iam:CreatePolicyVersion", "Resource": "*"}]})}))
    assert gate(with_cm, cpv, ACCT)["blocked"]              # a policy to version -> new path
    assert not gate(without_cm, cpv, ACCT)["blocked"]       # nothing to version -> no path
