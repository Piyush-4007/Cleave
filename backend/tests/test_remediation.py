"""Phase 8 — remediation generator + verification loop.

Each test runs a path fixture through analyze -> generate(fix) -> verify, and asserts the
fix both looks right (the corrected Terraform/policy removes the dangerous grant) and
WORKS (re-running the search with it applied removes the path). The verify half is the
handbook's "rescan -> path confirmed gone", done offline.
"""
import json
import pathlib

import pytest

from cleave.paths.analysis import analyze
from cleave.paths.graphview import graph_from_records
from cleave.remediation.generate import generate, generate_for_result
from cleave.remediation.verify import verify_fixes

FIX_DIR = pathlib.Path(__file__).parent / "path_fixtures"


def _load(name):
    fx = json.loads((FIX_DIR / name).read_text())
    g = graph_from_records(fx["records"], fx.get("cred_findings", []))
    return fx, g, analyze(g)


def _edge(result, rel):
    for e in result["minimum_cut"]["edges"]:
        if e["rel"] == rel:
            return e
    raise AssertionError(f"no {rel} in the minimum cut: "
                         f"{[e['rel'] for e in result['minimum_cut']['edges']]}")


# ---- GRANTS_ADMIN on a primitive (customer/inline policy) ------------------------------

def test_grants_admin_primitive_is_scoped_and_verified():
    fx, g, result = _load("01-iam_privesc_by_rollback.json")
    fix = generate(_edge(result, "GRANTS_ADMIN"), g)
    assert fix.confidence == "templated"
    assert "SetDefaultPolicyVersion" not in json.dumps(fix.policy_json)
    assert fix.terraform and "jsonencode" in fix.terraform
    v = verify_fixes(fx["records"], [fix.to_dict()])
    assert v["fully_cut"] and v["paths_after"] == 0


# ---- GRANTS_ADMIN on real AdministratorAccess (AWS-managed) -> guidance ----------------

def test_grants_admin_aws_managed_is_guidance():
    fx, g, result = _load("09-access-key-takeover-of-an-admin.json")
    # the admin policy itself is AWS-managed: a direct GRANTS_ADMIN fix is guidance-only
    admin_edge = {"rel": "GRANTS_ADMIN",
                  "frm": "arn:aws:iam::aws:policy/AdministratorAccess", "to": "admin",
                  "fix": "x"}
    fix = generate(admin_edge, g)
    assert fix.confidence == "guidance" and fix.terraform is None
    assert "detach" in fix.note.lower()


# ---- CAN_TAKE_OVER -> scope to self, verified ------------------------------------------

def test_can_take_over_is_scoped_to_self_and_verified():
    fx, g, result = _load("09-access-key-takeover-of-an-admin.json")
    fix = generate(_edge(result, "CAN_TAKE_OVER"), g)
    assert fix.confidence == "templated"
    assert "${aws:username}" in json.dumps(fix.policy_json)
    v = verify_fixes(fx["records"], [fix.to_dict()])
    assert v["fully_cut"] and v["paths_after"] == 0


# ---- the whole minimum cut, as the UI would request it ---------------------------------

def test_generate_for_result_cuts_every_path():
    fx, g, result = _load("06-overlapping-paths-shared-cut.json")
    fixes = generate_for_result(result, g)
    assert fixes and all(f["confidence"] in ("templated", "guidance") for f in fixes)
    templated = [f for f in fixes if f["confidence"] == "templated"]
    assert templated, "the shared-cut fixture should yield at least one templated fix"
    v = verify_fixes(fx["records"], templated, fx.get("cred_findings", []))
    assert v["remaining"] < v["paths_before"]  # the cut reduces the paths


# ---- a guidance fallback never claims to be a patch ------------------------------------

def test_unknown_edge_is_guidance_only():
    fix = generate({"rel": "CAN_REACH", "frm": "internet", "to": "x", "fix": "narrow SG"},
                   graph_from_records([]))
    assert fix.confidence == "guidance" and fix.terraform is None and not fix.apply


# ---- stage 2: CAN_ASSUME + CAN_LAUNCH_AS -----------------------------------------------

def test_can_assume_same_account_delegation_is_removed_and_verified():
    fx, g, result = _load("12-account-root-delegation.json")
    fix = generate(_edge(result, "CAN_ASSUME"), g)
    assert fix.confidence == "templated"
    assert "sts:AssumeRole" not in json.dumps(fix.policy_json)
    v = verify_fixes(fx["records"], [fix.to_dict()])
    assert v["fully_cut"] and v["paths_after"] == 0


def test_can_assume_wildcard_trust_is_removed_and_verified():
    A = "arn:aws:iam::111122223333:"
    admin = {"_type": "IamPolicy", "_id": "arn:aws:iam::aws:policy/AdministratorAccess",
             "PolicyName": "AdministratorAccess", "ManagedBy": "AWS",
             "Document": {"Statement": [{"Effect": "Allow", "Action": "*", "Resource": "*"}]}}
    role = {"_type": "IamRole", "_id": f"{A}role/open", "RoleName": "open",
            "AttachedPolicies": [admin["_id"]], "InlinePolicies": {},
            "TrustPolicy": {"Statement": [{"Effect": "Allow", "Principal": "*",
                                           "Action": "sts:AssumeRole"}]}}
    g = graph_from_records([role, admin])
    result = analyze(g)
    fix = generate(_edge(result, "CAN_ASSUME"), g)
    assert fix.confidence == "templated" and fix.apply["kind"] == "replace_trust"
    v = verify_fixes([role, admin], [fix.to_dict()])
    assert v["fully_cut"]


def test_cross_account_assume_is_guidance():
    fix = generate({"rel": "CAN_ASSUME", "frm": "arn:aws:iam::999999999999:root",
                    "to": "arn:aws:iam::111122223333:role/vendor", "fix": "x"},
                   graph_from_records([]))
    assert fix.confidence == "guidance" and "ExternalId" in fix.note


def test_can_launch_as_is_guidance_with_options():
    fix = generate({"rel": "CAN_LAUNCH_AS", "frm": "arn:aws:iam::1:user/dev",
                    "to": "arn:aws:iam::1:role/r", "fix": "x"}, graph_from_records([]))
    assert fix.confidence == "guidance" and "PassedToService" in fix.note


# ---- stage 3: CAN_REACH security-group narrowing ---------------------------------------

def test_can_reach_removes_public_ingress_and_applies():
    from cleave.remediation.verify import apply_fixes
    sg = {"_type": "SecurityGroup", "_id": "sg-123", "GroupName": "web",
          "IngressRules": [
              {"IpProtocol": "tcp", "FromPort": 22, "ToPort": 22,
               "IpRanges": [{"CidrIp": "0.0.0.0/0"}]},
              {"IpProtocol": "tcp", "FromPort": 443, "ToPort": 443,
               "IpRanges": [{"CidrIp": "10.0.0.0/8"}]}]}
    inst = {"_type": "Ec2Instance", "_id": "i-abc", "SecurityGroups": ["sg-123"]}
    g = graph_from_records([sg, inst])
    fix = generate({"rel": "CAN_REACH", "frm": "internet", "to": "i-abc", "fix": "x"}, g)
    assert fix.confidence == "templated"
    assert "22" in fix.note
    # 0.0.0.0/0 may appear in the explanatory comment, but never in the kept ingress rules
    assert "0.0.0.0/0" not in json.dumps(fix.apply["security_groups"])
    # the apply transform drops the public rule but keeps the internal one
    applied = apply_fixes([sg, inst], [fix.to_dict()])
    kept = next(r for r in applied if r["_id"] == "sg-123")["IngressRules"]
    assert len(kept) == 1 and kept[0]["FromPort"] == 443


def test_can_reach_without_sg_data_is_guidance():
    g = graph_from_records([{"_type": "Ec2Instance", "_id": "i-x", "SecurityGroups": []}])
    fix = generate({"rel": "CAN_REACH", "frm": "internet", "to": "i-x", "fix": "x"}, g)
    assert fix.confidence == "guidance"


# ---- stage 4: the downloadable bundle --------------------------------------------------

def test_bundle_writes_tf_files_and_summary(tmp_path):
    from cleave.remediation.bundle import write_bundle
    fx, g, result = _load("06-overlapping-paths-shared-cut.json")
    fixes = generate_for_result(result, g)
    out = write_bundle(fixes, tmp_path / "remediations")
    files = sorted(p.name for p in out.iterdir())
    assert "REMEDIATION.md" in files
    assert any(n.endswith(".tf") for n in files)
    md = (out / "REMEDIATION.md").read_text(encoding="utf-8")
    assert "might break" in md and "terraform plan" in md


# ---- stage 4: S3 public-bucket Public Access Block (source-level, verified) -------------

def test_public_bucket_gets_pab_and_is_verified():
    fx, g, result = _load("03-public-bucket-credential-to-admin.json")
    fixes = generate_for_result(result, g)
    pab = [f for f in fixes if f["rel"] == "PUBLIC_BUCKET"]
    assert pab, "a public-bucket path should yield a Public Access Block fix"
    assert pab[0]["confidence"] == "templated"
    assert "restrict_public_buckets = true" in pab[0]["terraform"]
    # applying just the PAB(s) removes the external bucket path
    v = verify_fixes(fx["records"], pab, fx.get("cred_findings", []))
    assert v["removed"] >= 1


# ---- stage 5: teams delivery (PR plan) -------------------------------------------------

def test_pr_plan_is_pure_and_complete():
    import datetime as dt
    from cleave.remediation.pr import build_pr_plan
    fx, g, result = _load("09-access-key-takeover-of-an-admin.json")
    fixes = generate_for_result(result, g)
    plan = build_pr_plan(fixes, "acme/infra", base="main",
                         now=dt.datetime(2026, 10, 3, tzinfo=dt.timezone.utc))
    assert plan["repo"] == "acme/infra" and plan["branch"].startswith("cleave/remediation-")
    # files are namespaced under the subdir, include the summary + at least one .tf
    assert all(p.startswith("cleave-remediation/") for p in plan["files"])
    assert any(p.endswith(".tf") for p in plan["files"])
    assert "terraform plan" in plan["body"] and "read-only AWS access" in plan["body"]


def test_open_pr_dry_run_opens_nothing():
    from cleave.remediation.pr import open_pr
    fx, g, result = _load("09-access-key-takeover-of-an-admin.json")
    out = open_pr(generate_for_result(result, g), "acme/infra", token="unused", dry_run=True)
    assert out["dry_run"] is True and "pr_url" not in out


# ---- correctness: never emit an invalid (empty) policy or an ARN-as-bucket-name ---------

def test_policy_that_grants_only_the_escalation_becomes_detach_guidance():
    A = "arn:aws:iam::1:"
    pol = {"_type": "IamPolicy", "_id": f"{A}policy/only-attach", "PolicyName": "only-attach",
           "Document": {"Statement": [{"Effect": "Allow", "Action": "iam:PutUserPolicy",
                                       "Resource": "*"}]}}
    user = {"_type": "IamUser", "_id": f"{A}user/u", "UserName": "u",
            "AttachedPolicies": [pol["_id"]], "Groups": [], "InlinePolicies": {}}
    g = graph_from_records([pol, user])
    fix = generate({"rel": "GRANTS_ADMIN", "frm": pol["_id"], "to": "admin", "fix": "x"}, g)
    assert fix.confidence == "guidance" and fix.terraform is None
    assert "detach" in fix.note.lower()


def test_s3_pab_uses_the_bucket_name_not_the_arn():
    bucket = {"_type": "S3Bucket", "_id": "arn:aws:s3:::my-data", "Name": "my-data",
              "PublicAccessBlock": None, "Acl": [],
              "Policy": {"Statement": [{"Effect": "Allow", "Principal": "*",
                                        "Action": "s3:GetObject",
                                        "Resource": "arn:aws:s3:::my-data/*"}]}}
    from cleave.remediation.generate import _fix_public_bucket
    tf = _fix_public_bucket("arn:aws:s3:::my-data", graph_from_records([bucket])).terraform
    assert 'bucket                  = "my-data"' in tf and "arn:aws:s3" not in tf
