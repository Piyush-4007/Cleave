"""Terraform plan adapter (Phase 9) — the whole trick.

`terraform show -json tfplan` describes what a PR would change. This turns that into the
**same normalised records the live collectors emit** (cleave/collectors/*), so the entire
engine — graph, IAM evaluator, path search, cut, remediation — is reused unchanged on a
*proposed* change. No new graph code; that is the handbook's explicit line.

Two steps, because a PR's attachments and inline policies often reference resources that
already exist LIVE and are not in the plan:

  parse_plan(plan, account)        -> {resources, rels, deleted}: the planned resource
                                      records, the relationship changes (attachments, inline
                                      policies, instance-profile roles) as deltas, and ids
                                      the plan destroys. No linking yet.
  build_records(base, parsed, acct)-> base records with the plan applied: planned resources
                                      upserted (field-merged on update), relationships linked
                                      against the MERGED set, deletes removed. base=[] gives a
                                      planned-only account; base=live records gives G_after.

Reference resolution: a plan rarely knows a new resource's ARN (it is computed), and
references use names. Records are keyed by a stable id (a real ARN when known, else
`arn:aws:iam::<account>:<kind>/<name>`); `account` is the live account the gate merges into,
so planned ARNs line up with the live graph.
"""
from __future__ import annotations
import json

PLAN_ACCOUNT = "PLAN"


def _loads(v):
    if isinstance(v, dict):
        return v
    if isinstance(v, str) and v.strip():
        try:
            return json.loads(v)
        except ValueError:
            return None
    return None


def _arn(account: str, kind: str, name: str) -> str:
    return f"arn:aws:iam::{account}:{kind}/{name}"


def _ingress(rules) -> list[dict]:
    out = []
    for r in rules or []:
        if not isinstance(r, dict):
            continue
        out.append({
            "IpProtocol": r.get("protocol"),
            "FromPort": r.get("from_port"),
            "ToPort": r.get("to_port"),
            "IpRanges": [{"CidrIp": c} for c in (r.get("cidr_blocks") or [])],
            "Ipv6Ranges": [{"CidrIpv6": c} for c in (r.get("ipv6_cidr_blocks") or [])],
        })
    return out


def parse_plan(plan: dict, account: str = PLAN_ACCOUNT) -> dict:
    resources: dict[str, dict] = {}
    rels: list[dict] = []
    deleted: set[str] = set()

    def arn_or(kind, after):
        return after.get("arn") or _arn(account, kind, after.get("name") or "")

    for ch in plan.get("resource_changes") or []:
        if ch.get("mode") != "managed":
            continue
        rtype = ch.get("type")
        c = ch.get("change") or {}
        actions = c.get("actions") or []
        after = c.get("after") or {}
        before = c.get("before") or {}

        if "delete" in actions and "create" not in actions:
            if before.get("arn"):
                deleted.add(before["arn"])
            elif rtype == "aws_s3_bucket" and before.get("bucket"):
                deleted.add(f"arn:aws:s3:::{before['bucket']}")
            continue
        if not after:
            continue

        if rtype == "aws_iam_role":
            _id = arn_or("role", after)
            resources[_id] = {"_type": "IamRole", "_id": _id, "RoleName": after.get("name"),
                              "TrustPolicy": _loads(after.get("assume_role_policy")),
                              "AttachedPolicies": [], "InlinePolicies": {}}
        elif rtype == "aws_iam_user":
            _id = arn_or("user", after)
            resources[_id] = {"_type": "IamUser", "_id": _id, "UserName": after.get("name"),
                              "AttachedPolicies": [], "InlinePolicies": {}, "Groups": [],
                              "AccessKeys": []}
        elif rtype == "aws_iam_group":
            _id = arn_or("group", after)
            resources[_id] = {"_type": "IamGroup", "_id": _id, "GroupName": after.get("name"),
                              "AttachedPolicies": [], "InlinePolicies": {}}
        elif rtype == "aws_iam_policy":
            _id = arn_or("policy", after)
            resources[_id] = {"_type": "IamPolicy", "_id": _id, "PolicyName": after.get("name"),
                              "Document": _loads(after.get("policy")), "ManagedBy": "Customer"}
        elif rtype == "aws_iam_instance_profile":
            _id = arn_or("instance-profile", after)
            resources[_id] = {"_type": "IamInstanceProfile", "_id": _id,
                              "InstanceProfileName": after.get("name"), "Roles": []}
            rels.append({"kind": "profile_role", "profile": _id, "role": after.get("role")})
        elif rtype == "aws_s3_bucket":
            name = after.get("bucket")
            _id = after.get("arn") or f"arn:aws:s3:::{name}"
            resources[_id] = {"_type": "S3Bucket", "_id": _id, "Name": name,
                              "Policy": None, "PublicAccessBlock": None, "Acl": []}
        elif rtype == "aws_s3_bucket_policy":
            rels.append({"kind": "bucket_policy", "bucket": after.get("bucket"),
                         "policy": _loads(after.get("policy"))})
        elif rtype == "aws_s3_bucket_public_access_block":
            rels.append({"kind": "bucket_pab", "bucket": after.get("bucket"), "pab": {
                "BlockPublicAcls": after.get("block_public_acls"),
                "IgnorePublicAcls": after.get("ignore_public_acls"),
                "BlockPublicPolicy": after.get("block_public_policy"),
                "RestrictPublicBuckets": after.get("restrict_public_buckets")}})
        elif rtype == "aws_security_group":
            _id = after.get("id") or after.get("arn") or _arn(account, "security-group",
                                                              after.get("name") or "sg")
            resources[_id] = {"_type": "SecurityGroup", "_id": _id,
                              "GroupName": after.get("name"),
                              "IngressRules": _ingress(after.get("ingress"))}
        elif rtype == "aws_lambda_function":
            _id = after.get("arn") or _arn(account, "function", after.get("function_name") or "fn")
            resources[_id] = {"_type": "LambdaFunction", "_id": _id,
                              "FunctionName": after.get("function_name"), "Role": after.get("role")}
        elif rtype in ("aws_iam_role_policy", "aws_iam_user_policy", "aws_iam_group_policy"):
            kind = {"aws_iam_role_policy": "role", "aws_iam_user_policy": "user",
                    "aws_iam_group_policy": "group"}[rtype]
            rels.append({"kind": "inline", "owner_kind": kind, "owner": after.get(kind),
                         "name": after.get("name"), "policy": _loads(after.get("policy"))})
        elif rtype in ("aws_iam_role_policy_attachment", "aws_iam_user_policy_attachment",
                       "aws_iam_group_policy_attachment"):
            kind = rtype.split("_")[2]  # role/user/group
            rels.append({"kind": "attach", "owner_kind": kind, "owner": after.get(kind),
                         "policy_arn": after.get("policy_arn")})
        elif rtype == "aws_iam_policy_attachment":
            for k, field in (("role", "roles"), ("user", "users"), ("group", "groups")):
                for nm in after.get(field) or []:
                    rels.append({"kind": "attach", "owner_kind": k, "owner": nm,
                                 "policy_arn": after.get("policy_arn")})

    return {"resources": resources, "rels": rels, "deleted": deleted}


def _find(by_id, by_name, kind, ref, account):
    """Resolve a role/user/group reference (name or ARN) against the merged record set."""
    if not ref:
        return None
    if ref in by_id:
        return by_id[ref]
    k = {"role": "role", "user": "user", "group": "group"}[kind]
    for cand in (by_name.get((k, ref)), _arn(account, k, ref)):
        if cand and (by_id.get(cand) if isinstance(cand, str) else cand):
            return by_id.get(cand) if isinstance(cand, str) else cand
    return by_name.get((k, ref))


def build_records(base: list[dict], parsed: dict, account: str = PLAN_ACCOUNT) -> list[dict]:
    """Apply a parsed plan to `base` records (live, or [] for a planned-only account)."""
    by_id = {r["_id"]: dict(r) for r in base if r["_id"] not in parsed["deleted"]}

    # upsert planned resources: field-merge on update (keep live fields the plan omits),
    # replace wholesale on create.
    for _id, rec in parsed["resources"].items():
        if _id in by_id:
            merged = dict(by_id[_id])
            merged.update({k: v for k, v in rec.items() if v not in (None, [], {})})
            by_id[_id] = merged
        else:
            by_id[_id] = dict(rec)

    by_name = {}
    for r in by_id.values():
        for k, field in (("role", "RoleName"), ("user", "UserName"), ("group", "GroupName")):
            if r.get(field):
                by_name[(k, r[field])] = r
    bucket_by_name = {r.get("Name"): r for r in by_id.values() if r["_type"] == "S3Bucket"}

    for rel in parsed["rels"]:
        kind = rel["kind"]
        if kind == "profile_role":
            prof, role = by_id.get(rel["profile"]), _find(by_id, by_name, "role", rel["role"], account)
            if prof is not None and role is not None:
                prof.setdefault("Roles", []).append(role["_id"])
        elif kind == "inline":
            owner = _find(by_id, by_name, rel["owner_kind"], rel["owner"], account)
            if owner is not None:
                owner.setdefault("InlinePolicies", {})[rel["name"]] = rel["policy"]
        elif kind == "attach":
            owner = _find(by_id, by_name, rel["owner_kind"], rel["owner"], account)
            if owner is not None and rel["policy_arn"]:
                owner.setdefault("AttachedPolicies", []).append(rel["policy_arn"])
        elif kind == "bucket_policy":
            b = bucket_by_name.get(rel["bucket"]) or by_id.get(f"arn:aws:s3:::{rel['bucket']}")
            if b is not None:
                b["Policy"] = rel["policy"]
        elif kind == "bucket_pab":
            b = bucket_by_name.get(rel["bucket"]) or by_id.get(f"arn:aws:s3:::{rel['bucket']}")
            if b is not None:
                b["PublicAccessBlock"] = rel["pab"]

    return list(by_id.values())


def records_from_plan(plan: dict, account: str = PLAN_ACCOUNT) -> tuple[list[dict], set[str]]:
    """Convenience: a planned-only account (base=[]) plus the deleted ids."""
    parsed = parse_plan(plan, account)
    return build_records([], parsed, account), parsed["deleted"]
