"""IAM collector — users, roles, groups, policies (inline + attached + managed),
trust policies, and access keys WITH last-used dates. IAM is global (no region loop).

Reads and normalises only; it never marks anything insecure.
"""
from __future__ import annotations
from .base import collector, paginate
from ._util import as_doc


@collector("iam")
def collect(ctx) -> list[dict]:
    iam = ctx.client("iam")
    out: list[dict] = []

    # --- Users ---
    for u in paginate(iam, "list_users", "Users"):
        name = u["UserName"]
        attached = [p["PolicyArn"] for p in paginate(
            iam, "list_attached_user_policies", "AttachedPolicies", UserName=name)]
        inline = {}
        for pn in paginate(iam, "list_user_policies", "PolicyNames", UserName=name):
            inline[pn] = as_doc(iam.get_user_policy(UserName=name, PolicyName=pn)["PolicyDocument"])
        groups = [g["GroupName"] for g in paginate(
            iam, "list_groups_for_user", "Groups", UserName=name)]
        keys = []
        for k in paginate(iam, "list_access_keys", "AccessKeyMetadata", UserName=name):
            kid = k["AccessKeyId"]
            last = iam.get_access_key_last_used(AccessKeyId=kid).get("AccessKeyLastUsed", {})
            keys.append({
                "AccessKeyId": kid, "Status": k.get("Status"),
                "CreateDate": k.get("CreateDate"),
                "LastUsedDate": last.get("LastUsedDate"),
                "LastUsedService": last.get("ServiceName"),
                "LastUsedRegion": last.get("Region"),
            })
        out.append({
            "_type": "IamUser", "_id": u["Arn"], "UserName": name, "Arn": u["Arn"],
            "UserId": u["UserId"], "CreateDate": u.get("CreateDate"),
            "AttachedPolicies": attached, "InlinePolicies": inline,
            "Groups": groups, "AccessKeys": keys,
        })

    # --- Roles ---
    for r in paginate(iam, "list_roles", "Roles"):
        name = r["RoleName"]
        attached = [p["PolicyArn"] for p in paginate(
            iam, "list_attached_role_policies", "AttachedPolicies", RoleName=name)]
        inline = {}
        for pn in paginate(iam, "list_role_policies", "PolicyNames", RoleName=name):
            inline[pn] = as_doc(iam.get_role_policy(RoleName=name, PolicyName=pn)["PolicyDocument"])
        out.append({
            "_type": "IamRole", "_id": r["Arn"], "RoleName": name, "Arn": r["Arn"],
            "RoleId": r["RoleId"], "CreateDate": r.get("CreateDate"),
            "TrustPolicy": as_doc(r.get("AssumeRolePolicyDocument")),
            "AttachedPolicies": attached, "InlinePolicies": inline,
        })

    # --- Groups ---
    for g in paginate(iam, "list_groups", "Groups"):
        name = g["GroupName"]
        attached = [p["PolicyArn"] for p in paginate(
            iam, "list_attached_group_policies", "AttachedPolicies", GroupName=name)]
        inline = {}
        for pn in paginate(iam, "list_group_policies", "PolicyNames", GroupName=name):
            inline[pn] = as_doc(iam.get_group_policy(GroupName=name, PolicyName=pn)["PolicyDocument"])
        out.append({
            "_type": "IamGroup", "_id": g["Arn"], "GroupName": name, "Arn": g["Arn"],
            "AttachedPolicies": attached, "InlinePolicies": inline,
        })

    # --- Customer-managed policies (with default-version document) ---
    for p in paginate(iam, "list_policies", "Policies", Scope="Local"):
        doc = None
        try:
            doc = as_doc(iam.get_policy_version(
                PolicyArn=p["Arn"], VersionId=p["DefaultVersionId"]
            )["PolicyVersion"]["Document"])
        except Exception:  # noqa: BLE001
            pass
        out.append({
            "_type": "IamPolicy", "_id": p["Arn"], "PolicyName": p["PolicyName"],
            "Arn": p["Arn"], "DefaultVersionId": p.get("DefaultVersionId"),
            "AttachmentCount": p.get("AttachmentCount"), "Document": doc,
        })

    # --- Attached AWS-managed policies (documents, not just names) ---
    # Most principals on a real account carry AWS-managed policies (IAMFullAccess,
    # PowerUserAccess, ...). Without their documents the evaluator is blind to them:
    # grants_admin misses them, is_allowed misses PassRole/compute granted through them,
    # and a literal *:* goes unseen. list_policies(Scope="Local") never returns them, so
    # fetch exactly the ones something is actually attached to -- not all of AWS's
    # hundreds. GetPolicy/GetPolicyVersion are free and allowed by SecurityAudit.
    collected = {r["_id"] for r in out if r["_type"] == "IamPolicy"}
    referenced = {arn for r in out if r["_type"] in ("IamUser", "IamRole", "IamGroup")
                  for arn in r.get("AttachedPolicies", [])}
    for arn in sorted(referenced - collected):
        try:
            meta = iam.get_policy(PolicyArn=arn)["Policy"]
            doc = as_doc(iam.get_policy_version(
                PolicyArn=arn, VersionId=meta["DefaultVersionId"]
            )["PolicyVersion"]["Document"])
        except Exception:  # noqa: BLE001 - one unreadable policy must not sink the scan
            continue
        out.append({
            "_type": "IamPolicy", "_id": arn, "PolicyName": meta.get("PolicyName"),
            "Arn": arn, "DefaultVersionId": meta.get("DefaultVersionId"),
            "AttachmentCount": meta.get("AttachmentCount"),
            "ManagedBy": "AWS" if arn.startswith("arn:aws:iam::aws:policy/") else "Customer",
            "Document": doc,
        })

    # --- Instance profiles (instance -> role bridge; abused in Phase 0 scenario 2) ---
    for ip in paginate(iam, "list_instance_profiles", "InstanceProfiles"):
        out.append({
            "_type": "IamInstanceProfile", "_id": ip["Arn"],
            "InstanceProfileName": ip["InstanceProfileName"], "Arn": ip["Arn"],
            "Roles": [r["Arn"] for r in ip.get("Roles", [])],
        })

    return out
