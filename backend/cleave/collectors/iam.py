"""IAM collector — users, roles, groups, policies (inline + attached + managed),
trust policies, and access keys WITH last-used dates. IAM is global (no region loop).

Reads and normalises only; it never marks anything insecure.
"""
from __future__ import annotations
import csv
import io
import time
from .base import collector, paginate
from ._util import as_doc


def parse_credential_report(content) -> list[dict]:
    """The IAM credential report is a CSV (one row per user, plus <root_account>). It holds
    no secrets: only flags and dates (password_enabled, mfa_active, key age / last use).
    Normalised: 'N/A' / 'no_information' / 'not_supported' become None, 'true'/'false'
    become bools."""
    text = content.decode("utf-8") if isinstance(content, bytes) else content
    rows = []
    for row in csv.DictReader(io.StringIO(text)):
        norm = {}
        for k, v in row.items():
            if v in ("N/A", "no_information", "not_supported", ""):
                norm[k] = None
            elif v in ("true", "false"):
                norm[k] = v == "true"
            else:
                norm[k] = v
        rows.append(norm)
    return rows


def _account_records(iam) -> list[dict]:
    """Account-level IAM facts the findings layer needs. Each is emitted only if it could
    be read, so a missing record means 'unknown', never 'fine'; the checks rely on that."""
    out: list[dict] = []
    # Credential report: GenerateCredentialReport only (re)builds AWS's own report. It is
    # allowed by SecurityAudit and changes no configuration; AWS reuses one under 4h old.
    try:
        for _ in range(15):
            if iam.generate_credential_report().get("State") == "COMPLETE":
                break
            time.sleep(1)
        rep = iam.get_credential_report()
        out.append({"_type": "IamCredentialReport", "_id": "account:credential-report",
                    "GeneratedTime": rep.get("GeneratedTime"),
                    "Rows": parse_credential_report(rep["Content"])})
    except Exception:  # noqa: BLE001 - denied / not ready: leave it unknown
        pass
    try:
        pol = iam.get_account_password_policy().get("PasswordPolicy")
        out.append({"_type": "IamPasswordPolicy", "_id": "account:password-policy", "Policy": pol})
    except Exception as e:  # noqa: BLE001
        if getattr(e, "response", {}).get("Error", {}).get("Code") == "NoSuchEntity":
            # read fine: the account simply has no password policy
            out.append({"_type": "IamPasswordPolicy", "_id": "account:password-policy",
                        "Policy": None})
    try:
        out.append({"_type": "IamAccountSummary", "_id": "account:summary",
                    "Summary": iam.get_account_summary().get("SummaryMap", {})})
    except Exception:  # noqa: BLE001
        pass
    return out


def _boundary(getter, **kw) -> str | None:
    """The permissions-boundary policy ARN of a user/role. ListUsers/ListRoles omit it,
    so it costs one Get call per principal (free). If that call fails we report no
    boundary, which can only over-report a path, never hide one."""
    try:
        entity = getter(**kw)
        entity = entity.get("User") or entity.get("Role") or {}
    except Exception:  # noqa: BLE001
        return None
    return (entity.get("PermissionsBoundary") or {}).get("PermissionsBoundaryArn")


@collector("iam")
def collect(ctx) -> list[dict]:
    iam = ctx.client("iam")
    out: list[dict] = []

    # Listing is one paginated call per kind; the per-principal detail calls (policies,
    # groups, keys) are where the time goes, so those fan out across ctx.map. Order is
    # preserved, so the output matches a serial scan record for record.

    # --- Users ---
    def user(u: dict) -> dict:
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
        return {
            "_type": "IamUser", "_id": u["Arn"], "UserName": name, "Arn": u["Arn"],
            "UserId": u["UserId"], "CreateDate": u.get("CreateDate"),
            "AttachedPolicies": attached, "InlinePolicies": inline,
            "Groups": groups, "AccessKeys": keys,
            "PermissionsBoundary": _boundary(iam.get_user, UserName=name),
        }
    out += ctx.map(user, paginate(iam, "list_users", "Users"))

    # --- Roles ---
    def role(r: dict) -> dict:
        name = r["RoleName"]
        attached = [p["PolicyArn"] for p in paginate(
            iam, "list_attached_role_policies", "AttachedPolicies", RoleName=name)]
        inline = {}
        for pn in paginate(iam, "list_role_policies", "PolicyNames", RoleName=name):
            inline[pn] = as_doc(iam.get_role_policy(RoleName=name, PolicyName=pn)["PolicyDocument"])
        return {
            "_type": "IamRole", "_id": r["Arn"], "RoleName": name, "Arn": r["Arn"],
            "RoleId": r["RoleId"], "CreateDate": r.get("CreateDate"),
            "TrustPolicy": as_doc(r.get("AssumeRolePolicyDocument")),
            "AttachedPolicies": attached, "InlinePolicies": inline,
            "PermissionsBoundary": _boundary(iam.get_role, RoleName=name),
        }
    out += ctx.map(role, paginate(iam, "list_roles", "Roles"))

    # --- Groups ---
    def group(g: dict) -> dict:
        name = g["GroupName"]
        attached = [p["PolicyArn"] for p in paginate(
            iam, "list_attached_group_policies", "AttachedPolicies", GroupName=name)]
        inline = {}
        for pn in paginate(iam, "list_group_policies", "PolicyNames", GroupName=name):
            inline[pn] = as_doc(iam.get_group_policy(GroupName=name, PolicyName=pn)["PolicyDocument"])
        return {
            "_type": "IamGroup", "_id": g["Arn"], "GroupName": name, "Arn": g["Arn"],
            "AttachedPolicies": attached, "InlinePolicies": inline,
        }
    out += ctx.map(group, paginate(iam, "list_groups", "Groups"))

    # --- Customer-managed policies (with default-version document) ---
    def local_policy(p: dict) -> dict:
        doc = None
        try:
            doc = as_doc(iam.get_policy_version(
                PolicyArn=p["Arn"], VersionId=p["DefaultVersionId"]
            )["PolicyVersion"]["Document"])
        except Exception:  # noqa: BLE001
            pass
        return {
            "_type": "IamPolicy", "_id": p["Arn"], "PolicyName": p["PolicyName"],
            "Arn": p["Arn"], "DefaultVersionId": p.get("DefaultVersionId"),
            "AttachmentCount": p.get("AttachmentCount"), "Document": doc,
        }
    out += ctx.map(local_policy, paginate(iam, "list_policies", "Policies", Scope="Local"))

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
    # permissions boundaries are managed policies too, often attached to nothing else
    referenced |= {r["PermissionsBoundary"] for r in out if r.get("PermissionsBoundary")}
    def managed_policy(arn: str) -> dict | None:
        try:
            meta = iam.get_policy(PolicyArn=arn)["Policy"]
            doc = as_doc(iam.get_policy_version(
                PolicyArn=arn, VersionId=meta["DefaultVersionId"]
            )["PolicyVersion"]["Document"])
        except Exception:  # noqa: BLE001 - one unreadable policy must not sink the scan
            return None
        return {
            "_type": "IamPolicy", "_id": arn, "PolicyName": meta.get("PolicyName"),
            "Arn": arn, "DefaultVersionId": meta.get("DefaultVersionId"),
            "AttachmentCount": meta.get("AttachmentCount"),
            "ManagedBy": "AWS" if arn.startswith("arn:aws:iam::aws:policy/") else "Customer",
            "Document": doc,
        }
    out += [r for r in ctx.map(managed_policy, sorted(referenced - collected)) if r]

    # --- Instance profiles (instance -> role bridge; abused in Phase 0 scenario 2) ---
    for ip in paginate(iam, "list_instance_profiles", "InstanceProfiles"):
        out.append({
            "_type": "IamInstanceProfile", "_id": ip["Arn"],
            "InstanceProfileName": ip["InstanceProfileName"], "Arn": ip["Arn"],
            "Roles": [r["Arn"] for r in ip.get("Roles", [])],
        })

    out += _account_records(iam)
    return out
