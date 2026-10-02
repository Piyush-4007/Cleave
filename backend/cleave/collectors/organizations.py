"""Organizations collector — is this account in an AWS Organization, and which service
control policies (SCPs) apply to it. Global. Reads only.

Emits exactly one `Organization` record (id `account:organization`). Every field is a
fact, not a judgement; iam/guardrails.py decides what they mean for evaluation:

  InOrganization     True / False / None (None = could not tell: the call was denied)
  OrgId, ManagementAccountId, Account
  ScpEnabled         is the SERVICE_CONTROL_POLICY type enabled on the root?
  ScpLevels          SCP documents per level, root first, then each OU, then the account
                     itself — or None when they could not be read. A member account
                     usually cannot read them (only the management account or a delegated
                     administrator can), so None is the normal member-account answer; the
                     scan then reports scp_status = "unreadable" rather than guessing.

All calls are free (organizations:Describe*/List*, in SecurityAudit).
"""
from __future__ import annotations
import json
from botocore.exceptions import ClientError
from .base import collector, paginate

ORG_ID = "account:organization"
SCP = "SERVICE_CONTROL_POLICY"


def _code(e: Exception) -> str:
    return getattr(e, "response", {}).get("Error", {}).get("Code", "") if isinstance(e, ClientError) else ""


def hierarchy(org, account: str) -> list[str]:
    """Target ids from the root down to the account: [root, ou..., account]."""
    chain, child = [account], account
    for _ in range(10):                      # OUs nest at most 5 deep; bound the walk
        parents = org.list_parents(ChildId=child).get("Parents", [])
        if not parents:
            break
        child = parents[0]["Id"]
        chain.append(child)
        if parents[0].get("Type") == "ROOT":
            break
    return list(reversed(chain))


def scp_documents(org, target: str) -> list[dict]:
    docs = []
    for pol in paginate(org, "list_policies_for_target", "Policies", TargetId=target, Filter=SCP):
        content = org.describe_policy(PolicyId=pol["Id"])["Policy"]["Content"]
        docs.append(json.loads(content) if isinstance(content, str) else content)
    return docs


def read_organization(org, account: str) -> dict:
    rec = {"_type": "Organization", "_id": ORG_ID, "Account": account,
           "InOrganization": None, "OrgId": None, "ManagementAccountId": None,
           "ScpEnabled": None, "ScpLevels": None}
    try:
        o = org.describe_organization()["Organization"]
    except Exception as e:  # noqa: BLE001
        if _code(e) == "AWSOrganizationsNotInUseException":
            rec["InOrganization"] = False
        return rec                           # denied / failed: membership unknown
    rec.update(InOrganization=True, OrgId=o.get("Id"),
               ManagementAccountId=o.get("MasterAccountId"))
    if o.get("FeatureSet") and o["FeatureSet"] != "ALL":
        rec["ScpEnabled"] = False            # consolidated-billing-only orgs have no SCPs
        return rec
    try:
        roots = org.list_roots().get("Roots", [])
        types = {t["Type"]: t["Status"] for r in roots for t in r.get("PolicyTypes", [])}
        rec["ScpEnabled"] = types.get(SCP) == "ENABLED"
        if rec["ScpEnabled"]:
            rec["ScpLevels"] = [scp_documents(org, t) for t in hierarchy(org, account)]
    except Exception:  # noqa: BLE001 - member accounts normally land here: unreadable
        rec["ScpLevels"] = None
    return rec


@collector("organizations")
def collect(ctx) -> list[dict]:
    account = ctx.client("sts").get_caller_identity()["Account"]
    return [read_organization(ctx.client("organizations"), account)]
