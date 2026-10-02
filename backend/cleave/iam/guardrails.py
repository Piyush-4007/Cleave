"""Guardrails in force for a principal (Phase 7): permissions boundary + SCPs.

Both only ever SUBTRACT. A permissions boundary caps what a user/role's own policies can
grant; service control policies cap everything the account's principals can do. The
evaluator takes them as `boundary=` / `scps=`; this module works out which apply, from
collected records, so the edge builders (graph/evaluated.py) and the on-demand access
expansion (paths/access.py) apply exactly the same rules.

Rules (IAM User Guide, "Policy evaluation logic"; AWS Organizations, "SCP evaluation"):
  * No boundary attached -> None. Boundary attached but its document unreadable -> the
    evaluator's UNREADABLE (every capped grant becomes POSSIBLE, never silently dropped).
  * A boundary the principal can remove or replace on itself
    (iam:Delete|Put{User,Role}PermissionsBoundary, allowed THROUGH the boundary) is not a
    guardrail against that principal: removing it is one more API call. -> None.
  * SCPs: not in an organization, the management account, or a service-linked role
    -> None. In an organization whose SCPs could not be read -> None as well, and the
    scan carries an `scp_status` caveat instead (see scp_status) — otherwise every path
    in a member account would collapse to POSSIBLE on a guardrail we cannot see.
"""
from __future__ import annotations
from typing import Callable
from .evaluator import UNREADABLE, Decision, is_allowed, is_full_admin

ORG_ID = "account:organization"
SERVICE_LINKED = "/aws-service-role/"

REMOVE_BOUNDARY = {
    "user": ("iam:DeleteUserPermissionsBoundary", "iam:PutUserPermissionsBoundary"),
    "role": ("iam:DeleteRolePermissionsBoundary", "iam:PutRolePermissionsBoundary"),
}


def _kind(arn: str) -> str | None:
    tail = arn.split(":", 5)[-1] if arn.startswith("arn:") else ""
    return "user" if tail.startswith("user/") else "role" if tail.startswith("role/") else None


def scp_levels(org: dict | None, principal_arn: str):
    """The SCP hierarchy that applies to this principal, or None."""
    if not org or not org.get("InOrganization"):
        return None
    if org.get("Account") and org.get("Account") == org.get("ManagementAccountId"):
        return None                      # SCPs never apply to the management account
    if SERVICE_LINKED in principal_arn:
        return None                      # nor to service-linked roles
    if org.get("ScpEnabled") is False:
        return None
    return org.get("ScpLevels") or None  # None when unreadable: see scp_status


def scp_status(org: dict | None) -> str:
    """One word for the scan summary: how SCPs were handled."""
    if not org:
        return "not_collected"
    if org.get("InOrganization") is None:
        return "unknown"
    if not org.get("InOrganization"):
        return "not_in_organization"
    if org.get("Account") and org.get("Account") == org.get("ManagementAccountId"):
        return "management_account"
    if org.get("ScpEnabled") is False:
        return "scps_disabled"
    return "applied" if org.get("ScpLevels") else "unreadable"


def org_context(org: dict | None) -> dict:
    """Request-context keys the organization makes decidable (aws:PrincipalOrgID)."""
    if org and org.get("InOrganization") and org.get("OrgId"):
        return {"aws:PrincipalOrgID": org["OrgId"]}
    return {}


def guardrails(principal: dict, docs: list[dict], lookup_doc: Callable[[str], dict | None],
               org: dict | None) -> dict:
    """Keyword arguments for is_allowed() for this principal:
    {"boundary": ..., "scps": ..., "context": {...}}.

    `docs` are the principal's identity policy documents (needed to decide whether it can
    remove its own boundary); `lookup_doc(arn)` returns a managed policy's document."""
    arn = principal["_id"]
    scps = scp_levels(org, arn)
    ctx = org_context(org)
    boundary = None
    b_arn = principal.get("PermissionsBoundary")
    if b_arn:
        boundary = lookup_doc(b_arn) or UNREADABLE
        kind = _kind(arn)
        if kind and docs:
            for action in REMOVE_BOUNDARY[kind]:
                r = is_allowed(docs, action, arn, principal=arn, context=ctx,
                               boundary=boundary, scps=scps)
                if r.decision is Decision.ALLOW:
                    boundary = None      # it can lift its own cap
                    break
    return {"boundary": boundary, "scps": scps, "context": ctx}


def boundary_below_full_admin(principal: dict, guard: dict) -> bool:
    """True if a boundary in force stops this principal being literal full admin, even
    when it holds AdministratorAccess."""
    b = guard.get("boundary")
    if b is None:
        return False
    if b == UNREADABLE:
        return True                      # unknown cap: do not call it baseline admin
    docs = b if isinstance(b, list) else [b]
    return not any(is_full_admin(d) for d in docs)
