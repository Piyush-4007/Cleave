"""IAM policy evaluator — v1.

Answers `is_allowed(policies, action, resource)` with a decision + confidence, and
`grants_admin(policy)`. Deliberately conservative: anything it cannot decide statically
becomes POSSIBLE, never a silent allow or deny.

v1 scope (handbook): explicit Deny, identity policies, wildcard action/resource expansion,
NotAction/NotResource, and conditions treated as "undecidable -> POSSIBLE". Deferred to v2
(Phase 7): SCPs, permission boundaries, session policies, cross-account, real condition
operators. Each deferral is marked `# TODO v2`.
"""
from __future__ import annotations
import fnmatch
from dataclasses import dataclass, field
from enum import Enum
from .catalogue import ADMIN_EQUIVALENT_ACTIONS


class Decision(str, Enum):
    ALLOW = "ALLOW"
    DENY = "DENY"


class Confidence(str, Enum):
    CERTAIN = "CERTAIN"
    POSSIBLE = "POSSIBLE"


@dataclass
class EvalResult:
    decision: Decision
    confidence: Confidence
    reason: str
    matched: list = field(default_factory=list)  # statements that decided it (edge evidence)

    @property
    def bucket(self) -> str:
        """The handbook's three buckets: Certain | Possible | Denied."""
        if self.decision is Decision.DENY:
            return "Denied"
        return "Certain" if self.confidence is Confidence.CERTAIN else "Possible"


# ---- matching helpers ----------------------------------------------------------------

def _as_list(v) -> list:
    if v is None:
        return []
    return v if isinstance(v, list) else [v]


def _glob(pattern: str, value: str, ci: bool) -> bool:
    """AWS-style wildcard match (* and ?). Actions are case-insensitive; resource ARNs
    are matched case-sensitively (S3 keys, etc. are case-sensitive)."""
    if ci:
        pattern, value = pattern.lower(), value.lower()
    return fnmatch.fnmatchcase(value, pattern)


def _action_matches(stmt: dict, action: str) -> bool:
    acts = _as_list(stmt.get("Action"))
    if acts:
        return any(_glob(p, action, ci=True) for p in acts)
    nacts = _as_list(stmt.get("NotAction"))
    if nacts:
        return not any(_glob(p, action, ci=True) for p in nacts)
    return False  # a statement with neither matches nothing


def _resource_matches(stmt: dict, resource: str, resource_policy: bool = False) -> bool:
    res = _as_list(stmt.get("Resource"))
    if res:
        return any(_glob(p, resource, ci=False) for p in res)
    nres = _as_list(stmt.get("NotResource"))
    if nres:
        return not any(_glob(p, resource, ci=False) for p in nres)
    # No Resource/NotResource. On a resource-BASED policy that means "this resource" — the
    # normal way bucket policies are written. On an identity policy it is not valid, and
    # treating it as a match would allow everything, so we stay conservative there.
    return resource_policy


def _account_of(arn: str | None) -> str | None:
    """The account id embedded in an ARN, if it has one."""
    if not arn or not arn.startswith("arn:"):
        return None
    parts = arn.split(":")
    return parts[4] or None if len(parts) > 4 else None


def _principal_match_kind(stmt: dict, principal: str | None, account: str | None) -> str | None:
    """How a resource-policy statement's Principal relates to our principal.

    Returns:
      "explicit"  — names this principal (or `*`). An Allow here is sufficient on its own.
      "delegated" — names the account root, i.e. "anyone in this account, *if* their own
                    identity policy also allows it". An Allow here grants nothing extra,
                    so it is recorded but never treated as an independent Allow.
      None        — does not apply to us.
    """
    # TODO v2: NotPrincipal (rare, and easy to get backwards — better absent than wrong).
    if "NotPrincipal" in stmt:
        return None
    pr = stmt.get("Principal")
    if pr == "*":
        return "explicit"
    if not isinstance(pr, dict):
        return None
    roots = {account, f"arn:aws:iam::{account}:root"} if account else set()
    for value in _as_list(pr.get("AWS")):
        if value == "*":
            return "explicit"
        if principal and value == principal:
            return "explicit"
        if value in roots:
            return "delegated"
    return None


def _statements(policies: list[dict]):
    for doc in policies:
        if not isinstance(doc, dict):
            continue
        stmts = doc.get("Statement", [])
        if isinstance(stmts, dict):
            stmts = [stmts]
        for st in stmts:
            if isinstance(st, dict):
                yield st


# ---- the evaluator -------------------------------------------------------------------

def is_allowed(policies: list[dict], action: str, resource: str,
               resource_policy: dict | None = None,
               principal: str | None = None) -> EvalResult:
    """Evaluate whether `action` on `resource` is allowed.

    `policies` are the identity policy documents in force for the caller. Pass
    `resource_policy` (a bucket policy, key policy, secret policy, …) and `principal`
    (the caller's ARN) to include the resource-based side of the decision.

    Same-account semantics: an Allow in *either* the identity policy or the resource
    policy is sufficient, and an explicit Deny in either wins. That is what AWS does
    within one account, which is the model Cleave uses (handbook: single account, two
    roles).
    TODO v2: cross-account needs an Allow on BOTH sides, and KMS is stricter still —
    the key policy is authoritative unless it delegates to IAM. Both currently
    over-allow, which is the v1 posture (over-report, never silently hide).
    """
    identity = [st for st in _statements(policies)
                if _action_matches(st, action) and _resource_matches(st, resource)]

    # The resource-based side also has to name us.
    account = _account_of(principal) or _account_of(resource)
    res_matched: list[tuple[dict, str]] = []
    if resource_policy:
        for st in _statements([resource_policy]):
            if not (_action_matches(st, action)
                    and _resource_matches(st, resource, resource_policy=True)):
                continue
            kind = _principal_match_kind(st, principal, account)
            if kind:
                res_matched.append((st, kind))

    denies = ([st for st in identity if st.get("Effect") == "Deny"]
              + [st for st, _k in res_matched if st.get("Effect") == "Deny"])
    identity_allows = [st for st in identity if st.get("Effect") == "Allow"]
    # A "delegated" resource Allow (Principal = account root) grants nothing the identity
    # policy does not already grant, so it is never an independent Allow.
    resource_allows = [st for st, k in res_matched
                       if st.get("Effect") == "Allow" and k == "explicit"]
    allows = identity_allows + resource_allows

    # 1) explicit Deny.  Unconditional deny -> hard block (Certain).
    hard_denies = [st for st in denies if "Condition" not in st]
    if hard_denies:
        return EvalResult(Decision.DENY, Confidence.CERTAIN,
                          "explicit Deny (unconditional) matched", hard_denies)

    # 2) Allow?
    if allows:
        # A conditional Deny *might* block -> can't be Certain.  (Do not hard-block: that
        # could hide a real path — we over-report instead, per v1 policy.)
        cond_denies = [st for st in denies if "Condition" in st]
        plain_allows = [st for st in allows if "Condition" not in st]
        via = ("the resource policy" if resource_allows and not identity_allows
               else "an identity policy")
        if plain_allows and not cond_denies:
            return EvalResult(Decision.ALLOW, Confidence.CERTAIN,
                              f"Allow matched in {via} (no blocking condition)", plain_allows)
        why = f"Allow matched in {via} but gated by an unevaluated Condition"
        if cond_denies:
            why = f"Allow matched in {via} but a conditional Deny might apply"
        return EvalResult(Decision.ALLOW, Confidence.POSSIBLE, why, allows + cond_denies)

    # 3) no matching Allow -> implicit deny
    return EvalResult(Decision.DENY, Confidence.CERTAIN,
                      "no matching Allow (implicit deny)", [])


def grants_admin(policy: dict) -> EvalResult:
    """Is this single policy document admin-equivalent? (`*:*`, or any admin-equivalent
    permission from the catalogue, allowed on a wildcard-ish resource.)"""
    for st in _statements([policy]):
        if st.get("Effect") != "Allow":
            continue
        actions = _as_list(st.get("Action"))
        resources = _as_list(st.get("Resource"))
        wildcard_resource = any(r == "*" or r.endswith(":*") or r.endswith("/*") for r in resources)
        for a in actions:
            for cat in ADMIN_EQUIVALENT_ACTIONS:
                # one-directional: does the GRANTED action pattern `a` cover the dangerous
                # concrete action `cat`?  ("iam:*" covers "iam:PassRole"; "s3:GetObject"
                # covers nothing dangerous)
                if _glob(a, cat, ci=True):
                    conf = Confidence.POSSIBLE if "Condition" in st else Confidence.CERTAIN
                    if not wildcard_resource:
                        conf = Confidence.POSSIBLE  # scoped resource -> weaker claim
                    return EvalResult(Decision.ALLOW, conf,
                                      f"admin-equivalent permission '{a}'", [st])
    return EvalResult(Decision.DENY, Confidence.CERTAIN, "no admin-equivalent permission", [])


def is_full_admin(policy: dict) -> bool:
    """True only for *literal* full administrator: an unconditional `Allow *` on `*`.

    Deliberately narrower than `grants_admin()`, which also fires on escalation
    *primitives* (`iam:SetDefaultPolicyVersion`, `iam:PassRole`, …). Path search needs
    the distinction: a principal that already holds `*:*` is the account's baseline, not
    a privilege-escalation finding, so it is excluded as a path source. A principal
    holding only a primitive still has to escalate — and that escalation IS the finding.
    """
    for st in _statements([policy]):
        if st.get("Effect") != "Allow" or "Condition" in st:
            continue
        # TODO v2: NotAction-based admin ("NotAction": []) is admin too; rare, deferred.
        if any(a == "*" for a in _as_list(st.get("Action"))) and \
           any(r == "*" for r in _as_list(st.get("Resource"))):
            return True
    return False
