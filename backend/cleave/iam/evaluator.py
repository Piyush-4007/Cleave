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


def _resource_matches(stmt: dict, resource: str) -> bool:
    res = _as_list(stmt.get("Resource"))
    if res:
        return any(_glob(p, resource, ci=False) for p in res)
    nres = _as_list(stmt.get("NotResource"))
    if nres:
        return not any(_glob(p, resource, ci=False) for p in nres)
    # No Resource/NotResource: valid on resource-based policies (implicitly "this resource").
    # For v1 identity-policy evaluation we treat "absent" as no match to stay conservative.
    return False


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

def is_allowed(policies: list[dict], action: str, resource: str) -> EvalResult:
    """Evaluate whether `action` on `resource` is allowed by the given policy documents."""
    stmts = list(_statements(policies))

    matching = [
        st for st in stmts
        if _action_matches(st, action) and _resource_matches(st, resource)
    ]
    denies = [st for st in matching if st.get("Effect") == "Deny"]
    allows = [st for st in matching if st.get("Effect") == "Allow"]

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
        if plain_allows and not cond_denies:
            return EvalResult(Decision.ALLOW, Confidence.CERTAIN,
                              "Allow matched (no blocking condition)", plain_allows)
        why = "Allow matched but gated by an unevaluated Condition"
        if cond_denies:
            why = "Allow matched but a conditional Deny might apply"
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
