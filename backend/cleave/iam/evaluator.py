"""IAM policy evaluator — v2 (Phase 7: v1 + more stages, not a rewrite).

Answers `is_allowed(policies, action, resource)` with a decision + confidence, and
`grants_admin(policy)`. Deliberately conservative: anything it cannot decide statically
becomes POSSIBLE, never a silent allow or deny.

v1 scope (handbook): explicit Deny, identity policies, wildcard action/resource expansion,
NotAction/NotResource, and conditions treated as "undecidable -> POSSIBLE".
v2 adds, stage by stage:
  * Conditions evaluated three-valued against a request context (iam/conditions.py):
    decidable keys (who the caller is, what a direct SDK call carries) give CERTAIN or
    DENY; request-time keys (SourceIp, MFA, time, tags) stay POSSIBLE and are NAMED in
    the reason. Policy variables (${aws:username}) are substituted in Resource too.
  * Guardrails: permissions boundaries and SCPs. Neither ever grants; each must ALSO
    allow. A boundary caps identity grants and grants to a role ARN, not grants that a
    resource policy makes to a user ARN. SCPs need an Allow at every level of the
    organization hierarchy and cap everything the account's principals do.
Remaining `# TODO v2` markers are the stages still to come.
"""
from __future__ import annotations
import fnmatch
from dataclasses import dataclass, field
from enum import Enum
from .catalogue import ADMIN_EQUIVALENT_ACTIONS
from . import conditions as cond


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
    unknown_keys: list = field(default_factory=list)  # condition keys that kept it POSSIBLE

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


def _any_pattern(patterns: list, resource: str, ctx: dict | None):
    """Does any pattern match? Policy variables are substituted first: a known-absent
    variable makes that pattern match nothing (AWS), an unknown one makes it UNKNOWN."""
    unknown = False
    for p in patterns:
        if ctx is not None and "${" in p:
            p = cond.substitute(p, ctx)
            if p is cond.UNKNOWN:
                unknown = True
                continue
            if p is cond.ABSENT:
                continue
        if _glob(p, resource, ci=False):
            return True
    return cond.UNKNOWN if unknown else False


def _resource_matches(stmt: dict, resource: str, resource_policy: bool = False,
                      ctx: dict | None = None):
    """True / False / UNKNOWN (UNKNOWN only when a policy variable is unresolvable)."""
    res = _as_list(stmt.get("Resource"))
    if res:
        return _any_pattern(res, resource, ctx)
    nres = _as_list(stmt.get("NotResource"))
    if nres:
        hit = _any_pattern(nres, resource, ctx)
        return cond.UNKNOWN if hit is cond.UNKNOWN else not hit
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

def _applies(st: dict, resource: str, ctx: dict, resource_policy: bool = False):
    """Does a statement (whose Action already matched) apply to this request?
    -> (True | False | UNKNOWN, unknown_keys)."""
    rm = _resource_matches(st, resource, resource_policy, ctx)
    if rm is False:
        return False, []
    c, keys = cond.evaluate(st.get("Condition"), ctx)
    if c is False:
        return False, []
    if rm is cond.UNKNOWN:
        keys = keys + ["<policy variable in Resource>"]
    if rm is cond.UNKNOWN or c is cond.UNKNOWN:
        return cond.UNKNOWN, keys
    return True, []


def _keys_text(keys: list[str]) -> str:
    uniq = list(dict.fromkeys(keys))
    return ", ".join(uniq[:4]) + (" ..." if len(uniq) > 4 else "")


UNREADABLE = "unknown"   # a boundary/SCP set exists but its documents could not be read


def _guardrail(docs: list[dict], action: str, resource: str, ctx: dict):
    """Evaluate one guardrail layer (a boundary, or one SCP hierarchy level).
    -> ("deny" | True | False | UNKNOWN, unknown_keys). Never grants; True only means
    'this layer does not stand in the way'."""
    allow, maybe, keys = False, False, []
    for st in _statements(docs):
        if not _action_matches(st, action):
            continue
        ap, k = _applies(st, resource, ctx)
        if ap is False:
            continue
        if st.get("Effect") == "Deny":
            if ap is True:
                return "deny", []
            maybe, keys = True, keys + k
        elif st.get("Effect") == "Allow":
            if ap is True:
                allow = True
            else:
                maybe, keys = True, keys + k
    if allow and not maybe:
        return True, []
    if allow or maybe:
        return cond.UNKNOWN, keys
    return False, []


def is_allowed(policies: list[dict], action: str, resource: str,
               resource_policy: dict | None = None,
               principal: str | None = None,
               context: dict | None = None,
               boundary=None, scps=None) -> EvalResult:
    """Evaluate whether `action` on `resource` is allowed.

    `policies` are the identity policy documents in force for the caller. Pass
    `resource_policy` (a bucket policy, key policy, secret policy, …) and `principal`
    (the caller's ARN) to include the resource-based side of the decision. `context`
    adds request-context keys (e.g. {"iam:PassedToService": "ec2.amazonaws.com"}) on
    top of what is derived from the principal (see conditions.request_context).

    Guardrails (v2): `boundary` is the principal's permissions-boundary document (a dict,
    a list of dicts, or UNREADABLE); `scps` is the SCP hierarchy that applies to the
    account, one list of documents per level (root, OUs, account), or UNREADABLE. None
    means "no such guardrail" (not in an organization / no boundary attached).

    Same-account semantics: an Allow in *either* the identity policy or the resource
    policy is sufficient, and an explicit Deny in either wins. That is what AWS does
    within one account, which is the model Cleave uses (handbook: single account, two
    roles).
    KMS is handled separately (is_allowed_kms): its key policy is authoritative. Here the
    same-account union stands for S3/Secrets/etc. Cross-account resource-policy grants for
    those services are not modelled (role assumption across accounts is, in
    graph/evaluated.py assume_role_edges); this stays the v1 posture of over-reporting
    same-account access rather than silently hiding a path.
    """
    ctx = cond.request_context(principal, context)

    # (statement, applies, unknown_keys, side, principal-kind)
    considered: list[tuple[dict, object, list, str, str]] = []
    for st in _statements(policies):
        if _action_matches(st, action):
            ap, keys = _applies(st, resource, ctx)
            if ap is not False:
                considered.append((st, ap, keys, "identity", "explicit"))

    # The resource-based side also has to name us.
    account = _account_of(principal) or _account_of(resource)
    if resource_policy:
        for st in _statements([resource_policy]):
            if not _action_matches(st, action):
                continue
            kind = _principal_match_kind(st, principal, account)
            if not kind:
                continue
            ap, keys = _applies(st, resource, ctx, resource_policy=True)
            if ap is not False:
                considered.append((st, ap, keys, "resource", kind))

    def eff(x):
        return x[0].get("Effect")

    # ---- guardrails: evaluate each layer once ----
    guard_keys: list[str] = []
    guard_maybe = False
    scp_state = True
    if scps == UNREADABLE:
        scp_state, guard_keys = cond.UNKNOWN, ["<SCPs unreadable>"]
    elif scps:
        for i, level in enumerate(scps):
            st_, k = _guardrail(_as_list(level), action, resource, ctx)
            if st_ == "deny":
                return EvalResult(Decision.DENY, Confidence.CERTAIN,
                                  f"explicit Deny in a service control policy (level {i})", [])
            if st_ is False:
                return EvalResult(Decision.DENY, Confidence.CERTAIN,
                                  f"no service control policy Allow at level {i} "
                                  "(SCPs must allow at every level)", [])
            if st_ is cond.UNKNOWN:
                scp_state, guard_keys = cond.UNKNOWN, guard_keys + k
    if scp_state is cond.UNKNOWN:
        guard_maybe = True

    bnd_state = True
    if boundary == UNREADABLE:
        bnd_state, bnd_keys = cond.UNKNOWN, ["<permissions boundary unreadable>"]
    elif boundary:
        bnd_state, bnd_keys = _guardrail(_as_list(boundary), action, resource, ctx)
        if bnd_state == "deny":
            return EvalResult(Decision.DENY, Confidence.CERTAIN,
                              "explicit Deny in the permissions boundary", [])
    else:
        bnd_keys = []
    is_user = bool(principal) and ":user/" in principal

    def capped_by_boundary(x) -> bool:
        """Does the boundary limit this grant? Identity grants always; resource-policy
        grants only when they name a role (a user ARN grant escapes the boundary)."""
        return x[3] == "identity" or not is_user

    denies = [x for x in considered if eff(x) == "Deny"]
    identity_allows = [x for x in considered if eff(x) == "Allow" and x[3] == "identity"]
    # A "delegated" resource Allow (Principal = account root) grants nothing the identity
    # policy does not already grant, so it is never an independent Allow.
    resource_allows = [x for x in considered
                       if eff(x) == "Allow" and x[3] == "resource" and x[4] == "explicit"]

    # 1) explicit Deny that provably applies -> hard block (Certain).
    hard_denies = [x[0] for x in denies if x[1] is True]
    if hard_denies:
        return EvalResult(Decision.DENY, Confidence.CERTAIN,
                          "explicit Deny matched (its conditions hold)", hard_denies)

    # Boundary: a grant it caps survives only if the boundary allows too.
    if bnd_state is False:
        identity_allows = [x for x in identity_allows if not capped_by_boundary(x)]
        resource_allows = [x for x in resource_allows if not capped_by_boundary(x)]
    allows = identity_allows + resource_allows
    if not allows and bnd_state is False and any(eff(x) == "Allow" for x in considered):
        return EvalResult(Decision.DENY, Confidence.CERTAIN,
                          "allowed by policy but outside the permissions boundary", [])

    # 2) Allow?
    if allows:
        # A Deny whose conditions are undecidable *might* block -> can't be Certain.
        # (Do not hard-block: that could hide a real path — we over-report instead.)
        maybe_denies = [x for x in denies if x[1] is cond.UNKNOWN]
        sure_allows = [x for x in allows if x[1] is True
                       and not (bnd_state is cond.UNKNOWN and capped_by_boundary(x))]
        via = ("the resource policy" if resource_allows and not identity_allows
               else "an identity policy")
        if sure_allows and not maybe_denies and not guard_maybe:
            return EvalResult(Decision.ALLOW, Confidence.CERTAIN,
                              f"Allow matched in {via} (conditions, if any, hold)",
                              [x[0] for x in sure_allows])
        # POSSIBLE: name every key that kept it open (conditions, boundary, SCPs).
        keys = [k for x in maybe_denies + allows for k in x[2]]
        keys += bnd_keys if bnd_state is cond.UNKNOWN else []
        keys += guard_keys if guard_maybe else []
        why = (f"Allow matched in {via}"
               + (" but a Deny may apply" if maybe_denies else "")
               + f"; depends on {_keys_text(keys)}")
        return EvalResult(Decision.ALLOW, Confidence.POSSIBLE, why,
                          [x[0] for x in allows + maybe_denies], list(dict.fromkeys(keys)))

    # 3) no matching Allow -> implicit deny
    return EvalResult(Decision.DENY, Confidence.CERTAIN,
                      "no matching Allow (implicit deny)", [])


def is_allowed_kms(policies: list[dict], action: str, resource: str,
                   key_policy: dict | None, principal: str | None = None,
                   context: dict | None = None, boundary=None, scps=None) -> EvalResult:
    """KMS key-policy precedence (Phase 7 stage 5).

    A KMS key is the one resource where the resource policy is authoritative: an identity
    policy can act on the key ONLY IF the key policy enables IAM for it (an Allow to the
    account root), or the key policy names the principal directly. This is unlike S3 or
    Secrets Manager, where an identity Allow is sufficient on its own — so KMS gets its
    own entry point rather than the `resource_policy=` same-account union in is_allowed().
    (KMS grants, the CreateGrant mechanism, are dynamic runtime state a read-only scan
    does not see; they are out of scope and noted, not guessed.)
    """
    ctx = cond.request_context(principal, context)
    account = _account_of(principal) or _account_of(resource)

    def identity():
        return is_allowed(policies, action, resource, principal=principal,
                          context=context, boundary=boundary, scps=scps)

    if not key_policy:
        # key policy unreadable: cannot confirm IAM is enabled on the key -> at most Possible
        ident = identity()
        if ident.decision is Decision.ALLOW:
            return EvalResult(Decision.ALLOW, Confidence.POSSIBLE,
                              "identity policy allows, but the key policy could not be read "
                              "so IAM-enablement on the key is unknown", ident.matched,
                              ["<key policy unreadable>"])
        return ident  # no identity grant -> denied regardless of the key policy

    deny, explicit, delegated = [], [], []   # each collects statement `applies` values
    for st in _statements([key_policy]):
        if not _action_matches(st, action):
            continue
        kind = _principal_match_kind(st, principal, account)
        if not kind:
            continue
        ap, _keys = _applies(st, resource, ctx, resource_policy=True)
        if ap is False:
            continue
        if st.get("Effect") == "Deny":
            deny.append(ap)
        elif kind == "explicit":
            explicit.append(ap)
        elif kind == "delegated":
            delegated.append(ap)

    if any(a is True for a in deny):
        return EvalResult(Decision.DENY, Confidence.CERTAIN,
                          "explicit Deny in the KMS key policy", [])
    maybe_deny = any(a is cond.UNKNOWN for a in deny)

    if any(a is True for a in explicit):
        conf = Confidence.POSSIBLE if maybe_deny else Confidence.CERTAIN
        return EvalResult(Decision.ALLOW, conf,
                          "the KMS key policy grants this principal directly", [])

    if any(a in (True, cond.UNKNOWN) for a in delegated):
        ident = identity()
        if ident.decision is Decision.ALLOW:
            certain = (ident.confidence is Confidence.CERTAIN
                       and all(a is True for a in delegated) and not maybe_deny)
            return EvalResult(Decision.ALLOW,
                              Confidence.CERTAIN if certain else Confidence.POSSIBLE,
                              "the key policy delegates to IAM (Allow to the account root) "
                              "and the identity policy allows the action", ident.matched,
                              ident.unknown_keys)
        return EvalResult(Decision.DENY, Confidence.CERTAIN,
                          "the key policy delegates to IAM but no identity policy allows "
                          "the action", [])

    if any(a is cond.UNKNOWN for a in explicit):
        return EvalResult(Decision.ALLOW, Confidence.POSSIBLE,
                          "the KMS key policy may grant this principal (an unevaluated "
                          "condition)", [])

    return EvalResult(Decision.DENY, Confidence.CERTAIN,
                      "the KMS key policy neither names this principal nor delegates to "
                      "IAM; an identity policy cannot grant access to the key", [])


def grants_admin(policy: dict) -> EvalResult:
    """Is this single policy document admin-equivalent? (`*:*`, or any admin-equivalent
    permission from the catalogue, allowed on a wildcard-ish resource.)"""
    ctx = cond.request_context(None)
    for st in _statements([policy]):
        if st.get("Effect") != "Allow":
            continue
        held, _keys = cond.evaluate(st.get("Condition"), ctx)
        if held is False:
            continue  # e.g. gated on aws:SourceAccount: never true for a direct call
        actions = _as_list(st.get("Action"))
        resources = _as_list(st.get("Resource"))
        wildcard_resource = any(r == "*" or r.endswith(":*") or r.endswith("/*") for r in resources)
        for a in actions:
            for cat in ADMIN_EQUIVALENT_ACTIONS:
                # one-directional: does the GRANTED action pattern `a` cover the dangerous
                # concrete action `cat`?  ("iam:*" covers "iam:PassRole"; "s3:GetObject"
                # covers nothing dangerous)
                if _glob(a, cat, ci=True):
                    conf = Confidence.CERTAIN if held is True else Confidence.POSSIBLE
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
    ctx = cond.request_context(None)
    for st in _statements([policy]):
        if st.get("Effect") != "Allow" or cond.evaluate(st.get("Condition"), ctx)[0] is not True:
            continue
        # TODO v2: NotAction-based admin ("NotAction": []) is admin too; rare, deferred.
        if any(a == "*" for a in _as_list(st.get("Action"))) and \
           any(r == "*" for r in _as_list(st.get("Resource"))):
            return True
    return False
