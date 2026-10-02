"""Condition evaluation — v2 (Phase 7).

v1 treated every `Condition` as undecidable. Most are not: a static scan knows exactly
who the caller is (`aws:PrincipalArn`, `aws:username`, `aws:PrincipalAccount`), and it
knows the shape of the request the attacker would make (a direct API call over TLS, not
via an AWS service). What it cannot know is request-time state the attacker does not
choose: source IP, MFA, time of day, tags on the request.

So conditions are evaluated in THREE values:

    True     the condition holds for this caller/request          -> statement applies
    False    it provably does not                                  -> statement ignored
    UNKNOWN  it depends on a key whose value is not knowable now   -> POSSIBLE, key named

The request context is a dict of lower-cased key -> list of string values, with a
sentinel for "known to be absent". A key not in the dict at all is UNKNOWN. That split
— absent vs unknown — is the whole design: AWS gives absent keys precise semantics
(positive operators false, negated operators true, ...IfExists true, ForAllValues true,
ForAnyValue false), and an unknown key must never be silently resolved either way.

Semantics follow the IAM User Guide ("Condition operators", "Conditions with multiple
context keys or values", "Single-valued vs. multivalued context keys"):
  * operators AND together; keys within an operator AND together;
  * values for one key OR together, or NOR for negated operators;
  * `...IfExists`: true when the key is absent;
  * `Null`: "true" means the key must be absent.
"""
from __future__ import annotations
import datetime as _dt
import fnmatch
import ipaddress
import re

ABSENT = object()        # the request carries no such key (known)


class _Unknown:
    """Third truth value. Falsy, but distinct from False — test with `is UNKNOWN`."""
    def __repr__(self):
        return "UNKNOWN"

    def __bool__(self):
        return False


UNKNOWN = _Unknown()


# ---- the request context -----------------------------------------------------------

def _account_of(arn: str | None) -> str | None:
    if not arn or not arn.startswith("arn:"):
        return None
    parts = arn.split(":")
    return (parts[4] or None) if len(parts) > 4 else None


def request_context(principal: str | None, extra: dict | None = None) -> dict:
    """What a static scan knows about the attacker's request.

    Known from the identity: aws:PrincipalArn / PrincipalAccount / PrincipalType /
    username. Known from the attack model — a direct API call by the principal, made
    with an SDK — and therefore not an assumption in the attacker's favour:
      * aws:SecureTransport = true   (the attacker picks HTTPS; every SDK does)
      * aws:ViaAWSService = false, aws:PrincipalIsAWSService = false
      * aws:SourceArn / SourceAccount / SourceOwner / SourceOrgID / CalledVia ABSENT:
        those exist only when an AWS service calls on someone's behalf.
    Everything else (SourceIp, MultiFactorAuthPresent, CurrentTime, RequestedRegion,
    tags, PrincipalOrgID unless known, ...) is left out, i.e. UNKNOWN.
    `extra` overrides/adds keys (e.g. iam:PassedToService for a specific launch).
    """
    ctx: dict = {
        "aws:securetransport": ["true"],
        "aws:viaawsservice": ["false"],
        "aws:principalisawsservice": ["false"],
        "aws:sourcearn": ABSENT, "aws:sourceaccount": ABSENT, "aws:sourceowner": ABSENT,
        "aws:sourceorgid": ABSENT, "aws:sourceorgpaths": ABSENT,
        "aws:calledvia": ABSENT, "aws:calledviafirst": ABSENT, "aws:calledvialast": ABSENT,
    }
    if principal and principal.startswith("arn:"):
        ctx["aws:principalarn"] = [principal]
        acct = _account_of(principal)
        if acct:
            ctx["aws:principalaccount"] = [acct]
        resource = principal.split(":", 5)[-1]
        if resource.startswith("user/"):
            ctx["aws:principaltype"] = ["User"]
            ctx["aws:username"] = [resource.rsplit("/", 1)[-1]]
        elif resource.startswith("role/"):
            ctx["aws:principaltype"] = ["AssumedRole"]
            ctx["aws:username"] = ABSENT      # roles have no aws:username
        elif resource == "root":
            ctx["aws:principaltype"] = ["Account"]
    for k, v in (extra or {}).items():
        ctx[k.lower()] = v if v is ABSENT else [str(x) for x in (v if isinstance(v, list) else [v])]
    return ctx


# ---- policy variables --------------------------------------------------------------

_VAR = re.compile(r"\$\{([^}]*)\}")
_ESCAPES = {"*": "*", "?": "?", "$": "$"}


def substitute(text: str, ctx: dict):
    """Replace ${key} policy variables. Returns the string, ABSENT if a referenced key is
    known-absent (AWS: the element then matches nothing), or UNKNOWN."""
    if "${" not in text:
        return text
    state = {"res": None}

    def repl(m):
        body = m.group(1)
        if body in _ESCAPES:
            # escaped literal: protect it from glob interpretation
            return "[" + body + "]" if body in "*?" else body
        key, _, default = body.partition(",")
        key = key.strip().lower()
        val = ctx.get(key)
        if val is None:
            if default:
                return default.strip().strip("'\"")
            state["res"] = state["res"] or UNKNOWN
            return ""
        if val is ABSENT or not val:
            if default:
                return default.strip().strip("'\"")
            state["res"] = ABSENT
            return ""
        return val[0]

    out = _VAR.sub(repl, text)
    return state["res"] if state["res"] is not None else out


# ---- operators ---------------------------------------------------------------------

def _glob(p: str, v: str, ci: bool = False) -> bool:
    return fnmatch.fnmatchcase(v.lower(), p.lower()) if ci else fnmatch.fnmatchcase(v, p)


def _num(x):
    return float(x)


def _date(x):
    s = str(x)
    if re.fullmatch(r"\d+(\.\d+)?", s):
        return float(s)
    return _dt.datetime.fromisoformat(s.replace("Z", "+00:00")).timestamp()


def _ip(policy_val: str, req_val: str) -> bool:
    return ipaddress.ip_address(req_val) in ipaddress.ip_network(policy_val, strict=False)


# base operator -> (compare(policy_value, request_value) -> bool, negated, substitutes vars)
_OPS = {
    "StringEquals":              (lambda p, v: p == v, False, True),
    "StringNotEquals":           (lambda p, v: p == v, True, True),
    "StringEqualsIgnoreCase":    (lambda p, v: p.lower() == v.lower(), False, True),
    "StringNotEqualsIgnoreCase": (lambda p, v: p.lower() == v.lower(), True, True),
    "StringLike":                (lambda p, v: _glob(p, v), False, True),
    "StringNotLike":             (lambda p, v: _glob(p, v), True, True),
    "ArnEquals":                 (lambda p, v: _glob(p, v), False, True),
    "ArnLike":                   (lambda p, v: _glob(p, v), False, True),
    "ArnNotEquals":              (lambda p, v: _glob(p, v), True, True),
    "ArnNotLike":                (lambda p, v: _glob(p, v), True, True),
    "NumericEquals":             (lambda p, v: _num(v) == _num(p), False, False),
    "NumericNotEquals":          (lambda p, v: _num(v) == _num(p), True, False),
    "NumericLessThan":           (lambda p, v: _num(v) < _num(p), False, False),
    "NumericLessThanEquals":     (lambda p, v: _num(v) <= _num(p), False, False),
    "NumericGreaterThan":        (lambda p, v: _num(v) > _num(p), False, False),
    "NumericGreaterThanEquals":  (lambda p, v: _num(v) >= _num(p), False, False),
    "DateEquals":                (lambda p, v: _date(v) == _date(p), False, False),
    "DateNotEquals":             (lambda p, v: _date(v) == _date(p), True, False),
    "DateLessThan":              (lambda p, v: _date(v) < _date(p), False, False),
    "DateLessThanEquals":        (lambda p, v: _date(v) <= _date(p), False, False),
    "DateGreaterThan":           (lambda p, v: _date(v) > _date(p), False, False),
    "DateGreaterThanEquals":     (lambda p, v: _date(v) >= _date(p), False, False),
    "Bool":                      (lambda p, v: p.lower() == v.lower(), False, False),
    "BinaryEquals":              (lambda p, v: p == v, False, False),
    "IpAddress":                 (_ip, False, False),
    "NotIpAddress":              (_ip, True, False),
}


def _as_list(v):
    if v is None:
        return []
    return v if isinstance(v, list) else [v]


def _key_result(op: str, key: str, policy_vals: list, ctx: dict):
    """Evaluate one (operator, key, values) triple -> True / False / UNKNOWN."""
    qualifier = None
    if ":" in op:
        qualifier, op = op.split(":", 1)
        if qualifier not in ("ForAllValues", "ForAnyValue"):
            return UNKNOWN
    if_exists = op.endswith("IfExists")
    base = op[:-len("IfExists")] if if_exists else op
    req = ctx.get(key.lower())

    if base == "Null":
        if req is None:
            return UNKNOWN
        want_absent = [str(p).lower() == "true" for p in policy_vals]
        is_absent = req is ABSENT or not req
        return any(w == is_absent for w in want_absent)

    spec = _OPS.get(base)
    if spec is None:
        return UNKNOWN                      # an operator we do not implement: never guess
    compare, negated, subs = spec

    if req is None:
        return UNKNOWN
    if req is ABSENT or not req:
        if qualifier == "ForAllValues":
            return True                      # vacuous: no values to fail
        if qualifier == "ForAnyValue":
            return False
        if if_exists:
            return True
        return negated                       # positive -> False, negated -> True

    # resolve policy-side variables (String/Arn operators only)
    pvals = []
    for p in policy_vals:
        p = str(p).lower() if isinstance(p, bool) else str(p)
        if subs:
            p = substitute(p, ctx)
            if p is UNKNOWN:
                return UNKNOWN
            if p is ABSENT:
                continue                     # this value can match nothing
        pvals.append(p)

    def matches_one(v: str):
        try:
            return any(compare(p, v) for p in pvals)
        except (ValueError, TypeError):
            return UNKNOWN

    per_value = [matches_one(v) for v in req]
    if any(r is UNKNOWN for r in per_value):
        return UNKNOWN
    if qualifier == "ForAllValues":
        return all((not r) if negated else r for r in per_value)
    if qualifier == "ForAnyValue":
        return any((not r) if negated else r for r in per_value)
    # single-valued key: OR of values, NOR for negated operators
    hit = any(per_value)
    return (not hit) if negated else hit


def evaluate(condition: dict | None, ctx: dict) -> tuple[object, list[str]]:
    """Evaluate a statement's Condition block.

    Returns (result, unknown_keys): result is True / False / UNKNOWN, and unknown_keys
    names every key that kept it from being decided (the evidence text uses them)."""
    if not condition:
        return True, []
    if not isinstance(condition, dict):
        return UNKNOWN, ["<malformed Condition>"]
    unknown: list[str] = []
    for op, block in condition.items():
        if not isinstance(block, dict):
            return UNKNOWN, [f"<malformed {op}>"]
        for key, vals in block.items():
            r = _key_result(op, key, _as_list(vals), ctx)
            if r is False:
                return False, []             # AND: one known-false key decides it
            if r is UNKNOWN:
                base = op.split(":")[-1]
                base = base[:-len("IfExists")] if base.endswith("IfExists") else base
                supported = base in _OPS or base == "Null"
                unknown.append(key if supported else f"{key} (unsupported operator {op})")
    return (UNKNOWN, unknown) if unknown else (True, [])
