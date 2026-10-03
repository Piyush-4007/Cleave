"""Evaluated edges (Phase 3) — the *dangerous* half of the graph.

Uses the IAM evaluator + reachability engine to materialise the escalation edges we
committed to in the design (Option A): GRANTS_ADMIN, CAN_PASS_ROLE, CAN_LAUNCH_AS, and
CAN_REACH. Generic CAN_READ/CAN_WRITE are evaluated lazily during path search (Phase 4),
not materialised here.

Pure transform over normalised records — no AWS calls.
"""
from __future__ import annotations
import fnmatch
from ..iam.evaluator import is_allowed, grants_admin, is_full_admin, Decision
from ..iam import conditions as cond
from ..iam.evaluator import _account_of
from ..iam.guardrails import ORG_ID, boundary_below_full_admin, guardrails, scp_levels
from ..iam.catalogue import (ADMIN_EQUIVALENT_ACTIONS, POLICY_VERSION_ACTIONS,
                             LAUNCH_SERVICES, TAKEOVER_ACTIONS)
from ..reachability.engine import compute_reach
from ..credscan import credential_edges


def _edge(frm, to, rel, reason, evidence, confidence, by="iam.evaluator.v2", **extra):
    return {"frm": frm, "to": to, "rel": rel, "props": {
        "reason": reason, "evidence": evidence,
        "confidence": confidence, "discovered_by": by, **extra}}


def _customer_managed(arn: str) -> bool:
    """A customer-managed policy ARN — versionable by its own account. AWS-managed
    policies (`arn:aws:iam::aws:policy/...`) are immutable, so they are excluded."""
    return ":policy/" in arn and ":iam::aws:policy/" not in arn


def _doc_holders(records: list[dict], groups_by_name: dict) -> dict:
    """policy-document uid -> [principal records that hold it], for inline and attached
    managed docs (directly or inherited from a group). Used to ask, per granting document,
    whether any holder has an attached customer-managed policy to version."""
    holders: dict[str, list[dict]] = {}
    for pr in (r for r in records if r["_type"] in ("IamUser", "IamRole")):
        seen: list[tuple[str, dict]] = []
        for pname in (pr.get("InlinePolicies") or {}):
            seen.append((f"{pr['_id']}#inline/{pname}", pr))
        carriers = [pr] + [groups_by_name[g] for g in pr.get("Groups", [])
                           if g in groups_by_name]
        for h in carriers:
            if h is not pr:
                for pname in (h.get("InlinePolicies") or {}):
                    seen.append((f"{h['_id']}#inline/{pname}", pr))
            for arn in (h.get("AttachedPolicies") or []):
                seen.append((arn, pr))
        for uid, p in seen:
            holders.setdefault(uid, []).append(p)
    return holders


def _attached_customer_managed(pr: dict, groups_by_name: dict, policy_docs: dict) -> list[str]:
    """Customer-managed policy ARNs attached to a principal (directly or via a group) that
    have a readable document — i.e. the policies this principal could version into admin."""
    arns = list(pr.get("AttachedPolicies") or [])
    for g in pr.get("Groups", []):
        grp = groups_by_name.get(g)
        if grp:
            arns += grp.get("AttachedPolicies") or []
    return [a for a in arns if _customer_managed(a) and policy_docs.get(a) is not None]


def policy_documents(records: list[dict]):
    """Every policy document in the account, keyed by the node uid the loader gives it.

    Managed policies are their own records; inline policies are a dict hanging off the
    identity, and the loader materialises them as `<identity_arn>#inline/<name>` nodes —
    so they must be enumerated here too or an inline admin policy has no GRANTS_ADMIN
    edge and the path through it silently disappears.
    """
    for r in records:
        if r["_type"] == "IamPolicy" and r.get("Document"):
            yield r["_id"], r["Document"], f"{r['_id']}#Document"
        elif r["_type"] in ("IamUser", "IamRole", "IamGroup"):
            for pname, doc in (r.get("InlinePolicies") or {}).items():
                if doc:
                    yield (f"{r['_id']}#inline/{pname}", doc,
                           f"{r['_id']}#InlinePolicies/{pname}")


def trust_principals(role: dict) -> tuple[set[str], bool]:
    """Who a role's trust policy lets assume it: (service principals, anyone_else).

    `anyone_else` is True when an Allow names an AWS/Federated/`*` principal, i.e. some
    identity (not only an AWS service) can obtain the role's credentials. This coarse
    read feeds role_source_note (is a role a plausible compromised starting point?), where
    over-reporting is intended; the precise, condition-aware edges are assume_role_edges.
    """
    services: set[str] = set()
    others = False
    stmts = (role.get("TrustPolicy") or {}).get("Statement", [])
    for st in ([stmts] if isinstance(stmts, dict) else stmts or []):
        if not isinstance(st, dict) or st.get("Effect") != "Allow":
            continue
        pr = st.get("Principal")
        if pr == "*":
            others = True
            continue
        for kind, val in (pr or {}).items():
            vals = val if isinstance(val, list) else [val]
            if kind == "Service":
                services.update(str(v).lower() for v in vals)
            else:
                others = True
    return services, others


def _stmts(doc):
    st = (doc or {}).get("Statement", [])
    return [st] if isinstance(st, dict) else [x for x in st or [] if isinstance(x, dict)]


def _could_allow(docs: list[dict], action: str) -> bool:
    """Cheap prefilter: does any Allow statement name this action at all (or use
    NotAction)? Saves an is_allowed() per (attacker, target) pair on big accounts."""
    for d in docs:
        for st in _stmts(d):
            if st.get("Effect") != "Allow":
                continue
            if "NotAction" in st:
                return True
            acts = st.get("Action")
            acts = acts if isinstance(acts, list) else [acts]
            if any(fnmatch.fnmatchcase(action.lower(), str(a).lower()) for a in acts):
                return True
    return False


def _worst(*buckets: str) -> str:
    return "Possible" if "Possible" in buckets else "Certain"


def takeover_edges(records: list[dict], principals: list[dict], eff_docs,
                   guard_of=lambda pr, docs: {}) -> list[dict]:
    """CAN_TAKE_OVER / CAN_JOIN_GROUP / CAN_REWRITE_TRUST -- become a specific principal.

    The edge only says "you can become X"; whether that is admin is decided by X's own
    edges downstream, exactly as CAN_LAUNCH_AS does for PassRole. Each edge also checks the
    AWS precondition that makes the call actually work:
      * CreateAccessKey: a user holds at most two keys; with two, you must delete one.
      * Create/UpdateLoginProfile: Create needs no password yet, Update needs one, and a
        user with MFA cannot be entered with a password alone (credential report).
      * AddUserToGroup: you can only add yourself if you are a user.
      * UpdateAssumeRolePolicy: service-linked roles are immutable; once the trust names
        you, same-account AssumeRole needs no identity grant -- unless explicitly denied.
    """
    users = [r for r in records if r["_type"] == "IamUser"]
    groups = [r for r in records if r["_type"] == "IamGroup"]
    roles = [r for r in records if r["_type"] == "IamRole"]
    report = next((r for r in records if r["_type"] == "IamCredentialReport"), None)
    login = {row.get("arn"): row for row in (report or {}).get("Rows") or [] if row.get("arn")}
    user_actions = {"iam:CreateAccessKey", "iam:CreateLoginProfile", "iam:UpdateLoginProfile"}
    out: list[dict] = []

    for pr in principals:
        docs = eff_docs(pr)
        if not docs:
            continue
        guard = guard_of(pr, docs)
        if any(is_full_admin(d) for d in docs) and not boundary_below_full_admin(pr, guard):
            continue  # an admin has already won: becoming someone else is no new step
        me = pr["_id"]
        held = {a for a in TAKEOVER_ACTIONS if _could_allow(docs, a)}
        if not held:
            continue
        ev = f"{me}#effective-policies"

        def ask(action, target):
            return is_allowed(docs, action, target, principal=me, **guard)

        # -- users: mint a key, or set/reset the console password
        for u in (users if held & user_actions else []):
            uid = u["_id"]
            if uid == me:
                continue
            routes: list[tuple[str, str]] = []   # (bucket, method)
            if "iam:CreateAccessKey" in held:
                ck = ask("iam:CreateAccessKey", uid)
                if ck.decision is Decision.ALLOW:
                    keys = u.get("AccessKeys")
                    if keys is not None and len(keys) >= 2:
                        dk = ask("iam:DeleteAccessKey", uid)
                        if dk.decision is Decision.ALLOW:
                            routes.append((_worst(ck.bucket, dk.bucket),
                                           "iam:DeleteAccessKey + iam:CreateAccessKey "
                                           "(user already has two keys)"))
                    else:
                        routes.append((ck.bucket, "iam:CreateAccessKey (mint a new key)"))
            row = login.get(uid)
            if row is not None:
                if str(row.get("mfa_active")).lower() != "true":
                    has_pw = str(row.get("password_enabled")).lower() == "true"
                    act = "iam:UpdateLoginProfile" if has_pw else "iam:CreateLoginProfile"
                    if act in held:
                        r = ask(act, uid)
                        if r.decision is Decision.ALLOW:
                            routes.append((r.bucket, f"{act} (set the console password; "
                                                     "no MFA on the user)"))
            else:
                # no credential report: which call works (and whether MFA blocks the
                # console) is unknown -> at most Possible
                lp = [a for a in ("iam:CreateLoginProfile", "iam:UpdateLoginProfile")
                      if a in held and ask(a, uid).decision is Decision.ALLOW]
                if lp:
                    routes.append(("Possible", f"{' / '.join(lp)} (console password; "
                                               "login state and MFA unknown)"))
            if routes:
                bucket, method = min(routes, key=lambda r: r[0] != "Certain")
                out.append(_edge(me, uid, "CAN_TAKE_OVER",
                                 f"can take over the user via {method}",
                                 f"{ev};{uid}#AccessKeys", bucket, method=method))

        # -- groups: a user can add itself to a group and inherit its policies
        if "iam:AddUserToGroup" in held and pr["_type"] == "IamUser":
            mine = set(pr.get("Groups") or [])
            for gr in groups:
                if gr.get("GroupName") in mine:
                    continue
                r = ask("iam:AddUserToGroup", gr["_id"])
                if r.decision is Decision.ALLOW:
                    out.append(_edge(me, gr["_id"], "CAN_JOIN_GROUP",
                                     "can add itself to the group (iam:AddUserToGroup) and "
                                     "inherit its policies", ev, r.bucket))

        # -- roles: rewrite the trust policy to name yourself, then assume it
        if "iam:UpdateAssumeRolePolicy" in held:
            for role in roles:
                rid = role["_id"]
                if rid == me or "/aws-service-role/" in rid:
                    continue
                r = ask("iam:UpdateAssumeRolePolicy", rid)
                if r.decision is not Decision.ALLOW:
                    continue
                assume = ask("sts:AssumeRole", rid)
                if assume.decision is Decision.DENY and assume.matched:
                    continue  # explicitly denied from assuming it afterwards
                out.append(_edge(me, rid, "CAN_REWRITE_TRUST",
                                 "can rewrite the role's trust policy to trust itself "
                                 "(iam:UpdateAssumeRolePolicy), then assume it",
                                 f"{ev};{rid}#TrustPolicy", r.bucket))
    return out


def _trust_statements(role: dict):
    """Yield (aws_principal_values, is_wildcard, condition) for each Allow statement in a
    role's trust policy. Service- and Federated-only statements yield no AWS values (they
    are handled elsewhere: Service by launch/workload logic, Federated by IRSA sources)."""
    stmts = (role.get("TrustPolicy") or {}).get("Statement", [])
    for st in ([stmts] if isinstance(stmts, dict) else stmts or []):
        if not isinstance(st, dict) or st.get("Effect") != "Allow":
            continue
        if "sts:AssumeRole" not in {a for a in (st.get("Action") if isinstance(st.get("Action"), list)
                                                else [st.get("Action")]) if a}:
            # AssumeRoleWithSAML/WithWebIdentity are federation, not a principal-to-role edge
            if st.get("Action") not in ("sts:AssumeRole", "sts:*", "*"):
                continue
        pr = st.get("Principal")
        if pr == "*":
            yield [], True, st.get("Condition")
            continue
        if not isinstance(pr, dict):
            continue
        aws = pr.get("AWS")
        vals = [str(v) for v in (aws if isinstance(aws, list) else [aws]) if aws is not None]
        wildcard = "*" in vals
        yield [v for v in vals if v != "*"], wildcard, st.get("Condition")


def _norm_account_principal(pv: str) -> str:
    """A Principal "AWS" value of a bare account id means that account's root."""
    return f"arn:aws:iam::{pv}:root" if pv.isdigit() and len(pv) == 12 else pv


def _is_account_root(pv: str) -> str | None:
    """The account id, if pv is an account-root principal (delegates to the whole account)."""
    if pv.endswith(":root"):
        return _account_of(pv)
    return None


def _trust_bucket(condition, principal: str | None) -> str | None:
    """Evaluate a trust Condition for a candidate assumer. Returns the confidence bucket
    ("Certain"/"Possible") or None when the condition is decidably false. With principal
    None (a `*` or cross-account assumer we cannot identify), principal-specific keys are
    unknown, so a restrictive condition stays Possible rather than being dropped."""
    held, _keys = cond.evaluate(condition, cond.request_context(principal))
    if held is False:
        return None
    return "Certain" if held is True else "Possible"


def assume_role_edges(records, principals, roles, eff_docs, guard_of) -> list[dict]:
    """CAN_ASSUME, condition-aware (Phase 7 stage 4). Replaces the v1 structural edge.

    Three shapes, from a role's trust policy:
      * trust names a specific principal ARN (same account): the trust is sufficient on
        its own -- no identity grant needed -- so CAN_ASSUME from that principal.
      * trust names the account root (or a bare account id = that account's root): this
        DELEGATES to the account. A principal can assume only if its OWN identity policy
        also allows sts:AssumeRole on the role. v1 drew the edge from a dead "...:root"
        node instead, so these same-account paths were invisible.
      * trust names `*` or another account's root/principal: an external entry point. The
        edge is drawn from that principal node; find_sources marks it EXTERNAL.
    Trust Conditions are evaluated per candidate assumer; an unknowable one (sts:ExternalId,
    aws:SourceIp, ...) keeps the edge but only Possible.
    """
    local_accounts = {_account_of(p["_id"]) for p in principals} | {
        _account_of(r["_id"]) for r in roles}
    local_accounts.discard(None)
    by_id = {p["_id"]: p for p in principals}
    out: list[dict] = []

    for role in roles:
        rid = role["_id"]
        for values, wildcard, condition in _trust_statements(role):
            if wildcard:
                b = _trust_bucket(condition, None)
                if b:
                    out.append(_edge("*", rid, "CAN_ASSUME",
                                     "role trust policy allows Principal '*' (anyone)",
                                     f"{rid}#TrustPolicy", b))
            for pv in values:
                pv = _norm_account_principal(pv)
                root_acct = _is_account_root(pv)
                if root_acct and root_acct in local_accounts:
                    # same-account delegation: resolve to principals that also hold the grant
                    for pr in principals:
                        if pr["_id"] == rid:
                            continue
                        tb = _trust_bucket(condition, pr["_id"])
                        if tb is None:
                            continue
                        docs = eff_docs(pr)
                        if not docs:
                            continue
                        res = is_allowed(docs, "sts:AssumeRole", rid, principal=pr["_id"],
                                         **guard_of(pr, docs))
                        if res.decision is not Decision.ALLOW:
                            continue
                        conf = "Possible" if "Possible" in (tb, res.bucket) else "Certain"
                        out.append(_edge(pr["_id"], rid, "CAN_ASSUME",
                                         "role trusts the account; this identity holds "
                                         "sts:AssumeRole on it", f"{rid}#TrustPolicy;"
                                         f"{pr['_id']}#effective-policies", conf))
                    continue
                # a specific principal (same account: trust alone suffices; cross account:
                # external foothold). Either way the edge is from that principal.
                acct = _account_of(pv)
                if acct in local_accounts and pv in by_id:
                    tb = _trust_bucket(condition, pv)
                    if tb:
                        out.append(_edge(pv, rid, "CAN_ASSUME",
                                         "role trust policy names this principal directly",
                                         f"{rid}#TrustPolicy", tb))
                elif acct and acct not in local_accounts:
                    tb = _trust_bucket(condition, None)
                    if tb:
                        out.append(_edge(pv, rid, "CAN_ASSUME",
                                         "role trust policy names a principal in another "
                                         f"account ({acct})", f"{rid}#TrustPolicy", tb))
    return out


def compute_evaluated_edges(records: list[dict], cred_findings: list[dict] = ()) -> list[dict]:
    policy_docs = {r["_id"]: r.get("Document")
                   for r in records if r["_type"] == "IamPolicy"}
    groups_by_name = {r["GroupName"]: r for r in records if r["_type"] == "IamGroup"}
    roles = [r for r in records if r["_type"] == "IamRole"]
    principals = [r for r in records if r["_type"] in ("IamUser", "IamRole")]
    edges: list[dict] = []

    # ---- GRANTS_ADMIN (policy -> Admin sink) ----
    # `full_admin` separates literal `*:*` from an escalation primitive. Path search uses
    # it to decide who is already admin (baseline) vs who has to escalate (the finding).
    # Phase 7: in an AWS Organization member account, SCPs cap every principal, so a
    # policy is admin-equivalent only if an admin-equivalent action survives them.
    org = next((r for r in records if r["_id"] == ORG_ID), None)
    account_scps = scp_levels(org, "arn:aws:iam::0:user/any")
    for uid, doc, evidence in policy_documents(records):
        res = grants_admin(doc)
        if res.decision is not Decision.ALLOW:
            continue
        bucket, reason = res.bucket, res.reason
        if account_scps:
            surviving = [r for r in (is_allowed([doc], a, "*", scps=account_scps)
                                     for a in sorted(ADMIN_EQUIVALENT_ACTIONS))
                         if r.decision is Decision.ALLOW]
            if not surviving:
                continue  # every admin-equivalent grant is blocked by an SCP
            if all(r.bucket != "Certain" for r in surviving):
                bucket, reason = "Possible", f"{reason}; an SCP may restrict it"
        edges.append(_edge(uid, "admin", "GRANTS_ADMIN", reason, evidence,
                           bucket, full_admin=is_full_admin(doc)))

    # ---- CreatePolicyVersion / SetDefaultPolicyVersion -> admin (holder-conditional) ----
    # A document granting one of these is admin-equivalent only for a HOLDER who has an
    # attached customer-managed policy (covered by the grant) to rewrite into admin -- an
    # inline-only holder cannot (inline policies have no versions), and AWS-managed policies
    # are immutable. So, unlike the sufficient-alone primitives above, draw the doc->admin
    # edge only when some holder of the document has such a policy. These are never full
    # admin (full_admin=False): the holder still has to escalate. Phase 10: the live PMapper
    # comparison surfaced the over-approximation (an inline-only holder was wrongly flagged).
    holders_of = _doc_holders(records, groups_by_name)
    for uid, doc, evidence in policy_documents(records):
        hit = None
        for act in sorted(POLICY_VERSION_ACTIONS):
            for pr in holders_of.get(uid, []):
                for parn in _attached_customer_managed(pr, groups_by_name, policy_docs):
                    r = is_allowed([doc], act, parn, scps=account_scps)
                    if r.decision is Decision.ALLOW:
                        hit = (act, parn, r.bucket)
                        break
                if hit:
                    break
            if hit:
                break
        if hit:
            act, parn, bucket = hit
            edges.append(_edge(
                uid, "admin", "GRANTS_ADMIN",
                f"grants {act} over attached customer-managed policy {parn}; its holder can "
                "set a new default version granting administrator", evidence,
                bucket, full_admin=False))

    # ---- effective policy documents in force for a principal ----
    def eff_docs(pr: dict) -> list[dict]:
        docs = []
        holders = [pr] + [groups_by_name[g] for g in pr.get("Groups", [])
                          if g in groups_by_name]
        for h in holders:
            docs += [d for d in (h.get("InlinePolicies") or {}).values() if d]
            for arn in h.get("AttachedPolicies", []):
                if policy_docs.get(arn):
                    docs.append(policy_docs[arn])
        return docs

    # ---- CAN_PASS_ROLE / CAN_LAUNCH_AS (principal -> role) ----
    # CAN_LAUNCH_AS means "can run code as this role": pass it to a compute service AND
    # that service can actually carry it. Two AWS facts make the second half real:
    #   * the role must TRUST the service (a Lambda-only role cannot ride an EC2 instance);
    #   * EC2 carries a role only inside an instance profile -- one that already holds it,
    #     or one the principal can put it into (the Phase 0 attachment walkthrough).
    # Without these, kerrigan (EC2) was credited with launching as a Lambda-only role in
    # the 30 Sep CloudGoat demo. See tests/test_launch_and_sources.py.
    # ---- guardrails (Phase 7): permissions boundary + SCPs per principal ----
    def guard_of(pr: dict, docs: list[dict]) -> dict:
        return guardrails(pr, docs, policy_docs.get, org)

    profiles = [r for r in records if r["_type"] == "IamInstanceProfile"]
    in_a_profile = {rid for p in profiles for rid in p.get("Roles", [])}
    for pr in principals:
        docs = eff_docs(pr)
        if not docs:
            continue
        # Evaluate every launch action once for this principal (cached across roles).
        launch_actions = {a for routes in LAUNCH_SERVICES.values()
                          for route in routes for a in route}
        me = pr["_id"]
        guard = guard_of(pr, docs)
        allow = {a: is_allowed(docs, a, "*", principal=me, **guard) for a in launch_actions}
        add_to_profile = is_allowed(docs, "iam:AddRoleToInstanceProfile", "*",
                                    principal=me, **guard)
        create_profile = is_allowed(docs, "iam:CreateInstanceProfile", "*",
                                    principal=me, **guard)
        can_fill_profile = add_to_profile.decision is Decision.ALLOW and (
            bool(profiles) or create_profile.decision is Decision.ALLOW)
        for role in roles:
            if role["_id"] == pr["_id"]:
                continue
            pr_res = is_allowed(docs, "iam:PassRole", role["_id"], principal=me, **guard)
            if pr_res.decision is not Decision.ALLOW:
                continue
            edges.append(_edge(pr["_id"], role["_id"], "CAN_PASS_ROLE",
                               pr_res.reason, f"{pr['_id']}#effective-policies", pr_res.bucket))

            trusted, _ = trust_principals(role)
            launched = False
            for svc, routes in LAUNCH_SERVICES.items():
                if svc not in trusted:
                    continue  # role does not trust this service
                # v2: PassRole is often scoped with iam:PassedToService -- re-ask for
                # THIS service, so an EC2-only grant cannot hand a role to Lambda.
                svc_pass = is_allowed(docs, "iam:PassRole", role["_id"], principal=me,
                                      boundary=guard["boundary"], scps=guard["scps"],
                                      context={**guard["context"],
                                               "iam:PassedToService": svc})
                if svc_pass.decision is not Decision.ALLOW:
                    continue
                for route in routes:
                    if any(allow[a].decision is not Decision.ALLOW for a in route):
                        continue  # this route is missing an action; try the next route
                    steps = list(route)
                    buckets = [svc_pass.bucket, *(allow[a].bucket for a in route)]
                    if svc == "ec2.amazonaws.com" and role["_id"] not in in_a_profile:
                        if not can_fill_profile:
                            continue  # no instance profile can carry it
                        steps.append("iam:AddRoleToInstanceProfile")
                        buckets.append(add_to_profile.bucket)
                    conf = "Possible" if "Possible" in buckets else "Certain"
                    edges.append(_edge(pr["_id"], role["_id"], "CAN_LAUNCH_AS",
                                       f"can PassRole + {' + '.join(steps)} "
                                       f"(role trusts {svc}; launch a resource carrying it)",
                                       f"{pr['_id']}#effective-policies;{role['_id']}#TrustPolicy",
                                       conf))
                    launched = True
                    break  # one route per service is enough
                if launched:
                    break  # one service is enough to establish the edge

    # ---- precise identity takeover (Phase 7) ----
    edges += takeover_edges(records, principals, eff_docs, guard_of)

    # ---- role assumption, condition-aware + cross-account (Phase 7 stage 4) ----
    edges += assume_role_edges(records, principals, roles, eff_docs, guard_of)

    # ---- CAN_REACH (Internet -> resource) ----
    edges += compute_reach(records)

    # ---- CONTAINS_CREDENTIAL (bucket -> owning principal) ----
    edges += credential_edges(list(cred_findings))
    return edges
