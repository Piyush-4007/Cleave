"""Evaluated edges (Phase 3) — the *dangerous* half of the graph.

Uses the IAM evaluator + reachability engine to materialise the escalation edges we
committed to in the design (Option A): GRANTS_ADMIN, CAN_PASS_ROLE, CAN_LAUNCH_AS, and
CAN_REACH. Generic CAN_READ/CAN_WRITE are evaluated lazily during path search (Phase 4),
not materialised here.

Pure transform over normalised records — no AWS calls.
"""
from __future__ import annotations
from ..iam.evaluator import is_allowed, grants_admin, is_full_admin, Decision
from ..iam.catalogue import LAUNCH_SERVICES
from ..reachability.engine import compute_reach
from ..credscan import credential_edges


def _edge(frm, to, rel, reason, evidence, confidence, by="iam.evaluator.v1", **extra):
    return {"frm": frm, "to": to, "rel": rel, "props": {
        "reason": reason, "evidence": evidence,
        "confidence": confidence, "discovered_by": by, **extra}}


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
    identity (not only an AWS service) can obtain the role's credentials. Trust Conditions
    are not evaluated yet (v2), so this errs towards "can assume" -- over-report, not drop.
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
    for uid, doc, evidence in policy_documents(records):
        res = grants_admin(doc)
        if res.decision is Decision.ALLOW:
            edges.append(_edge(uid, "admin", "GRANTS_ADMIN", res.reason, evidence,
                               res.bucket, full_admin=is_full_admin(doc)))

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
    profiles = [r for r in records if r["_type"] == "IamInstanceProfile"]
    in_a_profile = {rid for p in profiles for rid in p.get("Roles", [])}
    for pr in principals:
        docs = eff_docs(pr)
        if not docs:
            continue
        # Evaluate each launch service's required action(s) once for this principal.
        compute = {svc: [is_allowed(docs, a, "*") for a in actions]
                   for svc, actions in LAUNCH_SERVICES.items()}
        add_to_profile = is_allowed(docs, "iam:AddRoleToInstanceProfile", "*")
        create_profile = is_allowed(docs, "iam:CreateInstanceProfile", "*")
        can_fill_profile = add_to_profile.decision is Decision.ALLOW and (
            bool(profiles) or create_profile.decision is Decision.ALLOW)
        for role in roles:
            if role["_id"] == pr["_id"]:
                continue
            pr_res = is_allowed(docs, "iam:PassRole", role["_id"])
            if pr_res.decision is not Decision.ALLOW:
                continue
            edges.append(_edge(pr["_id"], role["_id"], "CAN_PASS_ROLE",
                               pr_res.reason, f"{pr['_id']}#effective-policies", pr_res.bucket))

            trusted, _ = trust_principals(role)
            for svc, actions in LAUNCH_SERVICES.items():
                results = compute[svc]
                if svc not in trusted or any(r.decision is not Decision.ALLOW for r in results):
                    continue  # role does not trust this service, or a required action is missing
                steps = list(actions)
                buckets = [pr_res.bucket, *(r.bucket for r in results)]
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
                break  # one route is enough to establish the edge

    # ---- CAN_REACH (Internet -> resource) ----
    edges += compute_reach(records)

    # ---- CONTAINS_CREDENTIAL (bucket -> owning principal) ----
    edges += credential_edges(list(cred_findings))
    return edges
