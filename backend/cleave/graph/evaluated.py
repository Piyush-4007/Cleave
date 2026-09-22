"""Evaluated edges (Phase 3) — the *dangerous* half of the graph.

Uses the IAM evaluator + reachability engine to materialise the escalation edges we
committed to in the design (Option A): GRANTS_ADMIN, CAN_PASS_ROLE, CAN_LAUNCH_AS, and
CAN_REACH. Generic CAN_READ/CAN_WRITE are evaluated lazily during path search (Phase 4),
not materialised here.

Pure transform over normalised records — no AWS calls.
"""
from __future__ import annotations
from ..iam.evaluator import is_allowed, grants_admin, Decision
from ..reachability.engine import compute_reach
from ..credscan import credential_edges

# AWS-managed policies whose documents we don't collect but whose meaning is well-known.
KNOWN_ADMIN_MANAGED = {"AdministratorAccess"}
FULL_ADMIN_DOC = {"Statement": [{"Effect": "Allow", "Action": "*", "Resource": "*"}]}
# TODO v2: fetch attached AWS-managed policy docs in the collector instead of name-matching.


def _edge(frm, to, rel, reason, evidence, confidence, by="iam.evaluator.v1"):
    return {"frm": frm, "to": to, "rel": rel, "props": {
        "reason": reason, "evidence": evidence,
        "confidence": confidence, "discovered_by": by}}


def compute_evaluated_edges(records: list[dict], cred_findings: list[dict] = ()) -> list[dict]:
    policy_docs = {r["_id"]: r.get("Document")
                   for r in records if r["_type"] == "IamPolicy"}
    groups_by_name = {r["GroupName"]: r for r in records if r["_type"] == "IamGroup"}
    roles = [r for r in records if r["_type"] == "IamRole"]
    principals = [r for r in records if r["_type"] in ("IamUser", "IamRole")]
    edges: list[dict] = []

    # ---- GRANTS_ADMIN (policy -> Admin sink) ----
    for p in records:
        if p["_type"] == "IamPolicy" and p.get("Document"):
            res = grants_admin(p["Document"])
            if res.decision is Decision.ALLOW:
                edges.append(_edge(p["_id"], "admin", "GRANTS_ADMIN",
                                   res.reason, f"{p['_id']}#Document", res.bucket))
    seen_admin = set()
    for pr in principals:
        for arn in pr.get("AttachedPolicies", []):
            name = arn.split("/")[-1]
            if name in KNOWN_ADMIN_MANAGED and arn not in seen_admin:
                seen_admin.add(arn)
                edges.append(_edge(arn, "admin", "GRANTS_ADMIN",
                                   f"AWS-managed {name} is admin-equivalent", arn, "Certain"))

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
                elif arn.split("/")[-1] in KNOWN_ADMIN_MANAGED:
                    docs.append(FULL_ADMIN_DOC)
        return docs

    # ---- CAN_PASS_ROLE / CAN_LAUNCH_AS (principal -> role) ----
    for pr in principals:
        docs = eff_docs(pr)
        if not docs:
            continue
        run = is_allowed(docs, "ec2:RunInstances", "*")
        create_fn = is_allowed(docs, "lambda:CreateFunction", "*")
        can_compute = (run.decision is Decision.ALLOW) or (create_fn.decision is Decision.ALLOW)
        for role in roles:
            if role["_id"] == pr["_id"]:
                continue
            pr_res = is_allowed(docs, "iam:PassRole", role["_id"])
            if pr_res.decision is not Decision.ALLOW:
                continue
            edges.append(_edge(pr["_id"], role["_id"], "CAN_PASS_ROLE",
                               pr_res.reason, f"{pr['_id']}#effective-policies", pr_res.bucket))
            if can_compute:
                svc = "ec2:RunInstances" if run.decision is Decision.ALLOW else "lambda:CreateFunction"
                compute_res = run if run.decision is Decision.ALLOW else create_fn
                conf = "Possible" if "Possible" in (pr_res.bucket, compute_res.bucket) else "Certain"
                edges.append(_edge(pr["_id"], role["_id"], "CAN_LAUNCH_AS",
                                   f"can PassRole + {svc} (launch a resource carrying the role)",
                                   f"{pr['_id']}#effective-policies", conf))

    # ---- CAN_REACH (Internet -> resource) ----
    edges += compute_reach(records)

    # ---- CONTAINS_CREDENTIAL (bucket -> owning principal) ----
    edges += credential_edges(list(cred_findings))
    return edges
