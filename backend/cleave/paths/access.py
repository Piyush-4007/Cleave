"""CAN_READ / CAN_WRITE expansion (Phase 4, increment 2).

These are the edges that turn a stored credential into an attack path:

    attacker --CAN_READ--> bucket --CONTAINS_CREDENTIAL--> victim --...--> Admin

They are not materialised by the Phase 3 loader, because the honest version is a
principal x resource cross product: every principal evaluated against every resource,
almost all of it thrown away. On a 300-resource account that is tens of thousands of
policy evaluations to produce a handful of useful edges.

**Demand-driven expansion instead.** A `CAN_READ` edge only matters if the resource
leads somewhere — it holds a credential, or it hands out a role, or it is itself a sink.
So we evaluate access only for resources that already have an outgoing traversable edge
(or are a sink), and only for principals that are candidate path sources. That is a
bounded, explainable computation rather than a cross product.

This is *demand-driven*, not per-step lazy evaluation inside Yen's algorithm. It reaches
the same edges for far less machinery, and it keeps the search operating on a static
graph, which is what `networkx.shortest_simple_paths` needs.
"""
from __future__ import annotations
import logging
from ..iam.evaluator import Decision, is_allowed
from ..iam.guardrails import ORG_ID, guardrails

log = logging.getLogger("cleave.paths.access")

# How to ask "can this principal read/write this resource?" per node type:
#   action            the IAM action that constitutes the access
#   resource          the ARN pattern to evaluate it against ({uid} = the node's id)
#   policy_field      the record field holding the resource-based policy, if any
#
# Deliberately small. Each entry is one concrete, defensible attacker action — not a
# guess at what "access" means in general.
ACCESS_MODEL = {
    "S3Bucket": {
        "CAN_READ":  {"action": "s3:GetObject", "resource": "{uid}/*"},
        "CAN_WRITE": {"action": "s3:PutObject", "resource": "{uid}/*"},
        "policy_field": "Policy",
    },
    "SecretsManagerSecret": {
        "CAN_READ": {"action": "secretsmanager:GetSecretValue", "resource": "{uid}"},
        "policy_field": "ResourcePolicy",
    },
    "LambdaFunction": {
        # Overwrite the code and it runs as the function's execution role. This is why
        # EXECUTES_AS matters: the write is the step that reaches the role.
        "CAN_WRITE": {"action": "lambda:UpdateFunctionCode", "resource": "{uid}"},
    },
    "KmsKey": {
        "CAN_READ": {"action": "kms:Decrypt", "resource": "{uid}"},
        "policy_field": "Policy",
    },
    "DynamoDbTable": {
        "CAN_READ": {"action": "dynamodb:GetItem", "resource": "{uid}"},
        "policy_field": "Policy",
    },
}
# TODO: SsmParameter is skipped — its `_id` is "<region>:<Name>", not an ARN, so there is
# nothing correct to evaluate an IAM Resource match against. Fix in the collector (build
# arn:aws:ssm:<region>:<account>:parameter/<name>) rather than guessing an ARN here.
# TODO: RdsInstance is skipped — database contents are not IAM-gated in the general case,
# so there is no read action to evaluate. Network reachability already covers RDS.

PRINCIPAL_LABELS = ("IamUser", "IamRole")


def effective_policy_docs(g, uid: str) -> list[dict]:
    """Every policy document in force for a principal, read from the graph: directly
    attached, plus anything attached to a group it belongs to. Inline-policy nodes carry
    their own Document, so managed and inline are read the same way."""
    docs, seen = [], set()

    def collect(policy_uid: str):
        if policy_uid in seen:
            return
        seen.add(policy_uid)
        doc = (g.nodes[policy_uid].get("record") or {}).get("Document")
        if doc:
            docs.append(doc)

    for _, nxt, d in g.out_edges(uid, data=True):
        rels = {c["rel"] for c in d["candidates"]}
        if "HAS_ATTACHED" in rels and g.nodes[nxt].get("label") == "IamPolicy":
            collect(nxt)
        if "IN_GROUP" in rels:
            for _, gp, gd in g.out_edges(nxt, data=True):
                if (any(c["rel"] == "HAS_ATTACHED" for c in gd["candidates"])
                        and g.nodes[gp].get("label") == "IamPolicy"):
                    collect(gp)
    return docs


def principal_guardrails(g, uid: str, docs: list[dict] | None = None) -> dict:
    """is_allowed() keyword arguments (boundary, scps, context) for a principal node, read
    from the graph — the same rules graph/evaluated.py applies to the records."""
    rec = g.nodes[uid].get("record") or {} if uid in g else {}
    if docs is None:
        docs = effective_policy_docs(g, uid)

    def lookup(arn):
        return (g.nodes[arn].get("record") or {}).get("Document") if arn in g else None

    org = (g.nodes[ORG_ID].get("record") or None) if ORG_ID in g else None
    return guardrails({**rec, "_id": uid}, docs, lookup, org)


def expansion_targets(g, traversable: set[str], sink_uids: frozenset[str] = frozenset()) -> list[str]:
    """Resources worth evaluating access to: those that lead somewhere.

    "Leads somewhere" means it has at least one outgoing traversable edge (it holds a
    credential, hands out a role, ...) or it is a sink. Everything else is a dead end, so
    knowing who can read it would not create a path.
    """
    targets = []
    for uid, data in g.nodes(data=True):
        if data.get("label") not in ACCESS_MODEL:
            continue
        if uid in sink_uids:
            targets.append(uid)
            continue
        leads_somewhere = any(
            c["rel"] in traversable
            for _, _t, d in g.out_edges(uid, data=True) for c in d["candidates"])
        if leads_somewhere:
            targets.append(uid)
    return targets


def access_edges(g, principal_uids, target_uids) -> list[dict]:
    """Evaluate each (principal, target) pair and emit the CAN_READ/CAN_WRITE edges that
    genuinely hold. One `is_allowed` call per pair per access kind."""
    edges: list[dict] = []
    evaluated = 0
    for p_uid in principal_uids:
        if p_uid not in g or g.nodes[p_uid].get("label") not in PRINCIPAL_LABELS:
            continue
        docs = effective_policy_docs(g, p_uid)
        if not docs:
            continue
        guard = principal_guardrails(g, p_uid, docs)
        for t_uid in target_uids:
            record = g.nodes[t_uid].get("record") or {}
            model = ACCESS_MODEL[g.nodes[t_uid]["label"]]
            res_policy = record.get(model.get("policy_field") or "") or None
            for rel, spec in model.items():
                if rel == "policy_field":
                    continue
                evaluated += 1
                res = is_allowed(docs, spec["action"],
                                 spec["resource"].format(uid=t_uid),
                                 resource_policy=res_policy, principal=p_uid, **guard)
                if res.decision is not Decision.ALLOW:
                    continue
                edges.append({"frm": p_uid, "to": t_uid, "rel": rel, "props": {
                    "reason": f"can call {spec['action']} — {res.reason}",
                    "evidence": f"{p_uid}#effective-policies",
                    "confidence": res.bucket,
                    "discovered_by": "paths.access",
                }})
    log.debug("access expansion: %d evaluations -> %d edges", evaluated, len(edges))
    return edges
