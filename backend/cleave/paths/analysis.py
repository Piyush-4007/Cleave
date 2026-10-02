"""Analysis assembly — the whole engine behind one call (Phase 5/6 bridge).

`analyze(g)` runs sources -> sinks -> search -> rank -> cut on a graph and returns one
structured result. The CLI (paths.run) and the API (api.service) both call it, so they can
never drift. `path_subgraph` extracts the drawable neighbourhood of a single path for the
Phase 6 Cytoscape viewer.
"""
from __future__ import annotations
import datetime as _dt
import json
from .endpoints import find_sinks, find_sources
from .model import EXTERNAL
from .search import MAX_HOPS, K_PER_PAIR, find_paths
from .ranking import rank
from .cut import minimum_cut, best_single_fix

# Graph node label -> the short type string the dashboard renders (icon + tag).
LABEL_TO_TYPE = {
    "IamUser": "user", "IamRole": "role", "IamGroup": "group", "IamPolicy": "policy",
    "S3Bucket": "s3", "Ec2Instance": "ec2", "LambdaFunction": "lambda", "RdsInstance": "rds",
    "SecretsManagerSecret": "secret", "KmsKey": "kms", "Internet": "internet", "Admin": "admin",
    "SecurityGroup": "sg", "Subnet": "subnet", "Vpc": "vpc", "IamInstanceProfile": "profile",
    "Principal": "principal",
    "GlueJob": "glue", "SageMakerNotebook": "sagemaker", "CodeBuildProject": "codebuild",
    "EcsService": "ecs", "SnsTopic": "sns", "SqsQueue": "sqs", "EcrRepository": "ecr",
    "DynamoDbTable": "dynamodb", "ApiGatewayApi": "apigw", "EksCluster": "eks",
}


def analyze(g, max_hops: int = MAX_HOPS, k: int = K_PER_PAIR) -> dict:
    sources = find_sources(g)
    sinks = find_sinks(g)
    paths = find_paths(g, sources, sinks, max_hops=max_hops, k=k)
    ranked = rank(paths, g)
    cut = minimum_cut(paths)
    fixes = best_single_fix(paths)

    # enrich each ranked path with node views (names, types, inspector detail) and a
    # generated title, so the dashboard renders live data as richly as the mock.
    for d in ranked:
        d["view"] = [_node_view(g, uid) for uid in d["nodes"]]
        d["title"] = _path_title(d["view"], d["sink"]["kind"], d["length"])

    # Per-resource findings (the Nessus-style layer), tagged and ranked by the paths above.
    from ..findings import run_checks, summarize, tag_and_rank
    findings = tag_and_rank(run_checks(g), ranked, sources)

    # Free cost estimate (what is running and billing now) — from the same graph, no
    # pricing API, no billing permission. Actual spend is the opt-in Cost Explorer panel.
    from ..cost import estimate as cost_estimate
    cost = cost_estimate(g)

    ext = sum(1 for s in sources if s.kind == EXTERNAL)
    return {
        "generated_at": _dt.datetime.now(_dt.timezone.utc).isoformat(),
        "graph": {"nodes": g.number_of_nodes(), "connected_pairs": g.number_of_edges()},
        "summary": {
            "sources": len(sources),
            "sources_external": ext,
            "sources_assumed_compromise": len(sources) - ext,
            "sinks": len(sinks),
            "sinks_admin": sum(1 for s in sinks if s.kind == "ADMIN"),
            "sinks_sensitive_data": sum(1 for s in sinks if s.kind == "SENSITIVE_DATA"),
            "paths_found": len(ranked),
            "top_score": ranked[0]["ranking"]["score"] if ranked else 0,
            "best_single_fix": (
                {"fix": fixes[0]["fix"], "breaks": fixes[0]["paths_cut"],
                 "of": fixes[0]["paths_total"], "cost": fixes[0]["cost"]}
                if fixes else None),
        },
        "paths": ranked,
        "minimum_cut": cut,
        "best_single_fix": fixes,
        "findings": findings,
        "findings_summary": summarize(findings),
        "cost": cost,
    }


def _node_detail(label: str, uid: str, rec: dict) -> dict | None:
    """The inspector payload for a node: its ARN, its policy document if it has one, and a
    few type-specific facts. Reads the collected record, never AWS."""
    detail: dict = {}
    if uid.startswith("arn:"):
        detail["arn"] = uid
    if rec.get("Document"):
        detail["policy"] = json.dumps(rec["Document"], indent=2, default=str)

    facts: list[list[str]] = []

    def add(k, v):
        if v not in (None, "", [], {}):
            facts.append([k, str(v)])

    if label == "IamUser":
        keys = rec.get("AccessKeys") or []
        if keys:
            add("access key", f"{keys[0].get('AccessKeyId', '?')} · {keys[0].get('Status', '')}".strip(" ·"))
            add("key last used", keys[0].get("LastUsedDate") or "never")
        add("groups", ", ".join(rec.get("Groups", [])) or None)
    elif label == "IamRole":
        add("attached", ", ".join(p.split("/")[-1] for p in rec.get("AttachedPolicies", [])) or None)
    elif label == "IamPolicy":
        add("default version", rec.get("DefaultVersionId"))
        add("managed by", rec.get("ManagedBy"))
    elif label == "Ec2Instance":
        add("public ip", rec.get("PublicIpAddress"))
        add("imds", "v1 (optional)" if rec.get("ImdsHttpTokens") == "optional" else rec.get("ImdsHttpTokens"))
    elif label == "S3Bucket":
        add("tags", ", ".join(f"{k}={v}" for k, v in (rec.get("Tags") or {}).items()) or None)
    elif label == "RdsInstance":
        add("publicly accessible", rec.get("PubliclyAccessible"))
        add("tags", ", ".join(f"{k}={v}" for k, v in (rec.get("Tags") or {}).items()) or None)
    elif label in ("GlueJob", "SageMakerNotebook", "CodeBuildProject", "EcsService"):
        add("runs as", (rec.get("Role") or "").split("/")[-1] or None)
        add("cluster", rec.get("Cluster"))
        add("command", rec.get("Command"))

    if facts:
        detail["facts"] = facts
    return detail or None


def _node_view(g, uid: str) -> dict:
    data = g.nodes.get(uid, {})
    label = data.get("label", "?")
    rec = data.get("record") or {}
    name = rec.get("Name") or rec.get("UserName") or rec.get("RoleName") \
        or rec.get("PolicyName") or rec.get("DBInstanceIdentifier") \
        or ("administrator" if label == "Admin" else "anyone" if label == "Internet"
            else uid.split("/")[-1] if "/" in uid else uid)
    return {
        "id": uid, "label": label, "type": LABEL_TO_TYPE.get(label, "resource"),
        "name": name, "detail": _node_detail(label, uid, rec),
    }


def _path_title(view: list[dict], sink_kind: str, length: int) -> str:
    """A one-line headline for a path, generated deterministically (no model)."""
    src = view[0]["name"] if view else "a principal"
    target = "sensitive data" if sink_kind == "SENSITIVE_DATA" else "administrator access"
    return f"{src} can reach {target} in {length} step{'s' if length != 1 else ''}."


def path_subgraph(g, ranked_path: dict, cut_edges: list[dict] | None = None) -> dict:
    """The drawable neighbourhood of one path: the path nodes plus one hop of context, and
    every edge among them. Rendering constraint (handbook Phase 6): never the full graph.

    Edges are flagged `on_path` (part of this route) and `in_cut` (part of the minimum
    cut), so the viewer can highlight the route and paint the cut red.
    """
    on_path_nodes = list(ranked_path["nodes"])
    cut_set = {(e["frm"], e["to"], e["rel"]) for e in (cut_edges or [])}
    on_path_edges = {(h["frm"], h["to"], h["rel"]) for h in ranked_path["hops"]}

    # one hop of context: immediate neighbours of the path nodes
    ctx = set(on_path_nodes)
    for n in on_path_nodes:
        if n in g:
            ctx.update(g.successors(n))
            ctx.update(g.predecessors(n))

    nodes = [{**_node_view(g, uid),
              "on_path": uid in set(on_path_nodes),
              "is_source": uid == ranked_path["source"]["uid"],
              "is_sink": uid == ranked_path["sink"]["uid"]}
             for uid in ctx]

    edges = []
    ctx_set = set(ctx)
    for a in ctx_set:
        if a not in g:
            continue
        for b in g.successors(a):
            if b not in ctx_set:
                continue
            for c in g[a][b]["candidates"]:
                rel = c["rel"]
                edges.append({
                    "frm": a, "to": b, "rel": rel,
                    "reason": c.get("reason", ""),
                    "confidence": c.get("confidence", "Possible"),
                    "on_path": (a, b, rel) in on_path_edges,
                    "in_cut": (a, b, rel) in cut_set,
                })
    return {"nodes": nodes, "edges": edges}
