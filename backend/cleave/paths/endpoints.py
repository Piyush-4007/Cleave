"""Sources and sinks — where a path may start, and what counts as winning (Phase 4).

Two source classes (design decision, October):

  EXTERNAL            an unauthenticated attacker on the internet starts here.
  ASSUMED_COMPROMISE  a principal that is not already an administrator. The question is
                      "if this credential leaked, what could it reach?" — which is the
                      only way IAM-only escalation shows up at all. Both Phase 0
                      ground-truth scenarios start from exactly such a user.

The exclusion that makes ASSUMED_COMPROMISE meaningful: a principal that already holds
literal `*:*` is the account's baseline, not a finding. Note this is `full_admin`, NOT
"has a GRANTS_ADMIN edge" — raynor's policy grants `iam:SetDefaultPolicyVersion`, which
is admin-*equivalent* and therefore carries a GRANTS_ADMIN edge, but raynor still has to
escalate. Excluding him would delete the very finding we exist to produce.
"""
from __future__ import annotations
import networkx as nx
from .model import Source, Sink, EXTERNAL, ASSUMED_COMPROMISE
from .ranking import sensitive_reason
from ..graph.evaluated import trust_principals

PRINCIPAL_LABELS = ("IamUser", "IamRole")
SERVICE_LINKED = "/aws-service-role/"


# ---- sinks ---------------------------------------------------------------------------

DATA_STORE_LABELS = ("S3Bucket", "RdsInstance")


def find_sinks(g: nx.DiGraph) -> list[Sink]:
    """The targets an attacker wants to reach.

    v1 sinks:
      * ADMIN          — the synthetic Admin node (full account compromise).
      * SENSITIVE_DATA — a data store (S3/RDS) the account owner tagged sensitive; reaching
                         CAN_READ/CAN_WRITE to it is the path.

    Deferred to Phase 7 (v2), each for a concrete reason, not oversight:
      * KMS admin — needs key-policy admin-action reasoning the evaluator doesn't do yet.
      * CloudTrail deletion (anti-forensics) — needs a CloudTrail collector, which we
        don't have.
    """
    sinks: list[Sink] = []
    if "admin" in g:
        sinks.append(Sink("admin", "ADMIN", "full administrative control of the account"))
    for uid, data in g.nodes(data=True):
        if data.get("label") in DATA_STORE_LABELS:
            why = sensitive_reason(uid, data.get("record") or {})
            if why:
                sinks.append(Sink(uid, "SENSITIVE_DATA", f"sensitive data store — {why}"))
    return sinks


# ---- already-admin (source exclusion) ------------------------------------------------

def _attached_policies(g: nx.DiGraph, uid: str):
    """Policy nodes this identity's permissions come from: directly attached, and those
    attached to groups it belongs to."""
    for _, nxt, d in g.out_edges(uid, data=True):
        rels = {c["rel"] for c in d["candidates"]}
        if "HAS_ATTACHED" in rels:
            yield nxt
        if "IN_GROUP" in rels:
            for _, gp, gd in g.out_edges(nxt, data=True):
                if any(c["rel"] == "HAS_ATTACHED" for c in gd["candidates"]):
                    yield gp


def holds_full_admin(g: nx.DiGraph, uid: str) -> bool:
    """True if the principal already holds literal `*:*` (directly or via a group)."""
    for policy in _attached_policies(g, uid):
        for _, _tgt, d in g.out_edges(policy, data=True):
            for c in d["candidates"]:
                if c["rel"] == "GRANTS_ADMIN" and c.get("full_admin"):
                    return True
    return False


# ---- external entry points -----------------------------------------------------------

def _as_list(v):
    if v is None:
        return []
    return v if isinstance(v, list) else [v]


def _pab_blocks_public(pab) -> bool:
    if not isinstance(pab, dict):
        return False
    return all(pab.get(k) for k in ("BlockPublicAcls", "IgnorePublicAcls",
                                    "BlockPublicPolicy", "RestrictPublicBuckets"))


def bucket_public_reason(rec: dict) -> str | None:
    """Why this bucket is internet-readable, or None. Public Access Block wins: with all
    four switches on, neither a policy nor an ACL can expose the bucket."""
    if _pab_blocks_public(rec.get("PublicAccessBlock")):
        return None
    policy = rec.get("Policy")
    if isinstance(policy, dict):
        stmts = policy.get("Statement", [])
        for st in ([stmts] if isinstance(stmts, dict) else stmts or []):
            if not isinstance(st, dict) or st.get("Effect") != "Allow":
                continue
            pr = st.get("Principal")
            if pr == "*" or (isinstance(pr, dict) and "*" in _as_list(pr.get("AWS"))):
                return "bucket policy allows Principal '*'"
    for grant in rec.get("Acl") or []:
        uri = ((grant.get("Grantee") or {}).get("URI") or "")
        if uri.endswith("/groups/global/AllUsers"):
            return "bucket ACL grants AllUsers"
        if uri.endswith("/groups/global/AuthenticatedUsers"):
            return "bucket ACL grants AuthenticatedUsers (any AWS account)"
    return None


def _internet_is_live(g: nx.DiGraph) -> bool:
    return "internet" in g and any(
        c["rel"] == "CAN_REACH"
        for _, _t, d in g.out_edges("internet", data=True) for c in d["candidates"])


# ---- which roles can be a compromised starting point --------------------------------

def _workload_roles(g: nx.DiGraph) -> dict[str, str]:
    """role uid -> a workload currently running as it (a Lambda, or an EC2 instance via its
    instance profile). Compromising that workload is how an attacker holds the role."""
    profile_roles = {uid: (d.get("record") or {}).get("Roles", [])
                     for uid, d in g.nodes(data=True) if d.get("label") == "IamInstanceProfile"}
    workload_label = {"LambdaFunction": "Lambda", "GlueJob": "Glue job",
                      "SageMakerNotebook": "SageMaker notebook",
                      "CodeBuildProject": "CodeBuild project", "EcsService": "ECS service"}
    out: dict[str, str] = {}
    for uid, d in g.nodes(data=True):
        rec, label = d.get("record") or {}, d.get("label")
        if label in workload_label and rec.get("Role"):
            out.setdefault(rec["Role"], f"{workload_label[label]} {rec.get('Name') or rec.get('FunctionName') or uid}")
        elif label == "Ec2Instance" and rec.get("IamInstanceProfile"):
            for role in profile_roles.get(rec["IamInstanceProfile"], []):
                out.setdefault(role, f"EC2 instance {rec.get('InstanceId') or uid}")
    return out


def role_source_note(uid: str, rec: dict, workloads: dict[str, str]) -> str | None:
    """Why this role's credentials could plausibly be held by an attacker, or None.

    Found in the 30 Sep CloudGoat demo: treating every non-admin role as compromisable
    reported paths "from" AWS service-linked roles and from service roles no workload runs
    as. Nobody can obtain those credentials, so they are not starting points. A role
    counts when an identity may assume it, or a live workload runs as it.
    """
    if SERVICE_LINKED in uid:
        return None  # only the AWS service itself can ever assume these
    if not rec.get("TrustPolicy"):
        return ""  # trust unknown (not collected / stub): keep, over-report rather than drop
    services, others = trust_principals(rec)
    if others:
        return " (assumable by another identity)"
    if uid in workloads:
        return f" (run as by {workloads[uid]} — compromise the workload, hold the role)"
    return None  # service-only trust and nothing runs as it


# ---- the source set ------------------------------------------------------------------

def find_sources(g: nx.DiGraph) -> list[Source]:
    sources: list[Source] = []
    workloads = _workload_roles(g)

    if _internet_is_live(g):
        sources.append(Source("internet", EXTERNAL,
                              "unauthenticated network access from the internet",
                              "reachability#CAN_REACH"))

    for uid, data in g.nodes(data=True):
        label, rec = data.get("label"), (data.get("record") or {})

        if label == "S3Bucket":
            why = bucket_public_reason(rec)
            if why:
                sources.append(Source(uid, EXTERNAL, f"public S3 bucket — {why}",
                                      f"{uid}#Policy/Acl/PublicAccessBlock"))

        elif label == "LambdaFunction" and str(rec.get("FunctionUrlAuthType") or "").upper() == "NONE":
            sources.append(Source(uid, EXTERNAL,
                                  "Lambda function URL with AuthType=NONE — anyone can invoke it",
                                  f"{uid}#FunctionUrlAuthType"))

        elif label == "ApiGatewayApi" and (rec.get("PublicRoutes")):
            sources.append(Source(uid, EXTERNAL,
                                  f"API Gateway with {len(rec['PublicRoutes'])} unauthenticated route(s)",
                                  f"{uid}#PublicRoutes"))

        elif label == "Principal" and uid == "*":
            # a role trust policy naming Principal "*". The Phase 2 loader does not yet
            # evaluate trust Conditions, so this can over-report — v1 over-reports on
            # purpose rather than silently dropping a real external entry point.
            sources.append(Source(uid, EXTERNAL,
                                  "a role trust policy names Principal '*' (any principal)",
                                  "IamRole#TrustPolicy"))

        elif label in PRINCIPAL_LABELS:
            if holds_full_admin(g, uid):
                continue  # already administrator: the baseline, not an escalation
            note = ""
            if label == "IamRole":
                note = role_source_note(uid, rec, workloads)
                if note is None:
                    continue
            sources.append(Source(
                uid, ASSUMED_COMPROMISE,
                f"non-admin principal{note} — treated as a compromised credential",
                f"{uid}#identity"))

    # TODO v2: cross-account `arn:aws:iam::<other>:root` trust principals are external
    # entry points too (+0.5 in the Phase 5 score). Left out of v1 to keep the source set
    # defensible; add here, not in search.
    return sources
