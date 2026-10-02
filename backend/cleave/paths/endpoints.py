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
from ..iam.guardrails import boundary_below_full_admin

PRINCIPAL_LABELS = ("IamUser", "IamRole")
SERVICE_LINKED = "/aws-service-role/"


# ---- sinks ---------------------------------------------------------------------------

DATA_STORE_LABELS = ("S3Bucket", "RdsInstance", "DynamoDbTable")


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
    """True if the principal already holds literal `*:*` (directly or via a group) and no
    permissions boundary caps it below that (Phase 7)."""
    for policy in _attached_policies(g, uid):
        for _, _tgt, d in g.out_edges(policy, data=True):
            for c in d["candidates"]:
                if c["rel"] == "GRANTS_ADMIN" and c.get("full_admin"):
                    rec = g.nodes[uid].get("record") or {}
                    if rec.get("PermissionsBoundary"):
                        from .access import principal_guardrails
                        if boundary_below_full_admin(rec, principal_guardrails(g, uid)):
                            return False
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

def _oidc_hosts(g: nx.DiGraph) -> set[str]:
    """OIDC provider identifiers of collected EKS clusters (issuer minus the scheme), used
    to recognise IRSA roles — roles a pod in the cluster can assume."""
    hosts = set()
    for _uid, d in g.nodes(data=True):
        if d.get("label") == "EksCluster":
            iss = (d.get("record") or {}).get("OidcIssuer") or ""
            if iss:
                hosts.add(iss.split("://", 1)[-1].rstrip("/"))
    return hosts


def _federated_principals(rec: dict) -> list[str]:
    stmts = (rec.get("TrustPolicy") or {}).get("Statement", [])
    out = []
    for st in ([stmts] if isinstance(stmts, dict) else stmts or []):
        if not isinstance(st, dict) or st.get("Effect") != "Allow":
            continue
        pr = st.get("Principal")
        if not isinstance(pr, dict):   # Principal "*" (or a bare string) has no Federated
            continue
        fed = pr.get("Federated")
        out += fed if isinstance(fed, list) else [fed] if fed else []
    return [str(f) for f in out]


def irsa_cluster(rec: dict, oidc_hosts: set[str]) -> str | None:
    """The EKS cluster a role is IRSA-assumable from, or None. A pod running with the
    matching Kubernetes service account can assume the role via the cluster OIDC provider.
    Matched only against clusters Cleave actually collected, so a generic external OIDC IdP
    is not mistaken for a pod."""
    for fed in _federated_principals(rec):
        host = fed.split("oidc-provider/", 1)[-1].rstrip("/")
        for oh in oidc_hosts:
            if host == oh:
                return oh.split("/id/")[0]
    return None


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

def _principal_account(uid: str) -> str | None:
    return uid.split(":")[4] if uid.startswith("arn:aws:iam::") and len(uid.split(":")) > 4 else None


def find_sources(g: nx.DiGraph) -> list[Source]:
    sources: list[Source] = []
    workloads = _workload_roles(g)
    oidc_hosts = _oidc_hosts(g)
    # the account(s) under analysis — anything outside them is another account's principal
    local_accounts = {_principal_account(uid) for uid, d in g.nodes(data=True)
                      if d.get("label") in PRINCIPAL_LABELS}
    local_accounts.discard(None)

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
            sources.append(Source(uid, EXTERNAL,
                                  "a role trust policy names Principal '*' (any principal)",
                                  "IamRole#TrustPolicy"))

        elif label == "Principal" and _principal_account(uid) and \
                _principal_account(uid) not in local_accounts:
            # a role trust policy names a principal in ANOTHER account: an attacker who
            # controls that account (or that principal) has a foothold here (Phase 7).
            sources.append(Source(uid, EXTERNAL,
                                  f"a role trusts a principal in another account "
                                  f"({_principal_account(uid)})", "IamRole#TrustPolicy"))

        elif label in PRINCIPAL_LABELS:
            # IRSA is checked before the already-admin exclusion: a pod assuming an
            # admin role IS an escalation (container -> account admin), so unlike a normal
            # admin identity it is a real starting point, admin or not.
            irsa = irsa_cluster(rec, oidc_hosts) if label == "IamRole" else None
            if irsa:
                short = irsa.split(".")[0] or irsa
                sources.append(Source(
                    uid, ASSUMED_COMPROMISE,
                    f"role assumable by a pod via IRSA in EKS cluster {short} — compromise a "
                    "pod and act as this role (in-cluster RBAC not assessed by a read-only scan)",
                    f"{uid}#TrustPolicy"))
                continue
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

    return sources
