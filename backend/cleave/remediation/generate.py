"""Edge -> Terraform fix generator (Phase 8).

Input: one cut edge (from paths.cut — frm, to, rel, ...) plus the graph it was found in.
Output: a `Fix` (see model.py). One template per edge type; a template fires only when
Cleave can produce a *correct* corrected resource, otherwise it returns guidance text.

Scope of this first cut (the edges Cleave's paths actually produce): the IAM escalation
edges, where Cleave holds the real policy/trust documents and can rewrite them exactly:
  GRANTS_ADMIN         scope the primitive, or detach real AdministratorAccess
  CAN_TAKE_OVER        scope the takeover action to the caller's own user
  CAN_JOIN_GROUP       scope / remove iam:AddUserToGroup
  CAN_REWRITE_TRUST    scope / remove iam:UpdateAssumeRolePolicy
  CAN_ASSUME           tighten the role trust policy
  CAN_LAUNCH_AS        add an iam:PassedToService condition to PassRole
Network / resource-policy templates (CAN_REACH SG, S3 public) land in the next sub-step;
anything else returns guidance. See model.Fix for the confidence contract.
"""
from __future__ import annotations
import json
from ..iam.catalogue import ADMIN_EQUIVALENT_ACTIONS, TAKEOVER_ACTIONS
from ..iam.evaluator import _glob
from .model import Fix

# rel -> the IAM actions whose grant creates that takeover edge (reverse of TAKEOVER_ACTIONS)
_TAKEOVER_BY_REL: dict[str, list[str]] = {}
for _act, (_rel, _kind) in TAKEOVER_ACTIONS.items():
    _TAKEOVER_BY_REL.setdefault(_rel, []).append(_act)


# ---- graph helpers -------------------------------------------------------------------

def _rec(g, uid: str) -> dict:
    return (g.nodes[uid].get("record") or {}) if uid in g else {}


def _short(uid: str) -> str:
    return uid.split("/")[-1].split("#")[-1] or uid


def _policy_nodes_of(g, principal_uid: str):
    """(policy_uid, record) for every policy a principal's permissions come from:
    directly attached, via a group, or inline. Mirrors paths.access.effective_policy_docs
    but yields the nodes, because a fix has to name the resource it edits."""
    seen: set[str] = set()

    def emit(puid):
        if puid in seen or puid not in g:
            return
        seen.add(puid)
        if _rec(g, puid).get("Document"):
            out.append((puid, _rec(g, puid)))

    out: list[tuple[str, dict]] = []
    for _, nxt, d in g.out_edges(principal_uid, data=True):
        rels = {c["rel"] for c in d["candidates"]}
        if "HAS_ATTACHED" in rels and g.nodes[nxt].get("label") == "IamPolicy":
            emit(nxt)
        if "IN_GROUP" in rels:
            for _, gp, gd in g.out_edges(nxt, data=True):
                if (any(c["rel"] == "HAS_ATTACHED" for c in gd["candidates"])
                        and g.nodes[gp].get("label") == "IamPolicy"):
                    emit(gp)
    return out


def _statements(doc: dict) -> list[dict]:
    st = (doc or {}).get("Statement", [])
    return [st] if isinstance(st, dict) else [s for s in st or [] if isinstance(s, dict)]


def _is_empty(doc: dict) -> bool:
    """A policy document with no statements — invalid in AWS, so never emit it as a patch."""
    return not _statements(doc)


def _grants(doc: dict, actions: list[str]) -> bool:
    for st in _statements(doc):
        if st.get("Effect") != "Allow":
            continue
        acts = st.get("Action")
        acts = acts if isinstance(acts, list) else [acts]
        if any(_glob(str(p), a, ci=True) for p in acts for a in actions):
            return True
    return False


# ---- policy transforms ---------------------------------------------------------------

def _remove_actions(doc: dict, actions: list[str]) -> tuple[dict, list[str]]:
    """Return (corrected doc, removed) with every Allow of a dangerous `action` taken out.

    A statement that granted it keeps its other actions; a statement that granted ONLY
    dangerous actions is dropped. The removal is exact — the escalation is gone — and the
    impact note names what left, because removing a real action is a judgement the owner
    confirms via the PR.
    """
    removed: list[str] = []
    new_stmts = []
    for st in _statements(doc):
        if st.get("Effect") != "Allow":
            new_stmts.append(st)
            continue
        acts = st.get("Action")
        as_list = acts if isinstance(acts, list) else [acts]
        keep, drop = [], []
        for a in as_list:
            if any(_glob(str(a), dang, ci=True) for dang in actions):
                drop.append(a)
            else:
                keep.append(a)
        if not drop:
            new_stmts.append(st)
            continue
        removed += [str(a) for a in drop]
        if keep:
            new_stmts.append({**st, "Action": keep if isinstance(acts, list) else keep[0]})
        # else: statement granted only dangerous actions -> drop it entirely
    new_doc = {k: v for k, v in doc.items() if k != "Statement"}
    new_doc["Statement"] = new_stmts
    return new_doc, removed


def _scope_to_self(doc: dict, actions: list[str], account: str) -> tuple[dict, list[str]]:
    """Scope the dangerous `actions` to the caller's own user (${aws:username}) instead of
    removing them — the self-service form that keeps the action usable without the
    account-takeover. Returns (doc, scoped) where `scoped` are the actions actually
    changed (so the message names what it did, not every candidate action)."""
    self_arn = f"arn:aws:iam::{account}:user/${{aws:username}}"
    scoped: list[str] = []
    new_stmts = []
    for st in _statements(doc):
        acts = st.get("Action")
        as_list = acts if isinstance(acts, list) else [acts]
        dang = [a for a in as_list if any(_glob(str(a), d, ci=True) for d in actions)]
        if st.get("Effect") != "Allow" or not dang:
            new_stmts.append(st)
            continue
        scoped += [str(a) for a in dang]
        safe = [a for a in as_list if a not in dang]
        if safe:
            new_stmts.append({**st, "Action": safe if isinstance(acts, list) else safe[0]})
        new_stmts.append({"Effect": "Allow", "Action": dang if len(dang) > 1 else dang[0],
                          "Resource": self_arn})
    new_doc = {k: v for k, v in doc.items() if k != "Statement"}
    new_doc["Statement"] = new_stmts
    return new_doc, scoped


# ---- Terraform rendering -------------------------------------------------------------

def _tf_name(uid: str) -> str:
    base = _short(uid).replace("-", "_").replace(".", "_")
    return "".join(c if (c.isalnum() or c == "_") else "_" for c in base).strip("_") or "cleave"


def _policy_resource(uid: str, record: dict, doc: dict) -> tuple[str, str]:
    """(terraform type, resource label) for a collected policy node. Inline policies become
    the identity's inline-policy resource; a customer-managed policy becomes aws_iam_policy.
    An AWS-managed policy has no editable Terraform — callers handle that as a detach."""
    label = _tf_name(uid)
    if "#inline/" in uid:
        identity = uid.split("#inline/", 1)[0]
        kind = {"user": "aws_iam_user_policy", "role": "aws_iam_role_policy",
                "group": "aws_iam_group_policy"}.get(identity.split(":")[-1].split("/")[0])
        return kind or "aws_iam_role_policy", label
    return "aws_iam_policy", label


def _render_policy_tf(uid: str, record: dict, doc: dict) -> str:
    res, label = _policy_resource(uid, record, doc)
    body = json.dumps(doc, indent=2)
    body = "\n".join("    " + ln for ln in body.splitlines())
    head = (f'# Cleave-proposed least-privilege replacement for {_short(uid)}\n'
            f'resource "{res}" "{label}" {{\n'
            f'  name   = "{_short(uid).split("#")[0]}"\n'
            f'  policy = jsonencode(\n{body}\n  )\n}}\n')
    return head


# ---- templates -----------------------------------------------------------------------

def _account_of(uid: str) -> str:
    parts = uid.split(":")
    return parts[4] if uid.startswith("arn:") and len(parts) > 4 and parts[4] else "ACCOUNT"


def _guidance(edge: dict, note: str, impact: str,
              target: str | None = None, title: str | None = None) -> Fix:
    tgt = target or edge.get("to") or edge.get("frm", "")
    return Fix(rel=edge["rel"], target=tgt,
               title=title or f"Review {_short(tgt)}",
               note=note, impact=impact, confidence="guidance")


def _fix_grants_admin(edge: dict, g) -> Fix:
    puid = edge["frm"]
    record = _rec(g, puid)
    doc = record.get("Document")
    # Real AdministratorAccess (AWS-managed, *:*): cannot be edited -> detach + guidance.
    if puid.startswith("arn:aws:iam::aws:policy/") or not doc:
        return _guidance(
            edge,
            f"{_short(puid)} grants administrator access. It is AWS-managed and cannot be "
            "edited; detach it from the identity on this path and attach a policy scoped to "
            "only what that identity needs.",
            "Removes administrator access from whoever holds this policy — confirm the "
            "identity's real duties first.",
            target=puid, title=f"Detach {_short(puid)} (AWS-managed admin)")
    # A customer/inline policy that reaches admin via a primitive: remove the primitive.
    new_doc, removed = _remove_actions(doc, sorted(ADMIN_EQUIVALENT_ACTIONS))
    if not removed:
        return _guidance(edge, f"{_short(puid)} reaches admin; scope its wildcard grant.",
                         "Review the wildcard permission before narrowing it.",
                         target=puid, title=f"Scope {_short(puid)}")
    if _is_empty(new_doc):
        # the policy existed only to grant the escalation — an empty policy is invalid,
        # so detach and delete it rather than emit a broken patch.
        return _guidance(
            edge,
            f"{_short(puid)} grants only {', '.join(sorted(set(removed)))} — its entire "
            "purpose is the escalation. Detach it from every identity that uses it and "
            "delete it; there is nothing in it worth keeping.",
            "Removes the policy entirely — make sure no identity relies on it for anything "
            "else first (it grants only the dangerous action here).",
            target=puid, title=f"Detach and delete {_short(puid)}")
    return Fix(
        rel=edge["rel"], target=puid,
        title=f"Remove admin-equivalent action(s) from {_short(puid)}",
        note=f"{_short(puid)} grants {', '.join(sorted(set(removed)))}, which is a complete "
             "privilege escalation. The replacement policy removes it; the identity keeps "
             "every other permission the policy granted.",
        impact=f"Anything that relied on {', '.join(sorted(set(removed)))} through this "
               "policy stops working — scope it to specific resources instead if a "
               "legitimate workflow needs it.",
        confidence="templated",
        terraform=_render_policy_tf(puid, record, new_doc), policy_json=new_doc,
        apply={"kind": "replace_policy", "uid": puid, "document": new_doc})


def _fix_takeover(edge: dict, g) -> Fix:
    attacker = edge["frm"]
    actions = _TAKEOVER_BY_REL.get(edge["rel"], [])
    account = _account_of(attacker)
    # find the attacker policy that grants the takeover action
    for puid, record in _policy_nodes_of(g, attacker):
        doc = record.get("Document")
        if not (doc and _grants(doc, actions)):
            continue
        if edge["rel"] == "CAN_TAKE_OVER":
            new_doc, changed_acts = _scope_to_self(doc, actions, account)
            verb, how = "Scope", f"to the caller's own user (arn:aws:iam::{account}:user/${{aws:username}})"
        else:
            new_doc, changed_acts = _remove_actions(doc, actions)
            verb, how = "Remove", "from this policy"
        if not changed_acts:
            continue
        if _is_empty(new_doc):
            return _guidance(
                edge, f"{_short(puid)} grants only {', '.join(actions)} — detach it from "
                f"{_short(attacker)} and delete it rather than keeping an empty policy.",
                "Removes the policy entirely; confirm nothing else relies on it.",
                target=puid, title=f"Detach and delete {_short(puid)}")
        acts = ", ".join(sorted(set(changed_acts)))
        return Fix(
            rel=edge["rel"], target=puid,
            title=f"{verb} {acts} on {_short(puid)}",
            note=f"{_short(attacker)} can take over {_short(edge['to'])} because "
                 f"{_short(puid)} grants {acts} on any principal. The replacement scopes it "
                 f"{how}, so it can no longer act on another identity.",
            impact=f"{_short(attacker)} can no longer use {acts} against other principals "
                   "(self-service is preserved where scoping applies).",
            confidence="templated",
            terraform=_render_policy_tf(puid, record, new_doc), policy_json=new_doc,
            apply={"kind": "replace_policy", "uid": puid, "document": new_doc})
    return _guidance(edge, f"Scope {', '.join(actions)} on {_short(attacker)}'s policy.",
                     "Narrowing the resource may affect legitimate self-service.")


def _trust_without_wildcard(trust: dict) -> tuple[dict, bool]:
    """Drop any Allow statement whose Principal is `*` from a role trust policy."""
    changed = False
    kept = []
    for st in _statements(trust):
        if st.get("Effect") == "Allow" and st.get("Principal") == "*":
            changed = True
            continue
        kept.append(st)
    new = {k: v for k, v in trust.items() if k != "Statement"}
    new["Statement"] = kept
    return new, changed


def _specific_assume_grant(doc: dict, role_uid: str) -> bool:
    """True if a policy grants sts:AssumeRole on THIS role by name (not via `*`). Only then
    is removing it a clean, non-over-reaching fix."""
    for st in _statements(doc):
        if st.get("Effect") != "Allow":
            continue
        acts = st.get("Action")
        acts = acts if isinstance(acts, list) else [acts]
        if not any(_glob(str(a), "sts:AssumeRole", ci=True) for a in acts):
            continue
        res = st.get("Resource")
        res = res if isinstance(res, list) else [res]
        if role_uid in [str(r) for r in res]:   # named explicitly, not "*"
            return True
    return False


def _fix_can_assume(edge: dict, g) -> Fix:
    role_uid, assumer = edge["to"], edge["frm"]
    trust = _rec(g, role_uid).get("TrustPolicy") or {}
    # 1) trust allows Principal "*" (anyone): remove that statement outright.
    new_trust, dropped = _trust_without_wildcard(trust)
    if dropped:
        res = "aws_iam_role"
        label = _tf_name(role_uid)
        body = "\n".join("    " + ln for ln in json.dumps(new_trust, indent=2).splitlines())
        tf = (f'# Cleave: remove the wildcard (Principal "*") trust on {_short(role_uid)}\n'
              f'resource "{res}" "{label}" {{\n  name               = "{_short(role_uid)}"\n'
              f'  assume_role_policy = jsonencode(\n{body}\n  )\n}}\n')
        return Fix(rel=edge["rel"], target=role_uid,
                   title=f"Remove the wildcard trust on {_short(role_uid)}",
                   note=f"{_short(role_uid)} can be assumed by ANY principal (its trust "
                        'policy names Principal "*"). The replacement drops that statement.',
                   impact="Only principals named in the remaining trust statements can "
                          "assume the role; add specific ones if the wildcard was load-bearing.",
                   confidence="templated", terraform=tf,
                   apply={"kind": "replace_trust", "uid": role_uid, "trust": new_trust})
    # 2) same-account delegation: the assumer holds sts:AssumeRole on THIS role by name.
    #    Removing that one statement is clean; a wildcard sts:AssumeRole is not (we cannot
    #    know which other roles it legitimately covers) -> guidance.
    for puid, record in _policy_nodes_of(g, assumer):
        doc = record.get("Document")
        if doc and _specific_assume_grant(doc, role_uid):
            new_doc, removed = _remove_actions(doc, ["sts:AssumeRole"])
            if removed:
                return Fix(
                    rel=edge["rel"], target=puid,
                    title=f"Remove sts:AssumeRole on {_short(role_uid)} from {_short(puid)}",
                    note=f"{_short(assumer)} can assume {_short(role_uid)} because "
                         f"{_short(puid)} grants sts:AssumeRole on it. The replacement "
                         "removes that grant.",
                    impact=f"{_short(assumer)} can no longer assume {_short(role_uid)}; "
                           "other roles it may assume are unaffected (the grant named this "
                           "role explicitly).",
                    confidence="templated",
                    terraform=_render_policy_tf(puid, record, new_doc), policy_json=new_doc,
                    apply={"kind": "replace_policy", "uid": puid, "document": new_doc})
    acct = _account_of(assumer)
    if _account_of(role_uid) and _account_of(role_uid) != acct:
        why = ("The role trusts another account. If that cross-account access is intended, "
               "add an sts:ExternalId condition to the trust; otherwise remove the "
               "cross-account principal from the trust policy.")
    else:
        why = ("Tighten the role's trust policy to name only the principals that must "
               "assume it, or remove the broad sts:AssumeRole grant from the caller.")
    return _guidance(edge, why,
                     "Trust/assume changes can break legitimate role switching — confirm "
                     "who needs this role before narrowing it.")


def _fix_can_launch_as(edge: dict, g) -> Fix:
    return _guidance(
        edge,
        f"{_short(edge['frm'])} can run code as {_short(edge['to'])} by passing it to a "
        "compute service (iam:PassRole + a launch action). Cut it by one of: scope "
        "iam:PassRole away from this role, add an iam:PassedToService condition limiting "
        "which services the role may be passed to, or remove the launch permission — which "
        "one depends on what this principal legitimately runs.",
        "Removing PassRole or the launch permission can break deployments that legitimately "
        "run workloads as this role.")


def _public_ingress(rule: dict) -> bool:
    cidrs = {r.get("CidrIp") for r in rule.get("IpRanges", [])}
    cidrs |= {r.get("CidrIpv6") for r in rule.get("Ipv6Ranges", [])}
    return "0.0.0.0/0" in cidrs or "::/0" in cidrs


def _sgs_of(g, resource_uid: str) -> list[str]:
    rec = _rec(g, resource_uid)
    return rec.get("SecurityGroups") or rec.get("VpcSecurityGroups") or []


def _fix_can_reach(edge: dict, g) -> Fix:
    """Narrow the internet-open security-group rules that make the resource reachable.

    Templated: drop every ingress rule open to 0.0.0.0/0 (or ::/0) from the SGs on the
    resource. The impact note is explicit -- this blocks ALL inbound from the internet on
    those ports -- because the legitimate source CIDR is a judgement only the owner has."""
    resource = edge["to"]
    offending = []   # (sg_uid, sg_record, kept_ingress, dropped_ports)
    for sg_uid in _sgs_of(g, resource):
        sg = _rec(g, sg_uid)
        ingress = sg.get("IngressRules") or []
        public = [r for r in ingress if _public_ingress(r)]
        if public:
            kept = [r for r in ingress if not _public_ingress(r)]
            ports = ", ".join(sorted({str(r.get("FromPort", "all")) for r in public}))
            offending.append((sg_uid, sg, kept, ports))
    if not offending:
        return _guidance(
            edge, f"Reach {_short(resource)} is open from the internet; restrict the "
            "security-group ingress to known source IP ranges.",
            "Restricting inbound can cut off legitimate clients — confirm who connects.")
    blocks, apply_sgs, all_ports = [], [], set()
    for sg_uid, sg, kept, ports in offending:
        all_ports.add(ports)
        label = _tf_name(sg_uid)
        rules = "\n".join("    " + ln for ln in json.dumps(kept, indent=2).splitlines())
        blocks.append(
            f'# Cleave: remove the 0.0.0.0/0 ingress (ports {ports}) from {sg.get("GroupName") or sg_uid}\n'
            f'resource "aws_security_group" "{label}" {{\n'
            f'  name = "{sg.get("GroupName") or _short(sg_uid)}"\n'
            f'  # ingress with the internet-open rule(s) removed:\n'
            f'  ingress = jsonencode(\n{rules}\n  )\n}}\n')
        apply_sgs.append({"uid": sg_uid, "ingress": kept})
    return Fix(
        rel=edge["rel"], target=resource,
        title=f"Remove internet-open ingress reaching {_short(resource)}",
        note=f"{_short(resource)} is reachable from the internet because "
             f"{len(offending)} security group(s) allow inbound from 0.0.0.0/0 on ports "
             f"{', '.join(sorted(all_ports))}. The replacement drops those rules.",
        impact="Blocks ALL inbound from the internet on those ports — add your specific "
               "source CIDR(s) back if legitimate clients connect from outside.",
        confidence="templated", terraform="\n".join(blocks),
        apply={"kind": "narrow_sg", "security_groups": apply_sgs})


_TEMPLATES = {
    "GRANTS_ADMIN": _fix_grants_admin,
    "CAN_TAKE_OVER": _fix_takeover,
    "CAN_JOIN_GROUP": _fix_takeover,
    "CAN_REWRITE_TRUST": _fix_takeover,
    "CAN_ASSUME": _fix_can_assume,
    "CAN_LAUNCH_AS": _fix_can_launch_as,
    "CAN_REACH": _fix_can_reach,
}


def _fix_public_bucket(bucket_uid: str, g) -> Fix:
    """A public S3 bucket is where an external path STARTS, not a cut edge. The fix is to
    stop it being public: a Public Access Block with all four switches on, which overrides
    any public bucket policy or ACL. Templated and verifiable (the bucket stops being a
    source once applied)."""
    # the bucket NAME, not the ARN: s3 arns are arn:aws:s3:::<name>[/<key>]
    name = (_rec(g, bucket_uid).get("Name")
            or bucket_uid.replace("arn:aws:s3:::", "").split("/")[0])
    label = _tf_name(name)
    tf = (f'# Cleave: block all public access to {name} (overrides public policy/ACL)\n'
          f'resource "aws_s3_bucket_public_access_block" "{label}" {{\n'
          f'  bucket                  = "{name}"\n'
          f'  block_public_acls       = true\n'
          f'  block_public_policy     = true\n'
          f'  ignore_public_acls      = true\n'
          f'  restrict_public_buckets = true\n}}\n')
    return Fix(
        rel="PUBLIC_BUCKET", target=bucket_uid,
        title=f"Block public access to {name}",
        note=f"{name} is readable from the internet, which is where this attack path "
             "starts. A Public Access Block with all four settings on makes it private "
             "regardless of its bucket policy or ACL.",
        impact=f"Anything that legitimately reads {name} anonymously over the internet "
               "(a public website, public dataset) stops working — confirm it is not a "
               "deliberately public bucket first.",
        confidence="templated", terraform=tf,
        apply={"kind": "block_public", "uid": bucket_uid})


def generate(edge: dict, g) -> Fix:
    """Turn one cut edge into a Fix. Unknown edge types return guidance, never a guess."""
    tmpl = _TEMPLATES.get(edge["rel"])
    if tmpl is None:
        return _guidance(
            edge, edge.get("fix", "review and scope this relationship"),
            "No templated fix for this edge type yet; apply the guidance by hand.")
    return tmpl(edge, g)


def _public_bucket_sources(result: dict, g) -> list[str]:
    """Bucket uids that are public and start at least one path — deduplicated, in path
    order. These get a source-level Public Access Block fix on top of the edge cuts."""
    from ..paths.endpoints import bucket_public_reason
    seen, out = set(), []
    for p in result.get("paths", []):
        src = p.get("source", {})
        uid = src.get("uid")
        if src.get("kind") != "EXTERNAL" or uid in seen or uid not in g:
            continue
        seen.add(uid)
        if g.nodes[uid].get("label") == "S3Bucket" and bucket_public_reason(_rec(g, uid)):
            out.append(uid)
    return out


def generate_for_result(result: dict, g) -> list[dict]:
    """A Fix (as dict) for the minimum cut, plus a Public Access Block for every public S3
    bucket that an external path starts from (a source-level fix, not an edge)."""
    fixes = [generate(e, g).to_dict()
             for e in result.get("minimum_cut", {}).get("edges", [])]
    fixes += [_fix_public_bucket(uid, g).to_dict()
              for uid in _public_bucket_sources(result, g)]
    return fixes
