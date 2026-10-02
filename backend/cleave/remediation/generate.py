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


def _guidance(edge: dict, note: str, impact: str) -> Fix:
    return Fix(rel=edge["rel"], target=edge.get("to") or edge.get("frm", ""),
               title=f"Review: {edge.get('fix', 'scope this permission')}",
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
            "identity's real duties first.")
    # A customer/inline policy that reaches admin via a primitive: remove the primitive.
    new_doc, removed = _remove_actions(doc, sorted(ADMIN_EQUIVALENT_ACTIONS))
    if not removed:
        return _guidance(edge, f"{_short(puid)} reaches admin; scope its wildcard grant.",
                         "Review the wildcard permission before narrowing it.")
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


_TEMPLATES = {
    "GRANTS_ADMIN": _fix_grants_admin,
    "CAN_TAKE_OVER": _fix_takeover,
    "CAN_JOIN_GROUP": _fix_takeover,
    "CAN_REWRITE_TRUST": _fix_takeover,
}


def generate(edge: dict, g) -> Fix:
    """Turn one cut edge into a Fix. Unknown edge types return guidance, never a guess."""
    tmpl = _TEMPLATES.get(edge["rel"])
    if tmpl is None:
        return _guidance(
            edge, edge.get("fix", "review and scope this relationship"),
            "No templated fix for this edge type yet; apply the guidance by hand.")
    return tmpl(edge, g)


def generate_for_result(result: dict, g) -> list[dict]:
    """A Fix (as dict) for each edge in the minimum cut of an analysis result."""
    return [generate(e, g).to_dict() for e in result.get("minimum_cut", {}).get("edges", [])]
