"""Plain-language summary of an attack path, for a reader who does not know IAM.

Every hop already has a known relationship type, so one fixed sentence per type is enough.
Deterministic, no model: the same path always yields the same words. It restates the path
the search found and adds nothing to it — the hops and their evidence stay the record.
"""
from __future__ import annotations
import re

# What to call each kind of thing in everyday words.
_NOUN = {
    "IamUser": "the user", "IamRole": "the role", "IamGroup": "the group",
    "IamPolicy": "the permission set", "S3Bucket": "the storage bucket",
    "Ec2Instance": "the server", "LambdaFunction": "the function",
    "RdsInstance": "the database", "DynamoDbTable": "the database table",
    "SecretsManagerSecret": "the stored secret", "GlueJob": "the data job",
    "SageMakerNotebook": "the notebook", "CodeBuildProject": "the build project",
    "EcsService": "the container service", "ApiGatewayApi": "the web API",
}

_ACTION = re.compile(r"'([A-Za-z0-9*]+:[A-Za-z0-9*]+)'")


def _thing(node: dict) -> str:
    noun = _NOUN.get(node.get("label", ""), "")
    return f"{noun} {node['name']}".strip()


def _cap(s: str) -> str:
    return s[:1].upper() + s[1:]


def _opening(src_kind: str, first: dict) -> str:
    label = first.get("label")
    if src_kind == "EXTERNAL":
        if label == "Internet":
            return "An attacker on the internet can start this without any login."
        if label == "S3Bucket":
            return f"Anyone on the internet can read {_thing(first)}, with no login."
        return f"{_cap(_thing(first))} can be reached by anyone on the internet."
    if label == "IamRole":
        return (f"Suppose someone gets to act as {_thing(first)}, for example through the "
                "system or automation that uses it.")
    return f"Suppose the login for {_thing(first)} is stolen or misused."


def _sentence(rel: str, a: dict, b: dict, reason: str, holder: dict) -> str | None:
    A, B = _cap(_thing(a)), _thing(b)
    if rel == "CAN_REACH":
        return f"From there they can connect to {B}."
    if rel in ("HAS_INSTANCE_PROFILE", "EXECUTES_AS", "CONTAINS_ROLE"):
        return f"{A} runs with the permissions of {B}, so controlling it means having those permissions."
    if rel == "CAN_READ":
        return f"{A} can read what is inside {B}."
    if rel == "CAN_WRITE":
        return f"{A} can change {B}."
    if rel == "CONTAINS_CREDENTIAL":
        return f"{A} holds a saved login key that belongs to {B}, so whoever reads it can act as {B}."
    if rel == "CAN_ASSUME":
        return f"{A} is allowed to switch into {B}."
    if rel == "CAN_LAUNCH_AS":
        return (f"{A} can start something new (a function, server or job) that runs as {B}, "
                "and so borrow its permissions.")
    if rel == "CAN_TAKE_OVER":
        return f"{A} can create a new login for {B} and act as them."
    if rel == "CAN_JOIN_GROUP":
        return f"{A} can add itself to {B} and gain everything that group is allowed to do."
    if rel == "CAN_REWRITE_TRUST":
        return f"{A} can change who is allowed to use {B}, and let itself in."
    if rel == "IN_GROUP":
        return f"{A} is a member of {B}."
    if rel == "HAS_ATTACHED":
        return None  # folded into the sentence about what that permission set allows
    if rel == "GRANTS_ADMIN":
        who = _cap(_thing(holder))
        m = _ACTION.search(reason or "")
        if m and m.group(1) not in ("*:*",):
            return (f"{who} holds a permission ({m.group(1)}) that lets it give itself full "
                    "control of the account.")
        return f"{who} has full administrator permissions, which means complete control of the account."
    return f"{A} leads to {B}."


def plain_summary(path: dict) -> str:
    """`path` is a ranked path dict that already carries `view` (one entry per node)."""
    view, hops = path.get("view") or [], path.get("hops") or []
    if not view or len(view) != len(hops) + 1:
        return ""
    out = [_opening((path.get("source") or {}).get("kind", ""), view[0])]
    holder = view[0]
    for i, h in enumerate(hops):
        a, b = view[i], view[i + 1]
        if a.get("label") != "IamPolicy":
            holder = a  # the last identity or resource before any permission set
        s = _sentence(h.get("rel", ""), a, b, h.get("reason", ""), holder)
        if s:
            out.append(s)
    if (path.get("sink") or {}).get("kind") == "SENSITIVE_DATA":
        out.append(f"{_cap(_thing(view[-1]))} is marked as sensitive, so this ends with that data exposed.")
    if path.get("confidence") == "Possible":
        out.append("At least one step depends on conditions that cannot be confirmed from "
                   "configuration alone, so this is possible rather than certain.")
    return " ".join(out)
