"""Who a scan ran as: the data behind the connected-account panel.

Everything here comes from the sts:GetCallerIdentity ARN plus the scanned graph. There's
no extra AWS call; the account alias is fetched by the collector run, not here.
"""
from __future__ import annotations
import networkx as nx


def principal_uid(g: nx.DiGraph, arn: str) -> str | None:
    """The graph node for the caller. An assumed-role ARN carries the role name but not
    its path (`assumed-role/Name/session`), so roles are matched by name."""
    if arn in g:
        return arn
    if ":assumed-role/" in arn:
        name = arn.split(":assumed-role/", 1)[1].split("/", 1)[0]
        for uid, d in g.nodes(data=True):
            if d.get("label") == "IamRole" and (d.get("record") or {}).get("RoleName") == name:
                return uid
    return None


def caller_identity(arn: str, g: nx.DiGraph | None = None) -> dict:
    """Parse a caller ARN into what the panel shows, and (given the scanned graph) whether
    those credentials are full admin."""
    resource = arn.split(":", 5)[-1] if arn.count(":") >= 5 else arn
    out = {"arn": arn, "principal_type": "unknown", "principal_name": resource,
           "session": None, "admin_credentials": None}
    if resource == "root":
        out.update(principal_type="root", principal_name="root account")
    elif resource.startswith("user/"):
        out.update(principal_type="user", principal_name=resource.rsplit("/", 1)[-1])
    elif resource.startswith("assumed-role/"):
        _, role, *session = resource.split("/")
        out.update(principal_type="role", principal_name=role,
                   session=session[0] if session else None)

    if g is not None:
        if out["principal_type"] == "root":
            out["admin_credentials"] = True
        else:
            from .paths.endpoints import holds_full_admin
            uid = principal_uid(g, arn)
            out["admin_credentials"] = bool(uid and holds_full_admin(g, uid))
    return out
