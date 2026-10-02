"""Verification loop (Phase 8): prove a fix actually cuts the path, before anyone merges it.

The handbook's "done when": click fix -> PR -> rescan -> path confirmed gone. Against a
live account the rescan is a real scan; here, and in tests, we apply the fix to the
collected records and re-run the exact same search. Same engine, so "the path is gone"
means gone, not approximately gone.

`apply_fix` is a pure transform over records (never touches AWS). `path_is_cut` returns
whether a specific path signature survives the fix, and `verify_fixes` folds a set of
fixes together (the minimum cut should remove every path).
"""
from __future__ import annotations
import copy
from ..paths.graphview import graph_from_records
from ..paths.search import find_paths


def _apply_one(records: list[dict], fix: dict) -> list[dict]:
    """Return records with one fix applied. Inline-policy edits are written back onto the
    owning identity; managed-policy edits onto the policy record."""
    ap = fix.get("apply") or {}
    kind = ap.get("kind")
    out = copy.deepcopy(records)
    by_id = {r["_id"]: r for r in out}

    if kind == "replace_policy":
        uid, doc = ap["uid"], ap["document"]
        if "#inline/" in uid:
            identity, name = uid.split("#inline/", 1)
            owner = by_id.get(identity)
            if owner is not None:
                owner.setdefault("InlinePolicies", {})[name] = doc
        elif uid in by_id:
            by_id[uid]["Document"] = doc
    elif kind == "detach_policy":
        owner = by_id.get(ap["principal"])
        if owner is not None:
            owner["AttachedPolicies"] = [p for p in owner.get("AttachedPolicies", [])
                                         if p != ap["policy"]]
    elif kind == "replace_trust":
        if ap["uid"] in by_id:
            by_id[ap["uid"]]["TrustPolicy"] = ap["trust"]
    elif kind == "narrow_sg":
        for sg in ap.get("security_groups", []):
            if sg["uid"] in by_id:
                by_id[sg["uid"]]["IngressRules"] = sg["ingress"]
    # unknown / guidance-only fixes change nothing (they carry no `apply`)
    return out


def apply_fixes(records: list[dict], fixes: list[dict]) -> list[dict]:
    for f in fixes:
        records = _apply_one(records, f)
    return records


def _signatures(paths) -> set[tuple]:
    return {(p.source.uid, p.sink.uid, tuple(p.nodes)) for p in paths}


def verify_fixes(records: list[dict], fixes: list[dict], cred_findings=()) -> dict:
    """Apply `fixes` to `records`, re-run the search, and report what changed.

    Returns {"paths_before", "paths_after", "removed", "remaining"} where removed/remaining
    are counts of distinct path signatures. `removed == paths_before and remaining == 0`
    is the minimum cut doing its job."""
    before = find_paths(graph_from_records(records, cred_findings))
    after = find_paths(graph_from_records(apply_fixes(records, fixes), cred_findings))
    sb, sa = _signatures(before), _signatures(after)
    return {
        "paths_before": len(sb),
        "paths_after": len(sa),
        "removed": len(sb - sa),
        "remaining": len(sa),
        "fully_cut": sa.isdisjoint(sb) and bool(sb),
    }
