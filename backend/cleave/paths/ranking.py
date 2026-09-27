"""Path ranking (Phase 5).

Turns a flat list of attack paths into a ranked, de-duplicated one. The score is a plain
weighted sum (weights in policy.json) so a reviewer can recompute any number by hand — no
model, no hidden math. Every path carries the breakdown that produced its score.
"""
from __future__ import annotations
import functools
import json
import pathlib
from .model import AttackPath, EXTERNAL

POLICY_PATH = pathlib.Path(__file__).with_name("policy.json")


def _strip_comments(obj):
    """Drop `_comment`/`_`-prefixed keys so weight/cost dicts sum cleanly and stay
    hand-annotatable."""
    if isinstance(obj, dict):
        return {k: _strip_comments(v) for k, v in obj.items() if not k.startswith("_")}
    return obj


@functools.lru_cache(maxsize=1)
def load_policy() -> dict:
    return _strip_comments(json.loads(POLICY_PATH.read_text()))


def sensitive_reason(uid: str, rec: dict) -> str | None:
    """Why this data store is sensitive, or None. Reads a tag or an explicit ARN list from
    policy.json — the account owner's own classification, never Cleave's guess. This is the
    ONE signal; there is no heuristic that decides data is 'production' on its own."""
    rule = load_policy().get("sensitive_data", {})
    if uid in set(rule.get("arns", [])):
        return "listed in policy.json sensitive_data.arns"
    keys = {k.lower() for k in rule.get("tag_keys", [])}
    values = {v.lower() for v in rule.get("tag_values", [])}
    for k, v in (rec.get("Tags") or {}).items():
        if k.lower() in keys and str(v).lower() in values:
            return f"tag {k}={v}"
    return None


# ---- documented-technique catalogue --------------------------------------------------
# Maps an ordered edge-type signature (a subsequence that must appear in the path, in
# order) to the published technique it is. Small on purpose — a named technique is a real
# claim, so each entry points at where we walked it. Grow it as scenarios are added.
TECHNIQUES = [
    {"name": "PassRole + RunInstances (instance-profile escalation)",
     "signature": ("CAN_LAUNCH_AS",),
     "ref": "Phase 0 scenario 2 — screenshots/phase0-iam_privesc_by_attachment"},
    {"name": "Credential exposed in storage, reused",
     "signature": ("CONTAINS_CREDENTIAL",),
     "ref": "handbook headline example — public bucket holding a credentials file"},
    {"name": "Read-then-steal (bucket read yields a live key)",
     "signature": ("CAN_READ", "CONTAINS_CREDENTIAL"),
     "ref": "Phase 4 increment 2 — credential-theft chain"},
    {"name": "Lambda code overwrite (act as the execution role)",
     "signature": ("CAN_WRITE", "EXECUTES_AS"),
     "ref": "handbook Phase 8 remediation set — lambda:UpdateFunctionCode"},
]


def _matches(signature: tuple, rels: list[str]) -> bool:
    """Is `signature` an ordered subsequence of `rels`?"""
    it = iter(rels)
    return all(any(r == s for r in it) for s in signature)


def detect_technique(path: AttackPath) -> dict | None:
    rels = [h.rel for h in path.hops]
    for t in TECHNIQUES:
        if _matches(t["signature"], rels):
            return t
    return None


# ---- production-data sink -------------------------------------------------------------
# The production-data factor fires when the path's sink is a sensitive data store, per the
# owner-supplied tag/ARN rule in policy.json (see sensitive_reason). No tag, no factor.
def _is_production_sink(path: AttackPath, g) -> bool:
    """A path scores the production-data factor when its sink IS a sensitive data store.
    Uses the same classifier find_sinks does, so the score and the sink agree."""
    if path.sink.kind == "SENSITIVE_DATA":
        return True
    if g is None:
        return False
    rec = (g.nodes.get(path.sink.uid, {}) or {}).get("record") or {}
    return sensitive_reason(path.sink.uid, rec) is not None


# ---- scoring --------------------------------------------------------------------------

def score(path: AttackPath, g=None) -> dict:
    """Return {score: 0-10, raw, max, factors: {name: points}}. `g` (optional) lets the
    production-data-sink factor read a tag off the sink node."""
    w = load_policy()["score_weights"]
    sp = load_policy()["short_path"]
    factors: dict[str, float] = {}

    if path.source.kind == EXTERNAL:
        factors["unauthenticated_source"] = w["unauthenticated_source"]

    # shorter is worse (more direct). Full bonus at the min hop count, fading linearly to
    # 0 at the hop limit. HOP_LIMIT here must track search.MAX_HOPS.
    HOP_LIMIT = 6
    full_at = sp["min_hops_for_full_bonus"]
    span = max(1, HOP_LIMIT - full_at)
    if path.length <= full_at:
        factors["short_path_bonus"] = w["short_path_bonus"]
    else:
        frac = max(0.0, (HOP_LIMIT - path.length) / span)
        if frac:
            factors["short_path_bonus"] = round(w["short_path_bonus"] * frac, 3)

    if path.sink.kind == "ADMIN":
        factors["admin_sink"] = w["admin_sink"]
    if _is_production_sink(path, g):
        factors["production_data_sink"] = w["production_data_sink"]
    if path.confidence == "Certain":
        factors["all_certain_edges"] = w["all_certain_edges"]

    tech = detect_technique(path)
    if tech:
        factors["documented_technique"] = w["documented_technique"]

    # cross-account: any hop crossing account boundaries (v2 territory; 0 for now unless
    # a source/sink ARN differs in account — cheap to detect, honest to include).
    if _crosses_account(path):
        factors["cross_account"] = w["cross_account"]

    raw = sum(factors.values())
    max_raw = sum(w.values())
    return {
        "score": round(10 * raw / max_raw, 2),
        "raw": round(raw, 3),
        "max": round(max_raw, 3),
        "factors": factors,
        "technique": tech["name"] if tech else None,
    }


def _account(uid: str) -> str | None:
    if uid.startswith("arn:"):
        parts = uid.split(":")
        return parts[4] or None if len(parts) > 4 else None
    return None


def _crosses_account(path: AttackPath) -> bool:
    accts = {a for a in (_account(n) for n in path.nodes) if a}
    return len(accts) > 1


# ---- ranking + dedup ------------------------------------------------------------------

def rank(paths: list[AttackPath], g=None) -> list[dict]:
    """Score every path, group variants by dedup_key (source, sink, edge-type tuple),
    keep the highest scorer per group, and return them highest-score-first.

    Each returned dict is the path's as_dict() plus `ranking` (the score breakdown) and
    `variants` (how many raw paths collapsed into it)."""
    scored = [(p, score(p, g)) for p in paths]

    best_by_key: dict[tuple, tuple] = {}
    counts: dict[tuple, int] = {}
    for p, sc in scored:
        key = p.dedup_key
        counts[key] = counts.get(key, 0) + 1
        if key not in best_by_key or sc["score"] > best_by_key[key][1]["score"]:
            best_by_key[key] = (p, sc)

    out = []
    for key, (p, sc) in best_by_key.items():
        d = p.as_dict()
        d["ranking"] = sc
        d["variants"] = counts[key]
        out.append(d)

    out.sort(key=lambda d: (-d["ranking"]["score"], d["length"], d["source"]["uid"]))
    for i, d in enumerate(out, 1):
        d["rank"] = i
        d["id"] = f"PATH-{i:03d}"
    return out
