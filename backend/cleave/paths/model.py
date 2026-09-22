"""Path-search data model (Phase 4).

A path is a *story*: start as somebody, take a sequence of steps each justified by a real
attacker action, end holding administrative control. Every hop carries the four-field
edge contract from graph/SCHEMA.md, so "why does this hop exist?" always has an answer.
"""
from __future__ import annotations
from dataclasses import dataclass, field

# --- source classes -------------------------------------------------------------------
# EXTERNAL           an unauthenticated attacker on the internet can start here.
# ASSUMED_COMPROMISE a principal that is not already an administrator; the path answers
#                    "if this credential leaked, what could it reach?". This is the
#                    standard framing in the IAM-escalation literature (PMapper asks the
#                    same question) and it is what makes IAM-only findings visible at all
#                    — an account with no internet-facing resource still has privesc.
EXTERNAL = "EXTERNAL"
ASSUMED_COMPROMISE = "ASSUMED_COMPROMISE"


@dataclass(frozen=True)
class Source:
    uid: str
    kind: str        # EXTERNAL | ASSUMED_COMPROMISE
    reason: str      # why this is a plausible starting point
    evidence: str    # the config element that proves it


@dataclass(frozen=True)
class Sink:
    uid: str
    kind: str        # v1: "ADMIN"
    reason: str


@dataclass(frozen=True)
class Hop:
    """One traversal. Mirrors the edge property contract."""
    frm: str
    to: str
    rel: str
    reason: str
    evidence: str
    confidence: str          # Certain | Possible
    discovered_by: str
    alternatives: tuple = ()  # other relationship types between the same two nodes


@dataclass
class AttackPath:
    source: Source
    sink: Sink
    nodes: list[str]
    hops: list[Hop]

    @property
    def length(self) -> int:
        return len(self.hops)

    @property
    def confidence(self) -> str:
        """A path is only as certain as its weakest hop."""
        return "Possible" if any(h.confidence != "Certain" for h in self.hops) else "Certain"

    @property
    def dedup_key(self) -> tuple:
        """Phase 5 groups variants of the same route by this and shows the top scorer."""
        return (self.source.uid, self.sink.uid, tuple(h.rel for h in self.hops))

    def narrate(self) -> str:
        """Plain-text hop-by-hop. Deterministic — the LLM (Phase 6) prettifies this, it
        never produces it, so switching the model off loses nothing but prose."""
        lines = [f"[{self.source.kind}] {_short(self.source.uid)} — {self.source.reason}"]
        for i, h in enumerate(self.hops, 1):
            alt = f"  (also: {', '.join(h.alternatives)})" if h.alternatives else ""
            lines.append(f"  {i}. --{h.rel}--> {_short(h.to)}"
                         f"  [{h.confidence}] {h.reason}{alt}")
        return "\n".join(lines)

    def as_dict(self) -> dict:
        return {
            "source": {"uid": self.source.uid, "kind": self.source.kind,
                       "reason": self.source.reason, "evidence": self.source.evidence},
            "sink": {"uid": self.sink.uid, "kind": self.sink.kind},
            "length": self.length, "confidence": self.confidence,
            "nodes": self.nodes,
            "hops": [{"frm": h.frm, "to": h.to, "rel": h.rel, "reason": h.reason,
                      "evidence": h.evidence, "confidence": h.confidence,
                      "discovered_by": h.discovered_by,
                      "alternatives": list(h.alternatives)} for h in self.hops],
        }


def _short(uid: str) -> str:
    """Readable tail of an ARN, keeping enough to stay unambiguous."""
    if uid.startswith("arn:"):
        tail = uid.split(":", 5)[-1]
        return tail if len(tail) < 60 else "…" + tail[-57:]
    return uid
