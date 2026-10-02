"""The remediation output shape (Phase 8).

A `Fix` is Cleave's answer to one cut edge: a corrected resource as Terraform, the
plain-English blast radius, and an honest confidence. Two confidences, and the split is
the whole safety story:

  "templated"  Cleave rewrote the actual resource it collected (removed the dangerous
               grant, tightened the trust, narrowed the CIDR). The corrected resource is
               in `terraform`, and `verify` can prove the path is gone by re-running the
               search with it applied. A patch that is wrong is worse than no patch, so
               this is only claimed when the transform is exact.
  "guidance"   Cleave cannot safely generate the resource (it does not hold it, or editing
               it would need a judgement only the owner can make — e.g. which ARNs a team
               legitimately needs). `terraform` is None; `note` says what to do by hand.

Never a direct apply, ever: a Fix is only ever rendered into a pull request for a human to
approve. Cleave holds no AWS write credentials (handbook Phase 8 security rule).
"""
from __future__ import annotations
from dataclasses import dataclass, field


@dataclass
class Fix:
    rel: str                       # the cut edge type this fixes
    target: str                    # uid of the resource the fix changes
    title: str                     # one line, e.g. "Scope iam:CreateAccessKey on dev-policy"
    note: str                      # what the change does and why it cuts the path
    impact: str                    # "this might break X" — the honest blast radius
    confidence: str                # "templated" | "guidance"
    terraform: str | None = None   # corrected resource as HCL, or None for guidance
    policy_json: dict | None = None  # corrected policy document, when the fix is a policy
    # how verify() applies this fix to the records before re-running the search:
    #   {"kind": "replace_policy", "uid": ..., "document": {...}}
    #   {"kind": "detach_policy",  "principal": ..., "policy": ...}
    #   {"kind": "replace_trust",  "uid": ..., "trust": {...}}
    #   {"kind": "narrow_sg",      ...}   (added as templates land)
    apply: dict = field(default_factory=dict)

    def to_dict(self) -> dict:
        return {
            "rel": self.rel, "target": self.target, "title": self.title,
            "note": self.note, "impact": self.impact, "confidence": self.confidence,
            "terraform": self.terraform, "policy_json": self.policy_json,
            "apply": self.apply,
        }
