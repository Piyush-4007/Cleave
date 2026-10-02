"""Render a gate result as a GitHub PR comment (Phase 9).

The handbook's "done when": a PR that introduces a path gets blocked with the rendered path
in the comment. This produces that markdown — the new route(s), and the scoped alternative
(the Phase-8 fix for the minimum cut) so the reviewer sees both the problem and the fix.
The GitHub App (stage 4) posts this; it is pure text so it is trivial to test.
"""
from __future__ import annotations


def render_comment(result: dict, age: str | None = None) -> str:
    n = result["introduced"]
    if not n:
        lines = ["### ✅ Cleave — no new attack paths",
                 "",
                 f"This change opens no route to admin or sensitive data that didn't already "
                 f"exist. ({result['paths_before']} path(s) before, {result['paths_after']} after"
                 + (f", {result['paths_removed']} removed" if result.get("paths_removed") else "")
                 + ")."]
    else:
        lines = [f"### ⛔ Cleave — this change introduces {n} new attack path(s)",
                 "",
                 "A linter sees individual resources; Cleave sees the **route**. This PR opens "
                 "the following path(s) that do not exist on the live account today:"]
        for i, np in enumerate(result["new_paths"], 1):
            lines += [f"\n**Path {i}** — {np['source']['kind']} → {np['sink']['kind']} "
                      f"({np['length']} hops, {np['confidence']})",
                      "```", np["narration"].rstrip(), "```"]
        rem = [f for f in result.get("remediation", []) if f.get("confidence") == "templated"]
        if rem:
            lines += ["\n#### Scoped alternative",
                      "Cutting the choke point(s) below stops every new path. Proposed Terraform:"]
            for f in rem:
                lines += [f"\n*{f['title']}* — {f['impact']}", "```hcl",
                          (f.get("terraform") or "").rstrip(), "```"]
        guidance = [f for f in result.get("remediation", []) if f.get("confidence") != "templated"]
        for f in guidance:
            lines.append(f"\n> **{f['title']}** — {f['note']}")

    if age:
        lines += ["", f"<sub>Compared against the live account graph ({age}). Cleave has "
                  "read-only access and changes nothing itself.</sub>"]
    return "\n".join(lines) + "\n"
