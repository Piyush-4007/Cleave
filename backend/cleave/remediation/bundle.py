"""Package a set of fixes for the "personal" delivery: a folder of Terraform the user
reviews and applies themselves (handbook Phase 8, no GitHub needed).

`write_bundle` writes one `.tf` file per templated fix plus a `REMEDIATION.md` that lists
every fix, its blast radius, and the guidance-only items (which have no patch). The user
runs `terraform plan` on the folder, reviews, applies, then rescans in Cleave to confirm
the path is gone. Nothing here touches AWS or GitHub.
"""
from __future__ import annotations
import pathlib


def _slug(text: str) -> str:
    keep = [c if (c.isalnum() or c in "-_") else "-" for c in text.split("/")[-1]]
    return "".join(keep).strip("-")[:50] or "fix"


def bundle_files(fixes: list[dict]) -> dict[str, str]:
    """{filename: contents} for a set of fixes, without touching disk (easy to test, and
    the desktop can stream the same files for a Download)."""
    files: dict[str, str] = {}
    md = ["# Cleave remediation\n",
          "Proposed changes that cut the attack paths Cleave found. **Review each one, run "
          "`terraform plan`, then apply** — Cleave never changes your account itself.\n",
          "After applying, rescan in Cleave to confirm the paths are gone.\n"]
    n = 0
    for fix in fixes:
        title = fix.get("title", "fix")
        md.append(f"\n## {title}")
        md.append(f"- **edge:** `{fix.get('rel')}`  →  `{fix.get('target')}`")
        md.append(f"- **what it does:** {fix.get('note', '')}")
        md.append(f"- **might break:** {fix.get('impact', '')}")
        if fix.get("confidence") == "templated" and fix.get("terraform"):
            n += 1
            fname = f"{n:02d}-{_slug(fix.get('target', title))}.tf"
            files[fname] = (f"# {title}\n# {fix.get('note', '')}\n"
                            f"# WARNING (might break): {fix.get('impact', '')}\n\n"
                            f"{fix['terraform']}")
            md.append(f"- **patch:** `{fname}`")
        else:
            md.append("- **patch:** none — apply the guidance above by hand "
                      "(Cleave cannot generate a safe patch for this one).")
    files["REMEDIATION.md"] = "\n".join(md) + "\n"
    return files


def write_bundle(fixes: list[dict], out_dir: str | pathlib.Path) -> pathlib.Path:
    out = pathlib.Path(out_dir)
    out.mkdir(parents=True, exist_ok=True)
    for name, content in bundle_files(fixes).items():
        (out / name).write_text(content, encoding="utf-8")
    return out
