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
    # last path segment, then last ARN/colon segment: "arn:aws:s3:::public-dump" -> "public-dump",
    # "arn:aws:iam::1:policy/foo" -> "foo"
    base = text.split("/")[-1].split(":")[-1]
    keep = [c if (c.isalnum() or c in "-_") else "-" for c in base]
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
        md.append(f"- **edge:** `{fix.get('rel')}`  ->  `{fix.get('target')}`")
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
    if n:
        files["providers.tf"] = _providers_tf(fixes)
        md[3:3] = ["\n## How to apply\n",
                   "1. Put these files in an empty folder, with AWS credentials for the "
                   "account in your environment (an admin, not the read-only CleaveAudit role).",
                   "2. `terraform init`",
                   "3. `terraform plan` — check it changes only the resources listed below "
                   "(existing ones are imported and updated in place, not recreated).",
                   "4. `terraform apply`, then rescan in Cleave.\n"]
    files["REMEDIATION.md"] = "\n".join(md) + "\n"
    return files


def _providers_tf(fixes: list[dict]) -> str:
    """Makes the bundle a complete root module, so `terraform init && terraform apply` works
    on the folder as downloaded. The region is the first fix's (S3 patches must run in the
    bucket's region; IAM is global). Credentials are never written here."""
    region = next((f["region"] for f in fixes if f.get("region")), None) or "us-east-1"
    return ("# Lets this folder be applied on its own: terraform init, then terraform apply.\n"
            "# Credentials come from your environment (AWS profile / env vars), never this file.\n"
            "# Existing resources are adopted with import blocks, which need Terraform >= 1.5.\n"
            "terraform {\n"
            '  required_version = ">= 1.5"\n'
            "  required_providers {\n"
            '    aws = { source = "hashicorp/aws", version = ">= 5.0" }\n'
            "  }\n"
            "}\n\n"
            f'provider "aws" {{\n  region = "{region}"\n}}\n')


def write_bundle(fixes: list[dict], out_dir: str | pathlib.Path) -> pathlib.Path:
    out = pathlib.Path(out_dir)
    out.mkdir(parents=True, exist_ok=True)
    for name, content in bundle_files(fixes).items():
        (out / name).write_text(content, encoding="utf-8")
    return out
