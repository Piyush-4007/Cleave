"""Teams delivery (Phase 8): open the remediation bundle as a GitHub pull request.

For teams who manage their cloud as code: instead of handing the user a `.tf` file to
apply by hand (bundle.py), Cleave commits the same files to a branch in their
infrastructure repo and opens a PR for review. Their normal review + CI applies it — Cleave
still never touches AWS or merges anything.

No new dependency: this uses GitHub's REST (git data) API over stdlib urllib. The token and
repo come ONLY from the environment (CLEAVE_GITHUB_TOKEN / CLEAVE_GITHUB_REPO), never from a
request body or the page — the same rule as every other Cleave credential. The token needs,
on that one repo, Contents: read/write and Pull requests: read/write (a fine-grained PAT).

`build_pr_plan` is pure (files + branch + title/body) and fully testable offline.
`open_pr` performs the calls; `dry_run=True` returns the plan without any network, which is
how it is exercised in tests and how the UI can preview a PR before it is opened.
"""
from __future__ import annotations
import datetime as _dt
import json
import urllib.error
import urllib.request
from .bundle import bundle_files

API = "https://api.github.com"


def _branch_name(now: _dt.datetime | None = None) -> str:
    now = now or _dt.datetime.now(_dt.timezone.utc)
    return f"cleave/remediation-{now:%Y%m%d-%H%M%S}"


def _pr_body(fixes: list[dict]) -> str:
    templated = [f for f in fixes if f.get("confidence") == "templated"]
    guidance = [f for f in fixes if f.get("confidence") != "templated"]
    lines = [
        "Automated remediation proposed by **Cleave** for the attack paths it found.",
        "",
        f"- {len(templated)} change(s) with a Terraform patch in this PR",
        f"- {len(guidance)} item(s) needing a manual judgement (listed below, no patch)",
        "",
        "**Review every change and run `terraform plan` before merging.** Cleave has "
        "read-only AWS access and never applies anything itself; after you merge and apply, "
        "rescan to confirm the paths are gone.",
        "",
        "## Changes",
    ]
    for f in templated:
        lines += [f"\n### {f.get('title')}",
                  f"- **cuts:** `{f.get('rel')}` -> `{f.get('target')}`",
                  f"- {f.get('note', '')}",
                  f"- **might break:** {f.get('impact', '')}"]
    if guidance:
        lines.append("\n## Needs manual review (no patch)")
        for f in guidance:
            lines.append(f"- **{f.get('title')}** — {f.get('note', '')}")
    return "\n".join(lines) + "\n"


def build_pr_plan(fixes: list[dict], repo: str, base: str = "main",
                  subdir: str = "cleave-remediation",
                  now: _dt.datetime | None = None) -> dict:
    """The complete PR as data: which files to commit (under `subdir`), the branch, and the
    title/body. Pure — no network, no credentials."""
    files = {f"{subdir}/{name}": content for name, content in bundle_files(fixes).items()}
    branch = _branch_name(now)
    n = sum(1 for f in fixes if f.get("confidence") == "templated")
    return {
        "repo": repo, "base": base, "branch": branch,
        "title": f"Cleave: remediate {n} attack-path finding(s)",
        "body": _pr_body(fixes),
        "files": files,
    }


# ---- GitHub REST (git data API) over urllib ------------------------------------------

def _call(method: str, url: str, token: str, payload: dict | None = None) -> dict:
    data = json.dumps(payload).encode() if payload is not None else None
    req = urllib.request.Request(url, data=data, method=method, headers={
        "Authorization": f"Bearer {token}",
        "Accept": "application/vnd.github+json",
        "X-GitHub-Api-Version": "2022-11-28",
        "Content-Type": "application/json",
        "User-Agent": "cleave-remediation",
    })
    with urllib.request.urlopen(req) as r:   # noqa: S310 - fixed https host
        body = r.read()
    return json.loads(body) if body else {}


def open_pr(fixes: list[dict], repo: str, token: str, base: str = "main",
            subdir: str = "cleave-remediation", dry_run: bool = False,
            now: _dt.datetime | None = None) -> dict:
    """Commit the remediation files to a new branch of `repo` and open a PR. Returns the
    plan plus, when actually opened, the PR url/number. `dry_run` returns only the plan.

    Never merges, never enables auto-merge: a human approves. Raises on a GitHub error so
    the caller (the API endpoint) can surface it."""
    plan = build_pr_plan(fixes, repo, base, subdir, now)
    if dry_run:
        return {**plan, "dry_run": True}

    base_sha = _call("GET", f"{API}/repos/{repo}/git/ref/heads/{base}", token)["object"]["sha"]
    base_commit = _call("GET", f"{API}/repos/{repo}/git/commits/{base_sha}", token)
    tree_items = []
    for path, content in plan["files"].items():
        blob = _call("POST", f"{API}/repos/{repo}/git/blobs", token,
                     {"content": content, "encoding": "utf-8"})
        tree_items.append({"path": path, "mode": "100644", "type": "blob", "sha": blob["sha"]})
    tree = _call("POST", f"{API}/repos/{repo}/git/trees", token,
                 {"base_tree": base_commit["tree"]["sha"], "tree": tree_items})
    commit = _call("POST", f"{API}/repos/{repo}/git/commits", token,
                   {"message": plan["title"], "tree": tree["sha"], "parents": [base_sha]})
    _call("POST", f"{API}/repos/{repo}/git/refs", token,
          {"ref": f"refs/heads/{plan['branch']}", "sha": commit["sha"]})
    pr = _call("POST", f"{API}/repos/{repo}/pulls", token,
               {"title": plan["title"], "body": plan["body"],
                "head": plan["branch"], "base": base})
    return {**plan, "dry_run": False, "pr_url": pr.get("html_url"), "pr_number": pr.get("number")}
