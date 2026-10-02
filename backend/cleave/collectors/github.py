"""GitHub repo collector (Phase 9 CI-identity edges) — the optional enrichment.

The AWS scan alone already finds which repos can assume which roles (from the OIDC trust
policy; see paths.endpoints.github_actions_repos). This adds *how exposed* each of those
repos is: is it public, and can code run without review? A public repo whose default branch
has no required reviewers is far easier to get a malicious workflow into than a private one
behind required reviews.

Standalone (not a boto @collector): GitHub is not an AWS service. It reads over GitHub's
REST API with stdlib urllib (no new dependency), the token from the environment only. An
injectable `fetch` makes it fully testable offline. Emits `GitHubRepo` records keyed
`github:OWNER/REPO`, which find_sources uses to sharpen the GitHub-Actions source note.
Read-only: it reads repo settings, nothing else.
"""
from __future__ import annotations
import json
import urllib.error
import urllib.request

API = "https://api.github.com"


def _http_fetch(url: str, token: str):
    req = urllib.request.Request(url, headers={
        "Authorization": f"Bearer {token}",
        "Accept": "application/vnd.github+json",
        "X-GitHub-Api-Version": "2022-11-28",
        "User-Agent": "cleave-ci-collector",
    })
    try:
        with urllib.request.urlopen(req) as r:   # noqa: S310 - fixed https host
            return r.status, json.loads(r.read() or "null")
    except urllib.error.HTTPError as e:
        return e.code, None


def _repo_record(owner_repo: str, repo: dict, protection, protection_status: int = 200) -> dict:
    # 200 -> read the count; 404 -> the branch has NO protection, i.e. 0 required reviews
    # (the most permissive, highest-exposure case); anything else (e.g. 403 no Administration
    # scope) -> unknown, left as None rather than guessed.
    if protection_status == 404:
        required_reviews: int | None = 0
    elif isinstance(protection, dict):
        rpr = protection.get("required_pull_request_reviews")
        required_reviews = (rpr.get("required_approving_review_count", 0) if isinstance(rpr, dict)
                            else 0)
    else:
        required_reviews = None
    return {
        "_type": "GitHubRepo", "_id": f"github:{owner_repo}", "Repo": owner_repo,
        "Visibility": "public" if repo.get("private") is False else
                      ("private" if repo.get("private") else None),
        "DefaultBranch": repo.get("default_branch"),
        "RequiredReviews": required_reviews,     # None = unknown (protection unreadable)
        "Archived": repo.get("archived"),
    }


def collect_github_repos(repos, token: str, fetch=_http_fetch) -> list[dict]:
    """A GitHubRepo record per `OWNER/REPO` in `repos`. `*` (any-repo misconfig) is skipped —
    there is no single repo to describe. A repo that cannot be read is skipped, not guessed."""
    out: list[dict] = []
    for owner_repo in sorted({r for r in repos if r and r != "*"}):
        status, repo = fetch(f"{API}/repos/{owner_repo}", token)
        if status != 200 or not isinstance(repo, dict):
            continue
        branch = repo.get("default_branch") or "main"
        pstatus, protection = fetch(f"{API}/repos/{owner_repo}/branches/{branch}/protection", token)
        out.append(_repo_record(owner_repo, repo, protection, pstatus))
    return out


def exposure_note(repo_rec: dict) -> str:
    """One clause describing how exposed a repo is, for the GitHub-Actions source reason."""
    if not repo_rec:
        return ""
    vis = repo_rec.get("Visibility")
    rev = repo_rec.get("RequiredReviews")
    bits = []
    if vis:
        bits.append(vis)
    if rev == 0:
        bits.append("no required reviews — a single merged/pushed workflow runs as this role")
    elif isinstance(rev, int) and rev > 0:
        bits.append(f"{rev} required review(s)")
    if vis == "public" and rev == 0:
        bits.insert(0, "HIGH exposure:")
    return (" [" + ", ".join(bits) + "]") if bits else ""
