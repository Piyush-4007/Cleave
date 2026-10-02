"""Cleave API — the analysis engine over HTTP, for the Phase 6 dashboard.

Routes stay thin: they call the service, which caches the analysis. The heavy lifting
(sources, sinks, search, rank, cut) lives in cleave.paths and is shared with the CLI, so
the API and `python -m cleave.paths.run` can never disagree.
"""
from __future__ import annotations
import hmac
from fastapi import Body, FastAPI, HTTPException, Query, Request
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse
from pydantic import BaseModel
from ..config import settings
from . import service

app = FastAPI(title="Cleave", version="0.5.0",
              description="Reachability-ranked attack path analysis for AWS")


@app.middleware("http")
async def require_token(request: Request, call_next):
    """With CLEAVE_API_TOKEN set (the desktop app), every route but /health needs the
    token. Registered before CORS so CORS stays outermost: preflights are answered by it,
    and a 401 still carries CORS headers the dashboard can read."""
    token = settings.cleave_api_token
    if token and request.method != "OPTIONS" and request.url.path != "/health":
        sent = request.headers.get("x-cleave-token", "")
        if not hmac.compare_digest(sent.encode(), token.encode()):
            return JSONResponse({"detail": "missing or invalid X-Cleave-Token"}, status_code=401)
    return await call_next(request)


# The dashboard is served from a separate origin (Vite on :3000 in dev, the Tauri webview
# on desktop), so the allowed origins come from the environment.
app.add_middleware(
    CORSMiddleware,
    allow_origins=[o.strip() for o in settings.cleave_cors_origins.split(",") if o.strip()],
    allow_methods=["GET", "POST"],
    allow_headers=["*"],
)


class ConnectRequest(BaseModel):
    mode: str = "login"          # "login" (ambient creds) | "role" (assume role_arn)
    role_arn: str | None = None


@app.get("/health")
def health() -> dict:
    return {"status": "ok", "service": "cleave", "phase": 5}


@app.get("/connection")
def connection() -> dict:
    """Whether an account is connected, and which mode."""
    return service.connection_status()


@app.post("/scan")
def scan(req: ConnectRequest) -> dict:
    """Connect to an AWS account and scan it. `mode=login` uses the machine's ambient AWS
    credentials; `mode=role` assumes the read-only role at `role_arn`. Read-only either way,
    and nothing leaves the machine."""
    if req.mode == "role" and not req.role_arn:
        raise HTTPException(status_code=400, detail="role mode needs a role_arn")
    try:
        return service.run_scan(req.mode, req.role_arn)
    except Exception as e:  # noqa: BLE001 - surface a readable message to the UI
        raise HTTPException(status_code=502, detail=f"scan failed: {type(e).__name__}: {e}")


class DisconnectRequest(BaseModel):
    forget_history: bool = False


@app.post("/disconnect")
def disconnect(req: DisconnectRequest) -> dict:
    """Forget the connected account on this machine (Cleave holds no credentials to revoke).
    Clears the current scan; with forget_history, that account's stored history too."""
    return service.disconnect(req.forget_history)


@app.get("/history")
def history_list(account: str | None = None) -> list[dict]:
    """Stored scans, newest first, each with its change vs the previous scan."""
    from .. import history
    return history.list_scans(account)


@app.get("/history/{scan_id}")
def history_diff(scan_id: int) -> dict:
    """One scan against the previous scan of the same account: new / resolved findings
    and paths."""
    from .. import history
    d = history.diff(scan_id)
    if d is None:
        raise HTTPException(status_code=404, detail=f"no scan {scan_id}")
    return d


@app.get("/analysis")
def analysis(refresh: bool = Query(False, description="rebuild after a new scan/load")) -> dict:
    """The full picture: ranked paths, minimum cut, best single fix, and summary counts."""
    return service.get_analysis(refresh=refresh)


@app.post("/gate")
def gate(plan: dict = Body(..., description="terraform show -json output")) -> dict:
    """Merge gate (Phase 9): given a Terraform plan, report the attack paths the change would
    introduce vs the live account, with a rendered PR comment and a scoped-alternative fix.
    Read-only: Cleave evaluates the plan, it never applies it."""
    if not isinstance(plan, dict) or "resource_changes" not in plan:
        raise HTTPException(status_code=400,
                            detail="body must be `terraform show -json` output (a JSON object "
                                   "with resource_changes)")
    return service.run_gate(plan)


@app.get("/remediation")
def remediation(refresh: bool = Query(False)) -> dict:
    """Proposed fixes for the current attack paths: corrected Terraform (or guidance) per
    minimum-cut edge, with blast radius, plus a downloadable .tf bundle. Cleave never
    applies anything — review, apply, then rescan to confirm."""
    return service.get_remediation(refresh=refresh)


@app.post("/remediation/pr")
def remediation_pr(dry_run: bool = Query(False, description="preview the PR without opening it")) -> dict:
    """TEAMS delivery: open the remediation bundle as a pull request in the configured
    infrastructure repo. OPT-IN and credential-gated — needs CLEAVE_GITHUB_TOKEN and
    CLEAVE_GITHUB_REPO in the environment (never in this request). Cleave opens the PR for
    review; it never merges and never touches AWS. Without credentials, use GET /remediation
    and apply the .tf yourself (the personal flow)."""
    if not settings.cleave_github_repo or (not settings.cleave_github_token and not dry_run):
        raise HTTPException(status_code=403, detail=(
            "The PR (teams) flow is off. Set CLEAVE_GITHUB_REPO to your infra repo "
            "(owner/repo) and CLEAVE_GITHUB_TOKEN to a fine-grained PAT (Contents + Pull "
            "requests read/write on that repo) in your .env. Until then, download the .tf "
            "from GET /remediation and apply it yourself."))
    try:
        return service.open_remediation_pr(dry_run=dry_run)
    except Exception as e:  # noqa: BLE001
        raise HTTPException(status_code=502, detail=f"GitHub PR failed: {type(e).__name__}: {e}")


@app.post("/cost/actual")
def cost_actual() -> dict:
    """Actual month-to-date spend via Cost Explorer. OPT-IN: off unless
    CLEAVE_COST_EXPLORER is set, because it needs the ce: permission and AWS bills ~$0.01
    per request. The free estimate lives in GET /analysis (the `cost` field)."""
    if not settings.cleave_cost_explorer:
        raise HTTPException(status_code=403,
                            detail="Cost Explorer is off. It needs the ce: permission and bills "
                                   "~$0.01 per request; enable CLEAVE_COST_EXPLORER to turn it on.")
    try:
        return service.actual_spend_now()
    except Exception as e:  # noqa: BLE001
        msg = f"{type(e).__name__}: {e}"
        code = 403 if "AccessDenied" in msg or "not authorized" in msg else 502
        raise HTTPException(status_code=code, detail=f"Cost Explorer call failed: {msg}")


@app.get("/analysis/summary")
def summary(refresh: bool = Query(False)) -> dict:
    """Just the dashboard numbers — light, no path bodies."""
    a = service.get_analysis(refresh=refresh)
    return {"source": a["source"], "generated_at": a["generated_at"],
            "graph": a["graph"], "summary": a["summary"]}


@app.get("/analysis/paths/{path_id}")
def path_detail(path_id: str) -> dict:
    """One ranked path plus its drawable subgraph (path + one hop of context, with the
    route and the minimum cut flagged) for the Cytoscape viewer."""
    detail = service.get_path(path_id)
    if detail is None:
        raise HTTPException(status_code=404, detail=f"no path {path_id}")
    return detail
