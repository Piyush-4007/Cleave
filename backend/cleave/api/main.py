"""Cleave API — the analysis engine over HTTP, for the Phase 6 dashboard.

Routes stay thin: they call the service, which caches the analysis. The heavy lifting
(sources, sinks, search, rank, cut) lives in cleave.paths and is shared with the CLI, so
the API and `python -m cleave.paths.run` can never disagree.
"""
from __future__ import annotations
from fastapi import FastAPI, HTTPException, Query
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel
from . import service

app = FastAPI(title="Cleave", version="0.5.0",
              description="Reachability-ranked attack path analysis for AWS")

# The dashboard is served from a separate origin in dev (Vite on :3000). Product ships
# both behind one origin, but allow local dev origins so Phase 6 can call the API.
app.add_middleware(
    CORSMiddleware,
    allow_origins=["http://localhost:3000", "http://localhost:5173"],
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


@app.get("/analysis")
def analysis(refresh: bool = Query(False, description="rebuild after a new scan/load")) -> dict:
    """The full picture: ranked paths, minimum cut, best single fix, and summary counts."""
    return service.get_analysis(refresh=refresh)


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
