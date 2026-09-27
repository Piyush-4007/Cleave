# Cleave

Reachability-ranked attack-path analysis for AWS. Cleave connects to an AWS account
**read-only**, builds a graph of resources and identities, finds routes from public
entry points to admin, ranks them, and computes the single smallest change (the
*minimum cut*) that breaks the most routes.

Self-hosted and local-first: **your AWS access never leaves your machine.**

## Install (three commands)

```bash
git clone <repo> && cd cleave
cp .env.example .env      # fill in a couple of local values
docker compose up
```

Then open http://localhost:8000/health (API) or http://localhost:8000/docs (interactive
API docs) — the dashboard (Phase 6) will live at http://localhost:3000.

## Connect an AWS account (no keys)

Cleave never asks for AWS access keys. You create a read-only role in your own account
and paste back its ARN:

1. Create a role (`CleaveAudit`) with the AWS-managed `SecurityAudit` + `ViewOnlyAccess`
   policies.
2. Put its ARN in `.env` as `CLEAVE_ROLE_ARN`.
3. Cleave assumes that role to scan. It holds no secret credential, ever.

## Layout

| Path | Phase | What |
|------|-------|------|
| `backend/cleave/collectors/` | 1 | read the account (one module per service) |
| `backend/cleave/graph/`      | 2 | nodes, edges, Neo4j loader |
| `backend/cleave/iam/`        | 3,7 | IAM policy evaluator + fixtures |
| `backend/cleave/reachability/` | 3 | network reachability |
| `backend/cleave/paths/`      | 4,5 | path search, scoring, min-cut |
| `backend/cleave/remediation/`| 8 | Terraform patch generator |
| `backend/cleave/gate/`       | 9 | plan collector + path diff |
| `backend/cleave/api/`        | — | FastAPI routes |
| `frontend/`                  | 6 | React dashboard |
| `scenarios/`                 | 10 | test-account generator |
| `eval/`                      | 10 | benchmark harness |

## Status
Phase 5 — ranking + minimum cut. See `../Cleave_Build_Handbook.md` for the full plan.

## Running a scan in dev (Phase 1)

```bash
cd backend && uv venv --python 3.11 .venv && uv pip install -r requirements.txt   # once
./scan.sh    # from the repo root
```

`scan.sh` bridges `aws login` credentials into the environment (boto3 can't read the
`login_session` format the AWS CLI uses), assumes the `CleaveAudit` role, and writes one
JSON file per service to `data/raw/`. Re-run any time; the graph rebuilds from those files
without re-hitting AWS.

## Finding attack paths in dev (Phase 4)

```bash
./load.sh                                  # data/raw -> Neo4j (needs the neo4j container)
cd backend && .venv/bin/python -m cleave.paths.run
```

`paths.run` reads the loaded graph, classifies sources and sinks, and prints every route
from a source to administrative control, shortest first, with the evidence behind each hop.
Add `--from-raw` to skip Neo4j and search straight from `data/raw`, or `--json` for
machine-readable output.

**What counts as a start.** Two source classes: `EXTERNAL` (internet-reachable resource,
public bucket, unauthenticated Lambda URL) and `ASSUMED_COMPROMISE` (any principal that is
not already a literal administrator — "if this credential leaked, what could it reach?").
A principal that already holds `*:*` is the account's baseline and is not reported.

**Detection is deterministic.** Same graph in, same paths out. No model is involved.

The output is three things: the ranked paths, the **best single fix** (the one change that
breaks the most paths — the demo headline), and the **minimum cut** (the cheapest set of
changes that breaks every path). Scoring weights and remediation costs live in
`cleave/paths/policy.json`, editable by hand so any score is reproducible with a
calculator.

## The API (Phase 5/6 bridge)

The same engine behind the CLI is served over HTTP for the dashboard:

| Route | Returns |
|---|---|
| `GET /health` | liveness |
| `GET /analysis` | ranked paths + minimum cut + best single fix + summary |
| `GET /analysis/summary` | just the dashboard numbers (no path bodies) |
| `GET /analysis/paths/{id}` | one path + its drawable subgraph (route and cut flagged) |

The graph source is Neo4j (populated by `./load.sh`); in dev it falls back to the raw
dump if Neo4j is down. Analysis is cached — pass `?refresh=true` after a new scan/load.
Interactive docs at `/docs`.
