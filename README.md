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

Then open http://localhost:8000/health (API) — the dashboard (Phase 6) will live at
http://localhost:3000.

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
Phase 1 — collectors. See `../Cleave_Build_Handbook.md` for the full plan.

## Running a scan in dev (Phase 1)

```bash
cd backend && uv venv --python 3.11 .venv && uv pip install -r requirements.txt   # once
./scan.sh    # from the repo root
```

`scan.sh` bridges `aws login` credentials into the environment (boto3 can't read the
`login_session` format the AWS CLI uses), assumes the `CleaveAudit` role, and writes one
JSON file per service to `data/raw/`. Re-run any time; the graph rebuilds from those files
without re-hitting AWS.
