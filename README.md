# Cleave

**Reachability-ranked attack-path analysis for AWS.** Cleave connects to an AWS account
**read-only**, builds a graph of every resource and identity, finds the routes an attacker
could actually walk from a public entry point to administrative control, ranks them by
reachability, and computes the single smallest change — the **minimum cut** — that breaks
the most routes.

Local-first and private: **your AWS access never leaves your machine, and nothing is
uploaded.** Detection is deterministic graph search — no machine learning. Same account in,
same paths out, every time.

> Cleave is powered by **Severance** — a deterministic, reachability-ranked attack-path
> engine. It enumerates every route to admin, ranks them by reachability, and names the one
> cut that severs the most paths.

## Why it's different

A config scanner gives you a flat list of hundreds of findings. Cleave gives you the **few
routes that actually reach admin**, ranked, with the one fix that closes the most — and a
pre-merge gate that blocks pull requests which *open* a new path.

On a synthetic benchmark account with 5 planted attack paths, run against every tool the
same day:

| Tool | Result | Paths to admin |
|---|---|---|
| Prowler | 661 findings, unranked | 0 (no path concept) |
| ScoutSuite | 187 flagged | 0 |
| Checkov | 258 IaC findings | 0 |
| PMapper | IAM privesc graph | 2 of 5 (IAM-only) |
| **Cleave** | **ranked paths + minimum cut + merge gate** | **5 of 5 + variants** |

Flat scanners find the *pieces*; Cleave finds the *routes*, ranks them, and names the fix.

## Install

**Desktop app (Windows):** download the latest signed installer from
[Releases](https://github.com/Piyush-4007/Cleave/releases/latest) and run it. It bundles the
engine; no setup. It also self-updates.

**Self-host (any platform):**

```bash
git clone https://github.com/Piyush-4007/Cleave && cd Cleave
cp .env.example .env
docker compose up
```

## Connect an AWS account — no keys, ever

Cleave never asks for AWS access keys. Two ways to connect:

- **Your AWS login:** if you're signed in with the AWS CLI (`aws login` / SSO), the app uses
  those credentials on your machine — one click, read-only.
- **Scoped read-only role:** create a `CleaveAudit` role with the AWS-managed `SecurityAudit`
  + `ViewOnlyAccess` policies in your account and paste back its ARN. Cleave assumes it and
  holds no secret credential.

Cleave only ever makes **read** calls.

## How it works

Collectors read the account → records become a graph → the **Severance** engine (IAM policy
evaluator + reachability) materialises the escalation edges → path search finds every route
to admin, scores it, and computes the minimum cut → remediation turns each cut edge into
corrected Terraform (or honest guidance).

- **What counts as a start.** `EXTERNAL` (internet-reachable resource, public bucket,
  unauthenticated Lambda URL) and `ASSUMED_COMPROMISE` (any non-admin principal — "if this
  credential leaked, what could it reach?"). A principal that already holds `*:*` is the
  baseline and is not reported.
- **Every edge has evidence** tied to a real attacker action.
- **Reproducible.** Scoring weights and remediation costs live in `cleave/paths/policy.json`,
  editable by hand — any score is reproducible with a calculator.

## Layout

| Path | What |
|------|------|
| `backend/cleave/collectors/` | read the account (one module per service) |
| `backend/cleave/graph/`      | nodes, edges, loader |
| `backend/cleave/iam/`        | the Severance IAM policy evaluator + fixtures |
| `backend/cleave/reachability/` | network reachability |
| `backend/cleave/paths/`      | path search, scoring, minimum cut |
| `backend/cleave/remediation/`| Terraform patch generator |
| `backend/cleave/gate/`       | pre-merge gate (plan diff) |
| `backend/cleave/benchmark/`  | synthetic benchmark + metrics |
| `backend/cleave/api/`        | FastAPI routes |
| `frontend/`                  | the dashboard (React) — attack-path graph, findings, remediation |
| `desktop/`                   | the Tauri desktop app (bundles the engine) |

## Status

Reachability-ranked path search, minimum cut, remediation-to-Terraform, a GitHub merge
gate, and a synthetic benchmark are all implemented; 385 backend tests. The desktop app
ships the engine with an attack-path graph view and self-update.

## License

[MIT](LICENSE).

## Authors

Piyush Singh, Ketan Bhendarkar, Ashwini Lawhale · Guide: Prof. Manoj Shinde · MIT-ADT
University, Pune (Group BCCC39). Not affiliated with AWS.
