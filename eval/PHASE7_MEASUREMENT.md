# Phase 7 — IAM evaluator v1 vs v2 (measured)

The evaluator was extended in stages (conditions → precise takeover edges → permission
boundaries + SCPs → condition-aware role assumption + cross-account → KMS key-policy
precedence). This records what changed, measured by running **both** engines over the
same inputs with `eval/compare.py` (v1 = git tag `v1-evaluator`, commit `e0031f1`).

Reproduce:

```bash
python eval/compare.py eval/corpus/<scan-dir> backend/tests/path_fixtures/*.json \
    --out eval/results/v1_vs_v2.json
```

`compare.py` checks out the v1 engine into a temporary git worktree and runs the shared
`measure.py` against it and against the working tree, so neither engine knows it is being
compared. Raw per-item diffs (which carry account ids / ARNs) stay in the gitignored
`eval/results/`.

## Hand-verified fixtures (ground truth)

Each path fixture is a hand-built account with the paths we walked by hand written down as
the expected answer. v2 reports **exactly** the real paths on all 13; the table shows where
v1 was wrong.

| Fixture | v1 paths | v2 paths | v1 error corrected |
|---|---|---|---|
| 01 rollback | 1 | 1 | — (regression guard) |
| 02 attachment | 1 | 1 | — |
| 03 public-bucket → admin | 2 | 2 | — |
| 04 aws-managed → admin | 1 | 1 | — |
| 05 credential theft | 2 | 2 | — |
| 06 overlapping paths | 5 | 5 | — |
| 07 sensitive-data sink | 1 | 1 | — |
| 08 glue passrole | 1 | 1 | — |
| **10** takeover, nobody to become | **1** | **0** | false **positive** removed |
| **11** boundary caps escalation | **2** | **1** | false **positive** removed |
| **12** account-root delegation | **0** | **1** | false **negative** fixed (missed path) |
| **13** cross-account trust | **0** | **1** | false **negative** fixed (missed path) |

Two error classes, both directions:

- **False positives (v1 over-reported):** an identity holding `iam:CreateAccessKey` etc.
  with no admin to become (10); a second identity whose permissions boundary caps the same
  escalation (11). v1 treated the permission as admin-equivalent on its own and ignored
  boundaries.
- **False negatives (v1 missed real paths):** a role trusting the account root, reachable
  by any principal that also holds `sts:AssumeRole` (12); a role trusting another account
  (13). v1 drew account-root trust from a dead-end node and had no cross-account notion, so
  it found **nothing** — the most dangerous kind of miss.

## Clean production-style account

A real scan of a clean account with no attack path. Both engines correctly report **0
paths**. What changed is the edge set:

| | v1 | v2 |
|---|---|---|
| traversable attack edges | 62 | 46 |

All 16 edges v2 drops are **non-traversable noise** v1 carried: 15 `CAN_ASSUME` edges from
AWS *service* principals (no attacker starts at a service), and 1 from the synthetic
account-`root` node (a dead end). v2 replaces the last with the one real delegation edge
(the admin user → the role it can actually assume). The v2 edge set is what a reviewer can
actually walk.

## Still to measure (live)

A multi-scenario CloudGoat figure (deploy several known-vulnerable scenarios, diff v1 vs v2
path counts) needs a live account and is the Phase 10 benchmark. The frozen 30 Sep
CloudGoat snapshot was overwritten by a later clean-account scan; redeploying is the
remaining measurement, done when the account is live.
