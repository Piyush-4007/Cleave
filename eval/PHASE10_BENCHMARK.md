# Cleave — Phase 10 benchmark (offline results)

Synthetic accounts with a known ground truth (planted paths among path-free benign noise), so recall and precision are exact. Reproduce with `python -m cleave.benchmark.run`. Cross-tool columns and the CloudGoat reality-check are added in the live run.

## Detection quality vs. account size

| resources | planted | recall | precision | raw findings | triage reduction | TTFP (findings) | best-fix cut | scan (s) |
|---|---|---|---|---|---|---|---|---|
| 129 | 5 | 1.0 | 1.0 | 54 | 10.8x | #1 | 84% | 0.29 |
| 189 | 5 | 1.0 | 1.0 | 79 | 15.8x | #1 | 87% | 0.01 |
| 249 | 5 | 1.0 | 1.0 | 103 | 20.6x | #1 | 89% | 0.01 |
| 309 | 5 | 1.0 | 1.0 | 127 | 25.4x | #1 | 91% | 0.01 |

## Merge-gate accuracy (30-PR corpus)

- PRs that introduce a path: **15** — detected: **15** (detection rate **1.0**)
- Benign-but-similar PRs: **15** — false alarms: **0** (false-positive rate **0.0**)

The benign-but-similar half (scoped PassRole, PassRole-only, a 0.0.0.0/0 port with nothing behind it, a GitHub-OIDC role on a scoped policy, a private credential bucket) is identical in shape to the dangerous PRs — a linter flags them; Cleave passes them.

## Headline

On the largest account (309 resources): **127 raw findings → 5 actionable attack paths** (25.4x reduction), the first genuinely dangerous finding ranked **#1**, and the single best fix cuts **91%** of paths.

