#!/usr/bin/env bash
# Dev helper: scan the account from the host (not the container).
#
# Why the cred dance: `aws login` stores creds under a `login_session` mechanism that
# boto3 does not read. `aws configure export-credentials` bridges them to standard env
# vars, which boto3 (and the assume-role for CleaveAudit) then use.
set -euo pipefail
cd "$(dirname "$0")"

# load dev config (.env), then bridge aws-login creds -> env
set -a; [ -f .env ] && . ./.env; set +a
# an empty AWS_PROFILE env var makes boto3 look for a profile named "" — drop it
[ -z "${AWS_PROFILE:-}" ] && unset AWS_PROFILE
eval "$("${AWS_CLI:-$HOME/.local/bin/aws}" configure export-credentials --format env)"

export AWS_REGION="${AWS_REGION:-us-east-1}"
export CLEAVE_OUTPUT_DIR="${CLEAVE_OUTPUT_DIR_HOST:-$(pwd)/data/raw}"
export AWS_PAGER=""
cd backend
exec .venv/bin/python -m cleave.collect
