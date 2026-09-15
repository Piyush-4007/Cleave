#!/usr/bin/env bash
# Destroys AWS *test* resources (CloudGoat scenarios + generated environments).
# Does NOT touch permanent project infra like the CleaveAudit role.
set -uo pipefail
echo "Tearing down CloudGoat scenarios..."
if [ -d "$HOME/CloudGoat" ]; then
  ( cd "$HOME/CloudGoat" && for s in $(.venv/bin/cloudgoat list all 2>/dev/null | grep cgid); do
      printf 'y\ny\n' | .venv/bin/cloudgoat destroy "$s"; done )
fi
echo "Done. Verify with: aws ec2 describe-instances --filters Name=instance-state-name,Values=running"
