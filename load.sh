#!/usr/bin/env bash
# Dev helper: load data/raw/*.json into the Neo4j container (run from repo root).
set -euo pipefail
cd "$(dirname "$0")"
set -a; [ -f .env ] && . ./.env; set +a
# host talks to Neo4j on localhost, and reads the host copy of data/raw
export NEO4J_URI="bolt://localhost:7687"
export CLEAVE_OUTPUT_DIR="$(pwd)/data/raw"
cd backend
exec .venv/bin/python -m cleave.graph.load
