"""Load the raw JSON dump into Neo4j.

    python -m cleave.graph.load

Wipes the graph and rebuilds it from CLEAVE_OUTPUT_DIR. Idempotent (MERGE-based).
"""
from __future__ import annotations
import logging
from .loader import GraphLoader
from ..config import settings


def run() -> dict:
    logging.basicConfig(level=logging.INFO, format="%(levelname)s %(name)s: %(message)s")
    logging.getLogger("neo4j.notifications").setLevel(logging.WARNING)  # quiet perf hints
    loader = GraphLoader(settings.neo4j_uri, settings.neo4j_user, settings.neo4j_password)
    try:
        loader.wipe()
        return loader.load(settings.cleave_output_dir)
    finally:
        loader.close()


if __name__ == "__main__":
    run()
