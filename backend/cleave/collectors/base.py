"""Collector framework.

Design rule (handbook Phase 1): collectors **read and normalise only. They never
decide anything is insecure.** Collection and judgement stay completely separate.

Every collector is a function `collect(ctx) -> list[dict]` registered with
@collector("name"). The runner (cleave.collect) executes them all, each isolated so
one denied permission cannot kill the scan.
"""
from __future__ import annotations
import logging
from typing import Callable, Iterator
import boto3
from botocore.config import Config
from botocore.exceptions import ClientError, BotoCoreError

log = logging.getLogger("cleave.collect")

# Exponential-backoff retry on throttling — never hand-roll this.
RETRY_CONFIG = Config(retries={"max_attempts": 10, "mode": "adaptive"})

# name -> collector function
COLLECTORS: dict[str, Callable[["Context"], list[dict]]] = {}


def collector(name: str):
    """Register a collector under a service name."""
    def deco(fn: Callable[["Context"], list[dict]]):
        COLLECTORS[name] = fn
        return fn
    return deco


class Context:
    """Shared scan context: the assumed-role session + helpers."""

    def __init__(self, session: boto3.Session, regions: list[str] | None = None):
        self.session = session
        self._regions = regions

    def client(self, service: str, region: str | None = None):
        return self.session.client(service, region_name=region, config=RETRY_CONFIG)

    def regions(self) -> list[str]:
        """All enabled regions (cached)."""
        if self._regions is None:
            ec2 = self.client("ec2")
            self._regions = [r["RegionName"] for r in ec2.describe_regions()["Regions"]]
        return self._regions


def paginate(client, method: str, result_key: str, **kwargs) -> Iterator[dict]:
    """Yield every item across all pages of a boto3 call. Uses paginators only."""
    paginator = client.get_paginator(method)
    for page in paginator.paginate(**kwargs):
        for item in page.get(result_key, []):
            yield item


def safe(name: str, fn: Callable[[], list[dict]]) -> list[dict]:
    """Run one collector; swallow+log a permission/other error so the scan survives."""
    try:
        return fn()
    except ClientError as e:
        code = e.response.get("Error", {}).get("Code", "ClientError")
        log.warning("collector %-12s skipped: %s", name, code)
        return []
    except (BotoCoreError, Exception) as e:  # noqa: BLE001 - one collector must not sink the scan
        log.warning("collector %-12s failed: %s", name, e)
        return []
