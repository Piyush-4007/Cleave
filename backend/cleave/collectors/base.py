"""Collector framework.

Design rule (handbook Phase 1): collectors **read and normalise only. They never
decide anything is insecure.** Collection and judgement stay completely separate.

Every collector is a function `collect(ctx) -> list[dict]` registered with
@collector("name"). The runner (cleave.collect) executes them all, each isolated so
one denied permission cannot kill the scan.

Concurrency (scan speed): the work is almost entirely network round-trips, so threads are
the right tool. `Context.per_region` fans a regional collector out over regions,
`Context.map` fans per-item detail calls out (IAM principals, S3 buckets), and the runner
runs collectors alongside each other. Results always come back in input order, so a
parallel scan's output is identical to a serial one. CLEAVE_SCAN_WORKERS=1 makes it serial.
"""
from __future__ import annotations
import logging
import threading
from concurrent.futures import ThreadPoolExecutor
from typing import Callable, Iterable, Iterator, TypeVar
import boto3
from botocore import xform_name
from botocore.config import Config
from botocore.exceptions import ClientError, BotoCoreError

log = logging.getLogger("cleave.collect")

# Exponential-backoff retry on throttling — never hand-roll this. The pool is widened
# because one client (e.g. global IAM) is shared by several worker threads.
RETRY_CONFIG = Config(retries={"max_attempts": 10, "mode": "adaptive"},
                      max_pool_connections=32)

T = TypeVar("T")
R = TypeVar("R")

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

    def __init__(self, session: boto3.Session, regions: list[str] | None = None,
                 workers: int | None = None):
        self.session = session
        self._regions = regions
        if workers is None:
            from ..config import settings
            workers = settings.cleave_scan_workers
        self.workers = max(1, workers)
        # boto3 Session.client() is not thread-safe; the clients it returns are.
        self._client_lock = threading.Lock()
        self._warmed: set[str] = set()

    def client(self, service: str, region: str | None = None):
        with self._client_lock:
            c = self.session.client(service, region_name=region, config=RETRY_CONFIG)
            if service not in self._warmed:
                # Load the service's paginator model once, here, under the lock. botocore
                # caches it for every later client, but the cache fills lazily: 17 region
                # threads calling get_paginator cold all race to load the same file, which
                # measured 10s instead of 1.7s. can_paginate is the public call that fills it.
                # Best-effort: a failed warm-up only costs speed, never records.
                try:
                    c.can_paginate(xform_name(c.meta.service_model.operation_names[0]))
                except Exception:  # noqa: BLE001
                    pass
                self._warmed.add(service)
            return c

    def map(self, fn: Callable[[T], R], items: Iterable[T]) -> list[R]:
        """fn over items on the worker pool, results in input order. An exception in any
        call propagates, exactly as it would from the equivalent serial loop."""
        items = list(items)
        if self.workers == 1 or len(items) <= 1:
            return [fn(i) for i in items]
        with ThreadPoolExecutor(max_workers=min(self.workers, len(items))) as pool:
            return list(pool.map(fn, items))

    def per_region(self, fn: Callable[[str], list[dict]]) -> list[dict]:
        """Run a regional collector body in every region concurrently and flatten, in
        region order. A region that fails (disabled opt-in region, denied call) yields
        nothing and the rest carry on — the old per-region try/except, preserved."""
        def one(region: str) -> list[dict]:
            try:
                return fn(region)
            except Exception as e:  # noqa: BLE001 - skip disabled/failed regions, keep going
                log.debug("region %s skipped: %s", region, e)
                return []
        return [r for recs in self.map(one, self.regions()) for r in recs]

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
