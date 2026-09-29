"""Parallel scan: the collectors fan out over regions / principals / each other.

No AWS here — a fake session stands in, and sleeps prove the work overlaps. What must hold:
  * output order is deterministic (same as the serial scan), whatever finishes first;
  * one failing region / collector is isolated exactly as before;
  * client creation is serialised (boto3 Session.client() is not thread-safe);
  * workers=1 is a true serial fallback.
"""
import threading
import time
import pytest
from cleave import collect
from cleave.collectors import base


class FakeClient:
    """Just enough of a botocore client for Context.client's paginator warm-up."""

    def __init__(self, service, region):
        self.service, self.region = service, region
        self.meta = type("M", (), {"service_model": type(
            "S", (), {"operation_names": ["DescribeThings"]})()})()
        self.warmed_with = None

    def can_paginate(self, op):
        self.warmed_with = op
        return True


class FakeSession:
    """Records concurrent entries into client() — boto3 forbids that."""

    def __init__(self):
        self.inside = 0
        self.overlapped = False
        self._guard = threading.Lock()

    def client(self, service, region_name=None, config=None):
        with self._guard:
            self.inside += 1
            if self.inside > 1:
                self.overlapped = True
        time.sleep(0.01)
        with self._guard:
            self.inside -= 1
        return FakeClient(service, region_name)


REGIONS = [f"r{i}" for i in range(10)]


def ctx(workers=16):
    return base.Context(FakeSession(), regions=list(REGIONS), workers=workers)


def test_per_region_keeps_region_order_and_flattens():
    def fn(region):
        time.sleep(0.05 if region == "r0" else 0)  # r0 finishes last
        return [f"{region}-a", f"{region}-b"]
    out = ctx().per_region(fn)
    assert out == [f"{r}-{s}" for r in REGIONS for s in "ab"]


def test_per_region_isolates_a_failing_region():
    def fn(region):
        if region == "r3":
            raise RuntimeError("opt-in region disabled")
        return [region]
    assert ctx().per_region(fn) == [r for r in REGIONS if r != "r3"]


def test_per_region_runs_concurrently():
    t = time.perf_counter()
    ctx().per_region(lambda r: time.sleep(0.2) or [r])
    assert time.perf_counter() - t < 1.0  # serial would be 2.0s


def test_workers_one_is_serial():
    t = time.perf_counter()
    ctx(workers=1).per_region(lambda r: time.sleep(0.05) or [r])
    assert time.perf_counter() - t >= 0.5


def test_map_keeps_order_and_propagates_errors():
    c = ctx()
    assert c.map(lambda x: x * 2, [3, 1, 2]) == [6, 2, 4]
    with pytest.raises(ValueError):
        c.map(lambda x: (_ for _ in ()).throw(ValueError("denied")) if x == 2 else x, [1, 2, 3])


def test_client_creation_is_serialised():
    c = ctx()
    clients = c.per_region(lambda r: [c.client("ec2", r)])
    assert [cl.region for cl in clients] == REGIONS  # nothing silently swallowed
    assert c.session.overlapped is False


def test_paginator_model_warmed_once_per_service():
    c = ctx()
    first = c.client("ec2", "r0")
    assert first.warmed_with == "describe_things"   # a real op name, python-cased
    assert c.client("ec2", "r1").warmed_with is None  # cache already filled
    assert c.client("rds", "r0").warmed_with == "describe_things"


def test_failed_warm_up_never_breaks_client_creation():
    c = ctx()

    class Grumpy(FakeClient):
        def can_paginate(self, op):
            raise KeyError(op)

    c.session.client = lambda service, region_name=None, config=None: Grumpy(service, region_name)
    assert c.client("ec2", "r0").region == "r0"


def test_run_collectors_concurrent_ordered_and_isolated(monkeypatch):
    def slow(tag):
        def fn(_ctx):
            time.sleep(0.2)
            return [tag]
        return fn

    def broken(_ctx):
        raise RuntimeError("boom")

    monkeypatch.setattr(base, "COLLECTORS", {"a": slow("a"), "b": broken, "c": slow("c"),
                                              "d": slow("d")})
    t = time.perf_counter()
    got = collect.run_collectors(ctx())
    assert time.perf_counter() - t < 0.6  # serial would be 0.6s+
    assert list(got) == ["a", "b", "c", "d"]
    assert got == {"a": ["a"], "b": [], "c": ["c"], "d": ["d"]}
