"""The token bucket, which is what decides whether a TEST run finishes.

The gateway caps *requests per minute* (measured 120). A semaphore cannot
express that, so before this existed a 16-way run offered ~275 rpm and the
excess came back as 429s absorbed by a 2/8/32 s backoff ladder. These tests use
short windows so they run in milliseconds while exercising the same arithmetic.
"""

from __future__ import annotations

import asyncio
import time

import pytest

from bastet_cc.llm import DEFAULT_RPM, LLMClient, RateLimiter


def _elapsed(coro) -> tuple[float, object]:
    t0 = time.monotonic()
    result = asyncio.run(coro)
    return time.monotonic() - t0, result


class TestBucketArithmetic:
    def test_default_matches_the_measured_cap(self):
        # The gateway allows 120; defaulting under it leaves room for the
        # bucket and the server's window not being phase-aligned.
        assert DEFAULT_RPM < 120

    def test_burst_defaults_to_a_quarter_not_the_whole_window(self):
        # A full-window burst is what earns 429s against a fixed-window counter.
        rl = RateLimiter(rpm=120)
        assert rl.burst == 30

    def test_burst_is_free_then_the_rate_binds(self):
        # window_s=1 => 60 tokens/sec refill at rpm=60. burst=15.
        rl = RateLimiter(rpm=60, window_s=1.0)

        async def go():
            await asyncio.gather(*(rl.acquire() for _ in range(15)))
        dt, _ = _elapsed(go())
        assert dt < 0.05, "the initial burst must not sleep"
        assert rl.n_waits == 0

    def test_sustained_rate_does_not_exceed_the_cap(self):
        rl = RateLimiter(rpm=60, window_s=1.0)   # 60/sec

        async def go():
            await asyncio.gather(*(rl.acquire() for _ in range(90)))
        dt, _ = _elapsed(go())
        # 15 free, then 75 more at 60/sec => ~1.25 s.
        effective = 90 / dt if dt else float("inf")
        assert effective <= 60 * 1.25, f"{effective:.0f}/s exceeds the cap"
        assert rl.n_waits > 0

    def test_refill_is_continuous_not_per_window(self):
        # A fixed-window refill lets 2x the cap through across a boundary.
        rl = RateLimiter(rpm=60, window_s=1.0, burst=1)

        async def go():
            await rl.acquire()
            await asyncio.sleep(0.5)
            t0 = time.monotonic()
            await asyncio.gather(*(rl.acquire() for _ in range(30)))
            return time.monotonic() - t0
        _, inner = _elapsed(go())
        # 0.5 s of idling accrued ~30 tokens but the cap is burst=1, so the
        # backlog must still be paid for at the refill rate.
        assert inner > 0.4, "capacity must not accumulate beyond the burst ceiling"

    def test_stats_report_what_was_paid(self):
        rl = RateLimiter(rpm=60, window_s=1.0, burst=2)

        async def go():
            await asyncio.gather(*(rl.acquire() for _ in range(10)))
        _elapsed(go())
        s = rl.stats()
        assert s["rpm"] == 60 and s["burst"] == 2
        assert s["n_waits"] >= 8 and s["waited_s"] > 0

    def test_concurrent_acquirers_are_serialised_correctly(self):
        rl = RateLimiter(rpm=120, window_s=1.0, burst=5)
        order: list[int] = []

        async def one(i: int):
            await rl.acquire()
            order.append(i)

        async def go():
            await asyncio.gather(*(one(i) for i in range(40)))
        _elapsed(go())
        assert len(order) == 40, "no acquirer may be dropped or double-counted"


class TestClientWiring:
    def test_limiter_is_on_by_default(self):
        c = LLMClient("http://x", "k", "m")
        assert c.limiter is not None and c.limiter.rpm == DEFAULT_RPM

    def test_rpm_none_disables_it(self):
        c = LLMClient("http://x", "k", "m", rpm=None)
        assert c.limiter is None

    def test_rpm_zero_disables_it(self):
        # `--rpm 0` on the CLI must mean "no cap", not "one request per minute".
        c = LLMClient("http://x", "k", "m", rpm=0)
        assert c.limiter is None

    def test_throttle_is_a_noop_when_disabled(self):
        c = LLMClient("http://x", "k", "m", rpm=None)
        dt, _ = _elapsed(c._throttle())
        assert dt < 0.05


class TestJsonRecovery:
    """`extract_json` keeps the arms on one code path; regressions here silently
    turn model output into parse failures, which score as 'found nothing'."""

    @pytest.mark.parametrize("text,expected", [
        ('{"findings": []}', {"findings": []}),
        ('```json\n{"a": 1}\n```', {"a": 1}),
        ('```\n[1, 2]\n```', [1, 2]),
        ('Here you go: {"a": 2} hope that helps', {"a": 2}),
        ('[]', []),
    ])
    def test_recovers_json_from_prose_and_fences(self, text, expected):
        from bastet_cc.llm import extract_json
        assert extract_json(text) == expected

    def test_returns_none_on_garbage(self):
        from bastet_cc.llm import extract_json
        assert extract_json("no json at all") is None

    def test_bare_array_is_wrapped_to_the_schema_shape(self):
        # Upstream prompts say "output a empty array", so the model returns a
        # top-level list where the schema wants {"findings": [...]}.
        c = LLMClient("http://x", "k", "m", rpm=None)
        schema = {"properties": {"findings": {}}}
        assert c._coerce([{"summary": "x"}], schema) == {"findings": [{"summary": "x"}]}

    def test_coerce_rejects_a_shape_it_cannot_fix(self):
        c = LLMClient("http://x", "k", "m", rpm=None)
        assert c._coerce([1, 2], {"properties": {"other": {}}}) is None
        assert c._coerce(None, {"properties": {"findings": {}}}) is None
