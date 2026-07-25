"""Inference backend: one client class, OpenAI-compatible, never raises on a call.

Behavior is calibrated against measurements of ais3/nemotron-3-ultra-550b (see
MODEL_NOTES.md). The two consequential findings: `response_format=json_schema` costs
~15-18s of server-side grammar compilation per call while `json_object` is free and
just as reliable, so schema requests use json_object plus a prompt-pinned schema; and
without JSON mode the model happily invents its own fenced schema, so the lenient
parser (fence strip, first-valid-JSON scan, bare-array wrap) is not decoration -- it is
what keeps the llama/gemma comparison arms on the same code path.

Concurrency alone is the wrong control. The gateway enforces a *request-rate* cap
(`Current limit: 120` requests/minute, measured -- runs/probe/phase7_sustained_w32.json),
and a semaphore cannot see it: 16 workers at ~3.5 s each offer ~275 rpm, so the
excess comes back as 429s that the retry ladder then absorbs at 2/8/32 s. The run
still completes, but throughput collapses to whatever the backoff happens to
settle at, the log fills with retries, and the wall-clock estimate in any plan
built from single-call latency is wrong by a factor of two or more. So the client
carries a token bucket as well, and the semaphore is left to bound memory rather
than rate. `phase7_sustained_w16` recorded zero errors only because it ran 21.95 s
and never crossed a minute boundary; the cap is real over any longer horizon.

Every call is one JSONL line in the log; cost charts aggregate that file directly
(DESIGN §1.5). Failures come back as `LLMResult(error=...)`, never exceptions:
the executor's only job is to append whatever it gets.
"""

from __future__ import annotations

import asyncio
import json
import re
import time
from collections.abc import Mapping
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path

import httpx

# Backoff schedule for retryable failures (429/5xx/timeout/connection): sleep before
# retry k. len() == default max_retries, i.e. 4 attempts total.
BACKOFF_S = [2.0, 8.0, 32.0]

# Measured gateway cap, runs/probe/phase7_sustained_w32.json: 120 requests/minute
# per key. Default a hair under it -- the bucket and the server's window are not
# phase-aligned, and being throttled costs more than the two requests saved.
DEFAULT_RPM = 115

_FENCE_RE = re.compile(r"```(?:json)?\s*(.*?)```", re.DOTALL)


class RateLimiter:
    """Token bucket, shared by every in-flight call.

    Deliberately not a semaphore. A semaphore bounds *simultaneity*; the cap
    being enforced here is on *arrivals per minute*, and the two only coincide
    when latency is constant, which it is not (measured 0.89 s to 9.5 s).

    Burst capacity is a fraction of the cap, not the whole of it. The gateway's
    429 body reports `Current limit: 120, Remaining: 0, Limit resets at: <ts>` --
    a *fixed window* counter, not a leaky bucket. A client starting with a full
    bucket would fire a whole window's worth of requests in the first second,
    and if the server's window happens to be half-consumed at that moment, the
    tail of that burst is exactly the 429 storm the limiter exists to prevent.
    Starting at a quarter costs a few seconds once, on a run measured in hours.
    """

    def __init__(self, rpm: int = DEFAULT_RPM, window_s: float = 60.0,
                 burst: int | None = None):
        self.rpm = max(1, int(rpm))
        self.window_s = window_s
        self.burst = max(1, int(burst if burst is not None else self.rpm // 4))
        self._tokens = float(self.burst)
        self._updated = time.monotonic()
        self._lock = asyncio.Lock()
        self.waited_s = 0.0          # cumulative sleep, reported in run manifests
        self.n_waits = 0

    async def acquire(self) -> None:
        while True:
            async with self._lock:
                now = time.monotonic()
                # Refill continuously rather than per-window: a fixed window lets
                # 2x the cap through across a boundary, which is exactly the burst
                # that earned the 429s in the first place.
                self._tokens = min(
                    float(self.burst),
                    self._tokens + (now - self._updated) * self.rpm / self.window_s,
                )
                self._updated = now
                if self._tokens >= 1.0:
                    self._tokens -= 1.0
                    return
                deficit = 1.0 - self._tokens
                sleep_s = deficit * self.window_s / self.rpm
                self.waited_s += sleep_s
                self.n_waits += 1
            # Sleep outside the lock so other coroutines can keep draining.
            await asyncio.sleep(sleep_s)

    def stats(self) -> dict:
        return {"rpm": self.rpm, "burst": self.burst, "n_waits": self.n_waits,
                "waited_s": round(self.waited_s, 1)}


@dataclass
class LLMResult:
    text: str
    parsed: dict | None     # only set when JSON parsing succeeded
    model: str
    input_tokens: int
    output_tokens: int
    latency_s: float
    attempts: int           # HTTP calls made, including retries and the repair call
    error: str | None       # timeout / rate_limit / server_error / json_invalid /
                            # context_overflow / truncated / connection_error / http_<n>


def extract_json(text: str) -> dict | list | None:
    """Lenient JSON recovery: direct parse, then fenced blocks, then a scan for the
    first valid JSON value anywhere in the text."""
    s = text.strip()
    try:
        return json.loads(s)
    except (json.JSONDecodeError, ValueError):
        pass
    for block in _FENCE_RE.findall(s):
        try:
            return json.loads(block.strip())
        except (json.JSONDecodeError, ValueError):
            continue
    decoder = json.JSONDecoder()
    # Prose-wrapped JSON: try each opening brace/bracket, first success wins. Capped
    # so a pathological output cannot spin.
    starts = [m.start() for m in re.finditer(r"[{\[]", s)][:50]
    for i in starts:
        try:
            value, _ = decoder.raw_decode(s[i:])
            return value
        except (json.JSONDecodeError, ValueError):
            continue
    return None


def _classify_http(status: int, body: str) -> tuple[str, bool]:
    """Map an HTTP failure to (error label, retryable)."""
    if status == 429:
        return "rate_limit", True
    if status >= 500:
        return "server_error", True
    low = body.lower()
    if status == 400 and ("context" in low and ("length" in low or "window" in low or "exceed" in low)):
        return "context_overflow", False
    return f"http_{status}", False


class LLMClient:
    def __init__(self, base_url: str, api_key: str | None, model: str,
                 max_concurrency: int = 32, timeout_s: int = 120,
                 max_retries: int = 3, log_path: Path | None = None,
                 rpm: int | None = DEFAULT_RPM,
                 extra_headers: Mapping[str, str] | None = None):
        self.base_url = base_url.rstrip("/")
        self.api_key = api_key
        self.model = model
        self.max_retries = max_retries
        self.log_path = Path(log_path) if log_path else None
        self._sem = asyncio.Semaphore(max_concurrency)
        # rpm=None disables the bucket, for a different endpoint or an offline test.
        self.limiter = RateLimiter(rpm) if rpm else None
        headers: dict[str, str] = {}
        if api_key:
            headers["Authorization"] = f"Bearer {api_key}"
        for name, value in (extra_headers or {}).items():
            if name.lower() == "authorization":
                raise ValueError("extra_headers may not override Authorization")
            headers[str(name)] = str(value)
        self._http = httpx.AsyncClient(
            timeout=httpx.Timeout(timeout_s),
            headers=headers,
            limits=httpx.Limits(max_connections=max_concurrency + 4),
        )
        # None = untested, False = endpoint rejected response_format for this model;
        # learned once per client so only the first call pays the probe 400.
        self._json_mode: bool | None = None

    async def aclose(self) -> None:
        await self._http.aclose()

    # -- public API ---------------------------------------------------------

    async def complete(self, system: str, user: str,
                       schema: dict | None = None,
                       temperature: float = 0.0,
                       max_tokens: int = 3072,
                       task_id: str | None = None,
                       stage: str | None = None) -> LLMResult:
        async with self._sem:
            result = await self._complete_inner(
                system, user, schema, temperature, max_tokens, stage)
        self._log(task_id, result)
        return result

    async def _throttle(self) -> None:
        if self.limiter is not None:
            await self.limiter.acquire()

    async def complete_many(self, calls: list[dict]) -> list[LLMResult]:
        """Concurrent batch: each dict is kwargs for `complete`. Order preserved;
        concurrency bounded by the client's semaphore."""
        return list(await asyncio.gather(*(self.complete(**c) for c in calls)))

    # -- internals ----------------------------------------------------------

    async def _complete_inner(self, system: str, user: str, schema: dict | None,
                              temperature: float, max_tokens: int,
                              stage: str | None) -> LLMResult:
        messages = []
        if system:
            messages.append({"role": "system", "content": system})
        messages.append({"role": "user", "content": user})

        attempts = 0
        in_tok = out_tok = 0
        t_start = time.monotonic()
        error: str | None = None
        text = ""
        finish = None

        for retry in range(self.max_retries + 1):
            body = {"model": self.model, "messages": messages,
                    "temperature": temperature, "max_tokens": max_tokens}
            if schema is not None and self._json_mode is not False:
                body["response_format"] = {"type": "json_object"}
            attempts += 1
            status, payload, err = await self._post(body, stage=stage)

            if err is not None:
                error = err
                if retry < self.max_retries:
                    await asyncio.sleep(BACKOFF_S[min(retry, len(BACKOFF_S) - 1)])
                    continue
                break

            if status != 200:
                text_body = payload if isinstance(payload, str) else json.dumps(payload)
                if (status == 400 and schema is not None and self._json_mode is None
                        and "response_format" in text_body):
                    # Endpoint lacks JSON mode for this model: remember and redo the
                    # same attempt with the schema carried by the prompt alone.
                    self._json_mode = False
                    continue
                error, retryable = _classify_http(status, text_body)
                if retryable and retry < self.max_retries:
                    await asyncio.sleep(BACKOFF_S[min(retry, len(BACKOFF_S) - 1)])
                    continue
                break

            if schema is not None and self._json_mode is None:
                self._json_mode = True
            choice = payload["choices"][0]
            # Probes never saw null content, but the guard costs one expression.
            text = choice["message"].get("content") or ""
            finish = choice.get("finish_reason")
            usage = payload.get("usage") or {}
            in_tok += int(usage.get("prompt_tokens") or 0)
            out_tok += int(usage.get("completion_tokens") or 0)
            error = None
            break

        latency = time.monotonic() - t_start
        if error is not None:
            return LLMResult(text=text, parsed=None, model=self.model,
                             input_tokens=in_tok, output_tokens=out_tok,
                             latency_s=latency, attempts=attempts, error=error)

        if schema is None:
            return LLMResult(text=text, parsed=None, model=self.model,
                             input_tokens=in_tok, output_tokens=out_tok,
                             latency_s=latency, attempts=attempts, error=None)

        parsed = self._coerce(extract_json(text), schema)
        if parsed is None:
            # One repair round-trip with the raw output; measured models cut JSON
            # mid-string on finish_reason=length, which repair can often close.
            attempts += 1
            r_status, r_payload, r_err = await self._post({
                "model": self.model, "temperature": 0.0, "max_tokens": max_tokens,
                "messages": [
                    {"role": "system",
                     "content": "You repair malformed JSON. Output only the corrected JSON object, nothing else."},
                    {"role": "user", "content": text or "(empty)"},
                ],
            }, stage="repair" if stage else None)
            if r_err is None and r_status == 200:
                usage = r_payload.get("usage") or {}
                in_tok += int(usage.get("prompt_tokens") or 0)
                out_tok += int(usage.get("completion_tokens") or 0)
                repaired = r_payload["choices"][0]["message"].get("content") or ""
                parsed = self._coerce(extract_json(repaired), schema)

        latency = time.monotonic() - t_start
        if parsed is None:
            error = "truncated" if finish == "length" else "json_invalid"
        return LLMResult(text=text, parsed=parsed, model=self.model,
                         input_tokens=in_tok, output_tokens=out_tok,
                         latency_s=latency, attempts=attempts, error=error)

    def _coerce(self, value: dict | list | None, schema: dict) -> dict | None:
        """Shape recovery: upstream detector prompts tell the model to 'output a empty
        array', so a bare top-level array is wrapped into the expected object when the
        schema has a `findings` property."""
        if isinstance(value, dict):
            return value
        if isinstance(value, list) and "findings" in (schema.get("properties") or {}):
            return {"findings": value}
        return None

    async def _post(
        self, body: dict, stage: str | None = None
    ) -> tuple[int, dict | str, str | None]:
        """One HTTP round-trip; network-level failures come back as labels.

        The bucket is drained here rather than in `complete()` so that retries and
        the JSON-repair round-trip also pay for themselves -- they are requests the
        gateway counts, and a run that retries heavily would otherwise sail past
        the cap and earn more 429s, which is the failure loop this prevents.
        """
        await self._throttle()
        try:
            headers = {"X-Bastet-Stage": stage} if stage else None
            r = await self._http.post(
                f"{self.base_url}/chat/completions", json=body, headers=headers)
        except httpx.TimeoutException:
            return 0, "", "timeout"
        except httpx.HTTPError:
            return 0, "", "connection_error"
        if r.status_code != 200:
            return r.status_code, r.text, None
        try:
            return 200, r.json(), None
        except ValueError:
            return 0, "", "connection_error"

    def _log(self, task_id: str | None, result: LLMResult) -> None:
        if self.log_path is None:
            return
        line = json.dumps({
            "ts": datetime.now(timezone.utc).isoformat(timespec="seconds"),
            "task_id": task_id,
            "model": result.model,
            "input_tokens": result.input_tokens,
            "output_tokens": result.output_tokens,
            "latency_s": round(result.latency_s, 3),
            "attempts": result.attempts,
            "error": result.error,
        })
        self.log_path.parent.mkdir(parents=True, exist_ok=True)
        with self.log_path.open("a") as fh:
            fh.write(line + "\n")
