"""Client for the AIS3 OpenAI-compatible gateway.

The binding constraint here is measured, not assumed. Live response headers report

    x-litellm-key-rpm-limit: 120
    x-litellm-key-tpm-limit: 20000000

which is 166,667 tokens for every one request. Requests are the scarce resource and
context is very nearly free, so this client rate-limits *requests* and never rations
tokens. Every architectural decision in ARBITER follows from that ratio; the limiter is
where it is enforced.

Two fairness obligations from BENCH_PROTOCOL are discharged in this file rather than in
the arms, so that neither arm can discharge them differently:

  * clause 1 -- a response whose ``content`` is null but which carries reasoning text
    must be read from the reasoning field instead of being scored as a parse failure.
    Both arms therefore see the same recovery behaviour.
  * the model actually used is read back out of the response body and compared to the
    model that was requested. A silent server-side reroute would otherwise invalidate a
    same-model comparison without leaving a trace.

Cost is taken from the ``x-litellm-response-cost`` header and summed. It is never
estimated from token counts.
"""

from __future__ import annotations

import json
import os
import threading
import time
import urllib.error
import urllib.request
from collections import deque
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

DEFAULT_BASE_URL = "https://llm-api.zoolab.org/v1"

# The measured cap is 120 rpm, enforced per API KEY rather than per process. The key is
# shared, so the whole 120 is never ours: a run that assumes it gets all of them collides
# with whatever else the team is doing and burns retries discovering that. We therefore
# claim a minority share by default and leave the rest of the window for other users.
# Raise it with --rpm only when the key is known to be idle.
DEFAULT_RPM = 45


class GatewayError(RuntimeError):
    """A request failed in a way retrying did not fix."""


class ModelMismatch(RuntimeError):
    """The gateway answered with a different model than the one requested.

    This is fatal rather than a warning. The entire claim is a same-model comparison,
    so a silent reroute would make the numbers meaningless while still producing them.
    """


@dataclass
class Usage:
    """Everything spent, accumulated across a run."""

    requests: int = 0
    prompt_tokens: int = 0
    completion_tokens: int = 0
    cost_usd: float = 0.0
    retries: int = 0
    http_errors: int = 0
    parse_failures: int = 0
    reasoning_recoveries: int = 0
    fingerprints: set[str] = field(default_factory=set)
    models_seen: set[str] = field(default_factory=set)

    def merge(self, other: "Usage") -> None:
        self.requests += other.requests
        self.prompt_tokens += other.prompt_tokens
        self.completion_tokens += other.completion_tokens
        self.cost_usd += other.cost_usd
        self.retries += other.retries
        self.http_errors += other.http_errors
        self.parse_failures += other.parse_failures
        self.reasoning_recoveries += other.reasoning_recoveries
        self.fingerprints |= other.fingerprints
        self.models_seen |= other.models_seen

    def as_dict(self) -> dict[str, Any]:
        return {
            "requests": self.requests,
            "prompt_tokens": self.prompt_tokens,
            "completion_tokens": self.completion_tokens,
            "cost_usd": round(self.cost_usd, 6),
            "retries": self.retries,
            "http_errors": self.http_errors,
            "parse_failures": self.parse_failures,
            "reasoning_recoveries": self.reasoning_recoveries,
            "system_fingerprints": sorted(self.fingerprints),
            "models_seen": sorted(self.models_seen),
        }


class RateLimiter:
    """Sliding-window limiter over a shared request budget.

    A semaphore on worker count would not do: the cap is on requests per minute for the
    whole key, so sixteen workers and one worker have to reach the same steady-state
    rate. Concurrency here bounds memory and latency hiding, never throughput.
    """

    def __init__(self, rpm: int = DEFAULT_RPM) -> None:
        self.rpm = rpm
        self._times: deque[float] = deque()
        self._lock = threading.Lock()

    def acquire(self) -> None:
        if self.rpm <= 0:
            return
        while True:
            with self._lock:
                now = time.monotonic()
                while self._times and now - self._times[0] >= 60.0:
                    self._times.popleft()
                if len(self._times) < self.rpm:
                    self._times.append(now)
                    return
                sleep_for = 60.0 - (now - self._times[0]) + 0.01
            time.sleep(max(sleep_for, 0.01))


class Gateway:
    """Thread-safe chat-completions client with a shared rate limit and a ledger."""

    def __init__(
        self,
        model: str,
        api_key: str | None = None,
        base_url: str = DEFAULT_BASE_URL,
        rpm: int = DEFAULT_RPM,
        limiter: RateLimiter | None = None,
        ledger_path: Path | None = None,
        timeout: float = 600.0,
        max_retries: int = 7,
        strict_model: bool = True,
    ) -> None:
        key = api_key or os.environ.get("AIS3_API_KEY", "")
        if not key:
            raise GatewayError(
                "No API key. Set AIS3_API_KEY in the environment; it is never read "
                "from a file in the repository and never written to one."
            )
        self.model = model
        self._key = key
        self.base_url = base_url.rstrip("/")
        self.limiter = limiter or RateLimiter(rpm)
        self.timeout = timeout
        self.max_retries = max_retries
        self.strict_model = strict_model
        self.usage = Usage()
        self._usage_lock = threading.Lock()
        self._ledger_path = ledger_path
        self._ledger_lock = threading.Lock()

    # -- ledger ---------------------------------------------------------------

    def _record(self, entry: dict[str, Any]) -> None:
        if self._ledger_path is None:
            return
        with self._ledger_lock:
            self._ledger_path.parent.mkdir(parents=True, exist_ok=True)
            with self._ledger_path.open("a", encoding="utf-8") as fh:
                fh.write(json.dumps(entry, ensure_ascii=False) + "\n")
                fh.flush()
                os.fsync(fh.fileno())

    # -- the call -------------------------------------------------------------

    def chat(
        self,
        messages: list[dict[str, Any]],
        *,
        max_tokens: int,
        temperature: float = 0.0,
        tools: list[dict[str, Any]] | None = None,
        tool_choice: str | dict[str, Any] | None = None,
        response_format: dict[str, Any] | None = None,
        tag: str = "",
    ) -> dict[str, Any]:
        """One chat completion. Returns the assistant message dict, enriched.

        The returned dict is the raw ``choices[0].message`` plus three keys this
        project adds: ``_finish_reason``, ``_recovered_from_reasoning`` and ``_usage``.
        """
        payload: dict[str, Any] = {
            "model": self.model,
            "messages": messages,
            "max_tokens": max_tokens,
            "temperature": temperature,
        }
        if tools:
            payload["tools"] = tools
            payload["tool_choice"] = tool_choice or "auto"
        if response_format:
            payload["response_format"] = response_format

        body = json.dumps(payload).encode("utf-8")
        last_error: str = ""

        for attempt in range(self.max_retries):
            self.limiter.acquire()
            req = urllib.request.Request(
                f"{self.base_url}/chat/completions",
                data=body,
                headers={
                    "Authorization": f"Bearer {self._key}",
                    "Content-Type": "application/json",
                },
                method="POST",
            )
            started = time.monotonic()
            try:
                with urllib.request.urlopen(req, timeout=self.timeout) as resp:
                    raw = resp.read().decode("utf-8")
                    headers = dict(resp.headers)
                data = json.loads(raw)
            except urllib.error.HTTPError as exc:
                detail = exc.read().decode("utf-8", "replace")[:400]
                last_error = f"HTTP {exc.code}: {detail}"
                with self._usage_lock:
                    self.usage.http_errors += 1
                    self.usage.retries += 1
                # 429 is the rate cap, 5xx is the backend. Both are worth retrying;
                # 4xx other than 429 is a bad request and will not improve.
                if exc.code != 429 and exc.code < 500:
                    raise GatewayError(last_error) from exc
                if exc.code == 429:
                    # The limiter is a sliding window over OUR requests; a 429 means
                    # someone else spent the shared budget. Backing off by seconds just
                    # collides again, so wait out most of a window.
                    time.sleep(min(25.0 + 10.0 * attempt, 70.0))
                else:
                    time.sleep(min(2.0 * (2**attempt), 30.0))
                continue
            except (urllib.error.URLError, TimeoutError, json.JSONDecodeError) as exc:
                last_error = f"{type(exc).__name__}: {exc}"
                with self._usage_lock:
                    self.usage.retries += 1
                time.sleep(min(2.0 * (2**attempt), 30.0))
                continue

            elapsed = time.monotonic() - started
            served_model = data.get("model", "")
            fingerprint = data.get("system_fingerprint", "")
            usage_block = data.get("usage") or {}
            cost = _header_cost(headers)

            with self._usage_lock:
                self.usage.requests += 1
                self.usage.prompt_tokens += int(usage_block.get("prompt_tokens") or 0)
                self.usage.completion_tokens += int(
                    usage_block.get("completion_tokens") or 0
                )
                self.usage.cost_usd += cost
                if fingerprint:
                    self.usage.fingerprints.add(fingerprint)
                if served_model:
                    self.usage.models_seen.add(served_model)

            if self.strict_model and served_model and not _models_agree(
                self.model, served_model
            ):
                raise ModelMismatch(
                    f"requested {self.model!r} but the gateway served "
                    f"{served_model!r}. A same-model comparison cannot proceed."
                )

            choice = (data.get("choices") or [{}])[0]
            message = dict(choice.get("message") or {})
            message["_finish_reason"] = choice.get("finish_reason", "")
            message["_usage"] = usage_block
            message["_cost_usd"] = cost
            message["_system_fingerprint"] = fingerprint

            recovered = _recover_content(message)
            message["_recovered_from_reasoning"] = recovered
            if recovered:
                with self._usage_lock:
                    self.usage.reasoning_recoveries += 1

            self._record(
                {
                    "tag": tag,
                    "model_requested": self.model,
                    "model_served": served_model,
                    "system_fingerprint": fingerprint,
                    "finish_reason": message["_finish_reason"],
                    "prompt_tokens": usage_block.get("prompt_tokens"),
                    "completion_tokens": usage_block.get("completion_tokens"),
                    "cost_usd": cost,
                    "elapsed_s": round(elapsed, 3),
                    "n_tool_calls": len(message.get("tool_calls") or []),
                    "recovered_from_reasoning": recovered,
                    "attempt": attempt,
                }
            )
            return message

        raise GatewayError(
            f"gave up after {self.max_retries} attempts; last error: {last_error}"
        )

    def note_parse_failure(self) -> None:
        """Count a response that could not be parsed.

        Kept separate from every other counter on purpose. BENCH_PROTOCOL clause 1
        forbids folding parse failures into false negatives, which would let either arm
        win by degrading the other's output handling.
        """
        with self._usage_lock:
            self.usage.parse_failures += 1


def _models_agree(requested: str, served: str) -> bool:
    """Compare model ids tolerantly enough to survive gateway prefixing.

    LiteLLM sometimes echoes back a bare model name where the request carried a
    namespaced one. Comparing the last path segment keeps that from tripping the
    guard while still catching an actual reroute to a different model.
    """
    return requested.split("/")[-1].lower() == served.split("/")[-1].lower()


def _header_cost(headers: dict[str, str]) -> float:
    for key, value in headers.items():
        if key.lower() == "x-litellm-response-cost":
            try:
                return float(value)
            except (TypeError, ValueError):
                return 0.0
    return 0.0


def _recover_content(message: dict[str, Any]) -> bool:
    """Fill empty ``content`` from a reasoning field. Returns True if it did.

    Gemma-family models on this gateway return ``content: null`` with the answer in a
    reasoning field when they run out of ``max_tokens``. Scoring that as an empty answer
    would hand us a win over the baseline that came from response handling rather than
    from detection, which BENCH_PROTOCOL clause 1 forbids.
    """
    if message.get("content"):
        return False
    for key in ("reasoning_content", "reasoning"):
        value = message.get(key)
        if isinstance(value, str) and value.strip():
            message["content"] = value
            return True
    extra = message.get("provider_specific_fields")
    if isinstance(extra, dict):
        for key in ("reasoning_content", "reasoning"):
            value = extra.get(key)
            if isinstance(value, str) and value.strip():
                message["content"] = value
                return True
    return False
