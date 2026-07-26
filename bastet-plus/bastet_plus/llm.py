"""OpenAI-compatible chat client with the reliability layer the original harness lacked.

Replaces the n8n stack (Docker + Postgres + webhooks + a busy-wait polling loop
with no timeout) with a single ~300 line module that talks straight to any
``/v1/chat/completions`` endpoint.

What it adds over the original:
  * bounded retries with exponential backoff + jitter on 429/5xx/timeouts
  * a hard per-request timeout (original: ``while True`` with no sleep, no ceiling)
  * a content-addressed sqlite response cache, so re-running an evaluation is
    free and A/B comparisons are reproducible
  * token / latency / cost accounting per call
  * a structured-output ladder: native ``json_schema`` -> ``json_object`` ->
    plain text + extraction, with a bounded self-repair round-trip
"""

from __future__ import annotations

import hashlib
import json
import os
import random
import re
import sqlite3
import threading
import time
import urllib.error
import urllib.request
from dataclasses import dataclass, field

from .config import LLMConfig


class LLMError(RuntimeError):
    pass


# --------------------------------------------------------------------------
# usage accounting
# --------------------------------------------------------------------------


@dataclass
class Usage:
    calls: int = 0
    cache_hits: int = 0
    retries: int = 0
    failures: int = 0
    prompt_tokens: int = 0
    completion_tokens: int = 0
    wall_seconds: float = 0.0
    _lock: threading.Lock = field(default_factory=threading.Lock, repr=False)

    def add(self, **kw: float) -> None:
        with self._lock:
            for k, v in kw.items():
                setattr(self, k, getattr(self, k) + v)

    def cost(self, cfg: LLMConfig) -> float:
        return (self.prompt_tokens * cfg.price_in + self.completion_tokens * cfg.price_out) / 1_000_000

    def as_dict(self, cfg: LLMConfig | None = None) -> dict:
        d = {
            "calls": self.calls,
            "cache_hits": self.cache_hits,
            "retries": self.retries,
            "failures": self.failures,
            "prompt_tokens": self.prompt_tokens,
            "completion_tokens": self.completion_tokens,
            "total_tokens": self.prompt_tokens + self.completion_tokens,
            "llm_wall_seconds": round(self.wall_seconds, 2),
        }
        if cfg is not None:
            d["est_cost_usd"] = round(self.cost(cfg), 6)
        return d


# --------------------------------------------------------------------------
# response cache
# --------------------------------------------------------------------------


class ResponseCache:
    """Content-addressed cache. Key = sha256 of the exact request payload.

    Makes evaluation reruns free and, more importantly, makes an A/B comparison
    honest: if you re-run the baseline after tweaking only the enhanced side,
    the baseline replays byte-identical model output instead of re-rolling the
    dice.
    """

    def __init__(self, path: str, enabled: bool = True):
        self.enabled = enabled
        self._local = threading.local()
        self.path = path
        if enabled:
            os.makedirs(os.path.dirname(os.path.abspath(path)) or ".", exist_ok=True)
            with self._conn() as c:
                c.execute("CREATE TABLE IF NOT EXISTS resp (k TEXT PRIMARY KEY, v TEXT, ts REAL)")

    def _conn(self) -> sqlite3.Connection:
        conn = getattr(self._local, "conn", None)
        if conn is None:
            conn = sqlite3.connect(self.path, timeout=30)
            conn.execute("PRAGMA journal_mode=WAL")
            self._local.conn = conn
        return conn

    @staticmethod
    def key(payload: dict) -> str:
        return hashlib.sha256(json.dumps(payload, sort_keys=True, ensure_ascii=False).encode()).hexdigest()

    def get(self, k: str):
        if not self.enabled:
            return None
        row = self._conn().execute("SELECT v FROM resp WHERE k=?", (k,)).fetchone()
        return json.loads(row[0]) if row else None

    def put(self, k: str, value: dict) -> None:
        if not self.enabled:
            return
        with self._conn() as c:
            c.execute(
                "INSERT OR REPLACE INTO resp (k, v, ts) VALUES (?,?,?)",
                (k, json.dumps(value, ensure_ascii=False), time.time()),
            )


# --------------------------------------------------------------------------
# JSON extraction / repair
# --------------------------------------------------------------------------

_FENCE = re.compile(r"```(?:json|JSON)?\s*(.*?)```", re.S)


def extract_json(text: str):
    """Best-effort recovery of a JSON value from a model response.

    The original harness delegated this to n8n's structured output parser and,
    on failure, silently dropped the finding (``escape one``). Weight-open
    models wrap JSON in prose and fences far more often than gpt-4o-mini does,
    so this ladder is what keeps recall from collapsing when you swap models.
    """
    if text is None:
        return None
    candidates: list[str] = []
    stripped = text.strip()
    if stripped:
        candidates.append(stripped)
    candidates.extend(m.strip() for m in _FENCE.findall(text))
    # Longest balanced [...] or {...} region.
    for opener, closer in (("[", "]"), ("{", "}")):
        start = text.find(opener)
        end = text.rfind(closer)
        if start != -1 and end > start:
            candidates.append(text[start : end + 1])

    for cand in candidates:
        for attempt in (cand, _drop_trailing_commas(cand)):
            try:
                return json.loads(attempt)
            except Exception:
                continue
    return None


def _drop_trailing_commas(s: str) -> str:
    return re.sub(r",(\s*[}\]])", r"\1", s)


# --------------------------------------------------------------------------
# client
# --------------------------------------------------------------------------

_RETRY_STATUS = {408, 409, 425, 429, 500, 502, 503, 504}


class LLMClient:
    def __init__(self, cfg: LLMConfig, usage: Usage | None = None, log_path: str | None = None):
        self.cfg = cfg
        self.usage = usage if usage is not None else Usage()
        self.cache = ResponseCache(cfg.cache_path, cfg.cache_enabled)
        self._sem = threading.Semaphore(max(1, cfg.concurrency))
        # Records how each structured call actually resolved, so the report can
        # show how often the model needed coaxing.
        self.parse_stats = {"native": 0, "extracted": 0, "repaired": 0, "failed": 0}
        self._stats_lock = threading.Lock()

        # Full request/response transcript. Off by default because it embeds
        # contract source verbatim and grows without bound; on when you need to
        # audit *why* a particular finding was produced. The response cache is
        # NOT a substitute -- it is keyed by a hash of the request, so it can
        # tell you what the model said but never what it was asked.
        self.log_path = log_path or (cfg.call_log_path or None)
        self._log_lock = threading.Lock()
        if self.log_path:
            os.makedirs(os.path.dirname(os.path.abspath(self.log_path)) or ".", exist_ok=True)

    def _log(self, record: dict) -> None:
        if not self.log_path:
            return
        with self._log_lock:
            with open(self.log_path, "a", encoding="utf-8") as fh:
                fh.write(json.dumps(record, ensure_ascii=False) + "\n")

    # -- raw ---------------------------------------------------------------

    def _post(self, payload: dict) -> dict:
        req = urllib.request.Request(
            self.cfg.base_url.rstrip("/") + "/chat/completions",
            data=json.dumps(payload, ensure_ascii=False).encode("utf-8"),
            headers={
                "Authorization": f"Bearer {self.cfg.api_key}",
                "Content-Type": "application/json",
            },
            method="POST",
        )
        with urllib.request.urlopen(req, timeout=self.cfg.request_timeout) as r:
            return json.loads(r.read().decode("utf-8"))

    def complete(self, messages: list[dict], *, model: str | None = None, temperature: float | None = None,
                 max_tokens: int | None = None, response_format: dict | None = None,
                 seed: int | None = ..., context: dict | None = None) -> str:
        """One chat completion, with cache + retry. Returns assistant content.

        ``context`` is metadata for the call log only (which detector, which
        file, which sample). It never enters the request payload, so it cannot
        perturb the cache key.
        """
        t_call = time.time()
        payload = {
            "model": model or self.cfg.model,
            "messages": messages,
            "temperature": self.cfg.temperature if temperature is None else temperature,
            "max_tokens": max_tokens or self.cfg.max_tokens,
        }
        if self.cfg.top_p != 1.0:
            payload["top_p"] = self.cfg.top_p
        s = self.cfg.seed if seed is ... else seed
        if s is not None:
            payload["seed"] = s
        if response_format is not None:
            payload["response_format"] = response_format

        ck = ResponseCache.key(payload)
        hit = self.cache.get(ck)
        if hit is not None:
            self.usage.add(cache_hits=1)
            self._log({
                "ts": t_call, "event": "cache_hit", "request_sha256": ck,
                "context": context or {}, "model": payload["model"],
                "temperature": payload["temperature"], "seed": payload.get("seed"),
                "response_format": (response_format or {}).get("type"),
                "messages": messages, "response": hit["content"],
                "usage": hit.get("usage", {}), "latency_s": round(time.time() - t_call, 3),
            })
            return hit["content"]

        last_err: Exception | None = None
        for attempt in range(self.cfg.max_retries + 1):
            if attempt:
                delay = min(30.0, 1.5 * (2 ** (attempt - 1))) * (0.7 + 0.6 * random.random())
                time.sleep(delay)
                self.usage.add(retries=1)
            t0 = time.time()
            try:
                with self._sem:
                    body = self._post(payload)
            except urllib.error.HTTPError as e:
                detail = ""
                try:
                    detail = e.read().decode("utf-8", "replace")[:500]
                except Exception:
                    pass
                last_err = LLMError(f"HTTP {e.code}: {detail}")
                if e.code not in _RETRY_STATUS:
                    break
                continue
            except Exception as e:  # timeout, connection reset, malformed body
                last_err = e
                continue
            finally:
                self.usage.add(wall_seconds=time.time() - t0)

            u = body.get("usage") or {}
            self.usage.add(
                calls=1,
                prompt_tokens=u.get("prompt_tokens", 0) or 0,
                completion_tokens=u.get("completion_tokens", 0) or 0,
            )
            choices = body.get("choices") or []
            if not choices:
                last_err = LLMError(f"no choices in response: {str(body)[:300]}")
                continue
            content = choices[0].get("message", {}).get("content") or ""
            self.cache.put(ck, {"content": content, "usage": u})
            self._log({
                "ts": t_call, "event": "completion", "request_sha256": ck,
                "context": context or {}, "model": payload["model"],
                "temperature": payload["temperature"], "seed": payload.get("seed"),
                "response_format": (response_format or {}).get("type"),
                "attempts": attempt + 1,
                "messages": messages, "response": content, "usage": u,
                "latency_s": round(time.time() - t_call, 3),
            })
            return content

        self.usage.add(failures=1)
        self._log({
            "ts": t_call, "event": "failed", "request_sha256": ck,
            "context": context or {}, "model": payload["model"],
            "attempts": self.cfg.max_retries + 1, "error": str(last_err),
            "messages": messages, "latency_s": round(time.time() - t_call, 3),
        })
        raise LLMError(f"request failed after {self.cfg.max_retries + 1} attempts: {last_err}")

    # -- structured --------------------------------------------------------

    def complete_json(self, messages: list[dict], schema: dict, *, model: str | None = None,
                      temperature: float | None = None, max_tokens: int | None = None,
                      seed: int | None = ..., schema_name: str = "result",
                      context: dict | None = None):
        """Return parsed JSON honouring ``schema``, degrading gracefully.

        Ladder: native ``json_schema`` -> ``json_object`` -> free text, then a
        single repair round-trip. Every rung is recorded in ``parse_stats``.
        """
        rungs = [
            ("native", {"type": "json_schema", "json_schema": {"name": schema_name, "strict": True, "schema": schema}}),
            ("native", {"type": "json_object"}),
            ("extracted", None),
        ]
        raw = ""
        for rung_idx, (label, rf) in enumerate(rungs):
            ctx = dict(context or {}, rung=rung_idx, rung_kind=(rf or {}).get("type", "plain"))
            try:
                raw = self.complete(messages, model=model, temperature=temperature,
                                    max_tokens=max_tokens, response_format=rf, seed=seed,
                                    context=ctx)
            except LLMError:
                continue
            parsed = extract_json(raw)
            if parsed is not None:
                self._bump(label if rf is not None else "extracted")
                return parsed

        # Last resort: show the model its own broken output and ask for JSON only.
        try:
            fixed = self.complete(
                [
                    {"role": "system", "content": "You convert malformed output into valid JSON. Reply with JSON only, no prose, no code fences."},
                    {"role": "user", "content": f"Target JSON schema:\n{json.dumps(schema)}\n\nMalformed output:\n{raw[:6000]}\n\nReturn the corrected JSON."},
                ],
                model=model, temperature=0.0, max_tokens=max_tokens, seed=seed,
                context=dict(context or {}, rung="repair"),
            )
            parsed = extract_json(fixed)
            if parsed is not None:
                self._bump("repaired")
                return parsed
        except LLMError:
            pass

        self._bump("failed")
        return None

    def _bump(self, key: str) -> None:
        with self._stats_lock:
            self.parse_stats[key] = self.parse_stats.get(key, 0) + 1
