"""Run a task plan against the LLM: bounded concurrency, append-only persistence.

Both arms flow through this one function (DESIGN 0.1); the executor knows nothing
about routed vs broadcast. Its contract is resumability: every completed task is one
flushed line in results.jsonl before anything else happens, so killing a 40K-call
broadcast run at any instant loses at most the calls in flight. Resume is re-running
the same command -- `store.done_ids()` skips what is already on disk, and task_id
embeds model + prompt_version so a config change invalidates the cache by itself.

Concurrency is bounded inside LLMClient (its semaphore); the executor simply gathers
one coroutine per task. Prompts are built inside the coroutine, not up front, so a
huge plan does not hold every rendered prompt in memory at once.

Error policy: done_ids() treats any persisted line as done, so persisting a failure
freezes it forever. Transient failures (timeout, rate limit, 5xx, connection) are
therefore NOT persisted -- the client already burned its own retries, and the next
resume gets a fresh attempt. Permanent failures (json_invalid after repair,
context_overflow, http_4xx) are persisted with their error label: retrying them
would loop forever, and the label in results.jsonl is the audit trail.
"""

from __future__ import annotations

import asyncio
import time
from collections import Counter
from typing import Callable

from .findings import parse_findings, to_dict
from .llm import LLMClient
from .prompts import OUTPUT_SCHEMA, PROMPT_VERSION, build_prompt
from .routing import Task
from .runstore import RunStore, task_id as make_task_id

PROGRESS_EVERY = 500

# Failures worth a fresh attempt on the next resume; everything else is permanent.
TRANSIENT_ERRORS = {"timeout", "rate_limit", "server_error", "connection_error"}


async def run_tasks(tasks: list[Task], client: LLMClient, store: RunStore,
                    exemplar_fn: Callable[[Task], list[dict]] | None = None) -> None:
    """Execute every not-yet-done task, appending each result as it completes.

    exemplar_fn injects retrieved exemplars into the prompt (routed synthesized
    detectors only, per DESIGN 1.4); the caller decides the policy, the executor
    just applies it. None means no exemplars for anyone -- the broadcast setting.
    """
    done = store.done_ids()

    pending: list[tuple[str, Task]] = []
    seen: set[str] = set()
    for t in tasks:
        tid = make_task_id(t, client.model, PROMPT_VERSION)
        if tid in done or tid in seen:  # seen guards duplicate plan entries
            continue
        seen.add(tid)
        pending.append((tid, t))
    # Deterministic execution order so two resumes of the same run walk the same
    # frontier; the ids are content hashes, the order itself is arbitrary but fixed.
    pending.sort(key=lambda p: p[0])

    total = len(tasks)
    print(f"[executor] {total} tasks planned, {total - len(pending)} already done, "
          f"{len(pending)} to run", flush=True)
    if not pending:
        return

    completed = 0
    errors: Counter[str] = Counter()
    latency_sum = 0.0
    t0 = time.monotonic()

    async def one(tid: str, t: Task) -> None:
        nonlocal completed, latency_sum
        exemplars = exemplar_fn(t) if exemplar_fn is not None else None
        system, user = build_prompt(t, exemplars)
        result = await client.complete(system, user, schema=OUTPUT_SCHEMA, task_id=tid)
        if result.error in TRANSIENT_ERRORS:
            errors[result.error] += 1  # not persisted: the next resume retries it
        else:
            found = [to_dict(f) for f in parse_findings(t, result)]
            # Persist before counting: a crash after this line costs nothing on resume.
            store.append(tid, result, found)
            if result.error:
                errors[result.error] += 1
        completed += 1
        latency_sum += result.latency_s
        if completed % PROGRESS_EVERY == 0 or completed == len(pending):
            elapsed = time.monotonic() - t0
            err_note = f", errors={dict(errors)}" if errors else ""
            print(f"[executor] {completed}/{len(pending)} done "
                  f"({elapsed:.0f}s elapsed, avg latency {latency_sum / completed:.2f}s"
                  f"{err_note})", flush=True)

    await asyncio.gather(*(one(tid, t) for tid, t in pending))

    if errors:
        transient = {k: v for k, v in errors.items() if k in TRANSIENT_ERRORS}
        note = " (rerun the same command to retry transient ones)" if transient else ""
        print(f"[executor] finished with errors: {dict(errors)}{note}", flush=True)
