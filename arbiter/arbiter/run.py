"""Run ARBITER over an evaluation set: concurrent, resumable, fully recorded.

Concurrency here buys latency hiding, not throughput -- the gateway's 120 rpm cap is per
key, so the rate limiter in ``gateway`` is what actually shapes the run. Workers exist
because each audit spends real wall-clock inside ``forge`` with no request outstanding,
and that time is free to overlap.

Every audit writes one JSONL row containing the verdict, the PoCs the agent wrote, the
compiler and EVM output, and the full turn trace. A run is therefore auditable after the
fact by someone who does not trust the summary, which is the point.
"""

from __future__ import annotations

import json
import os
import threading
import time
from concurrent.futures import ThreadPoolExecutor, as_completed
from pathlib import Path
from typing import Any

from .agent import audit, outcome_to_label
from .gateway import Gateway, RateLimiter
from .workspace import Workspace


def load_evalset(path: Path) -> tuple[dict[str, Any], list[dict[str, Any]]]:
    data = json.loads(path.read_text(encoding="utf-8"))
    return data.get("meta", {}), data["items"]


def truth_map(items: list[dict[str, Any]]) -> dict[str, str]:
    return {item["id"]: item["label"] for item in items}


def run_arbiter(
    *,
    evalset: Path,
    model: str,
    run_id: str,
    out_dir: Path,
    repeats: int = 1,
    concurrency: int = 8,
    max_turns: int = 16,
    max_tokens: int = 4096,
    rpm: int = 110,
    workspace_root: Path | None = None,
    api_key: str | None = None,
) -> dict[str, Any]:
    meta, items = load_evalset(evalset)
    out_dir.mkdir(parents=True, exist_ok=True)
    ws_root = workspace_root or Path("/tmp/arbiter-ws") / run_id

    limiter = RateLimiter(rpm)
    gateway = Gateway(
        model=model,
        api_key=api_key,
        limiter=limiter,
        ledger_path=out_dir / f"{run_id}.ledger.jsonl",
    )

    results_path = out_dir / f"{run_id}.results.jsonl"
    done: set[str] = set()
    if results_path.exists():
        for line in results_path.read_text(encoding="utf-8").splitlines():
            try:
                row = json.loads(line)
            except json.JSONDecodeError:
                continue
            done.add(f"{row['repeat']}::{row['sample_id']}")

    write_lock = threading.Lock()
    started = time.monotonic()

    def one(repeat: int, item: dict[str, Any]) -> dict[str, Any] | None:
        key = f"{repeat}::{item['id']}"
        if key in done:
            return None
        ws = Workspace(ws_root / f"r{repeat}", item["id"], item["code"])
        trace: list[dict[str, Any]] = []
        t0 = time.monotonic()
        try:
            outcome = audit(
                gateway,
                ws,
                max_turns=max_turns,
                max_tokens=max_tokens,
                trace_sink=trace,
            )
            error = ""
        except Exception as exc:  # noqa: BLE001
            from .tools import AgentOutcome

            outcome = AgentOutcome(stop_reason=f"error: {type(exc).__name__}: {exc}")
            error = f"{type(exc).__name__}: {exc}"

        row = {
            "repeat": repeat,
            "sample_id": item["id"],
            "truth": item["label"],
            "predicted": outcome_to_label(outcome),
            "elapsed_s": round(time.monotonic() - t0, 2),
            "error": error,
            "outcome": outcome.as_dict(),
            "trace": trace,
        }
        with write_lock:
            with results_path.open("a", encoding="utf-8") as fh:
                fh.write(json.dumps(row, ensure_ascii=False) + "\n")
                fh.flush()
                os.fsync(fh.fileno())
        ws.cleanup()
        hit = "OK " if row["predicted"] == row["truth"] else "MISS"
        proven = "proven" if outcome.proven else outcome.stop_reason
        print(
            f"  [{hit}] r{repeat} {item['id'][:44]:46s} "
            f"-> {row['predicted']:5s} ({proven}, {outcome.turns}t, "
            f"{row['elapsed_s']}s)",
            flush=True,
        )
        return row

    jobs = [(r, item) for r in range(repeats) for item in items]
    print(
        f"ARBITER  model={model}  samples={len(items)}  repeats={repeats}  "
        f"max_turns={max_turns}  workers={concurrency}  rpm={rpm}",
        flush=True,
    )

    with ThreadPoolExecutor(max_workers=concurrency) as pool:
        futures = [pool.submit(one, r, item) for r, item in jobs]
        for future in as_completed(futures):
            future.result()

    rows = [
        json.loads(line)
        for line in results_path.read_text(encoding="utf-8").splitlines()
        if line.strip()
    ]
    summary = {
        "arm": "arbiter",
        "run_id": run_id,
        "model": model,
        "evalset": str(evalset),
        "evalset_meta": meta,
        "repeats": repeats,
        "max_turns": max_turns,
        "max_tokens": max_tokens,
        "wall_clock_s": round(time.monotonic() - started, 1),
        "usage": gateway.usage.as_dict(),
        "predictions_by_repeat": _by_repeat(rows),
        "no_verdict_rate": _no_verdict_rate(rows),
        "proven_rate": _proven_rate(rows),
        "mean_turns": _mean_turns(rows),
    }
    (out_dir / f"{run_id}.summary.json").write_text(
        json.dumps(summary, ensure_ascii=False, indent=1), encoding="utf-8"
    )
    return summary


def _by_repeat(rows: list[dict[str, Any]]) -> dict[str, dict[str, str]]:
    out: dict[str, dict[str, str]] = {}
    for row in rows:
        out.setdefault(str(row["repeat"]), {})[row["sample_id"]] = row["predicted"]
    return out


def _no_verdict_rate(rows: list[dict[str, Any]]) -> float:
    if not rows:
        return 0.0
    n = sum(1 for r in rows if r["outcome"]["verdict"] == "no_verdict")
    return round(n / len(rows), 4)


def _proven_rate(rows: list[dict[str, Any]]) -> float:
    """Share of vulnerable verdicts backed by an execution.

    Structurally 1.0 for ARBITER, because the submission gate rejects anything else, and
    structurally 0.0 for Bastet, because it has no execution stage. Reported anyway so
    the gate can be verified rather than believed.
    """
    positives = [r for r in rows if r["predicted"] == "vuln"]
    if not positives:
        return 0.0
    return round(
        sum(1 for r in positives if r["outcome"]["proven"]) / len(positives), 4
    )


def _mean_turns(rows: list[dict[str, Any]]) -> float:
    if not rows:
        return 0.0
    return round(sum(r["outcome"]["turns"] for r in rows) / len(rows), 2)
