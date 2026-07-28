#!/usr/bin/env python3
"""Would today's gate have refused the exploits yesterday's gate accepted?

The proof audit found that 25 of 68 claimed proofs were on the PATCHED half of an
authored pair -- contracts the benchmark says are clean. Those runs predate three gates
added since: the value must leave the contract under audit, the predicate must actually
be reached, and setup may not halt the transaction.

Knowing that the old gate was too weak is worth little on its own. What matters is
whether the current one is stronger on exactly those cases, so this recomposes each
exploit from the fragments the agent originally supplied -- recovered from the run's own
turn trace -- and puts them through today's harness unchanged.

The answer is a number, in both directions: how many false positives today's gate
refuses, and how many TRUE positives it refuses along with them, because a gate that
rejects everything is not an improvement.

Pure CPU. No gateway requests.
"""

from __future__ import annotations

import argparse
import glob
import json
import os
import sys
from pathlib import Path

sys.path.insert(0, os.path.expanduser("~/rig/arbiter"))

from arbiter.workspace import Workspace  # noqa: E402

RIG = Path(os.path.expanduser("~/rig/arbiter"))
WS = Path("/tmp/regate")


def load_sources() -> dict[str, str]:
    out: dict[str, str] = {}
    for path in sorted((RIG / "evalsets").glob("*.json")):
        try:
            data = json.loads(path.read_text(encoding="utf-8"))
        except (OSError, json.JSONDecodeError):
            continue
        for item in data.get("items", []):
            if item.get("id") and item.get("code"):
                out.setdefault(item["id"], item["code"])
    return out


def exploit_args(row: dict) -> list[dict]:
    """The run_exploit arguments the agent supplied, from the recorded turn trace."""
    out: list[dict] = []
    for turn in row.get("trace") or []:
        for call in turn.get("tool_calls") or []:
            if call.get("name") != "run_exploit":
                continue
            raw = call.get("arguments") or ""
            try:
                out.append(json.loads(raw))
            except json.JSONDecodeError:
                continue          # truncated in the trace; nothing recoverable
    return out


def regate(job: tuple[str, str, str, list[dict]]) -> dict:
    run, sample_id, source, arg_list = job
    rec = {
        "run": run, "sample_id": sample_id,
        "patched_sample": sample_id.startswith("S_") or sample_id.startswith("S1"),
        "recovered": len(arg_list),
    }
    if not source:
        rec["verdict"] = "source missing"
        return rec
    if not arg_list:
        rec["verdict"] = "fragments not recoverable from trace"
        return rec

    ws = Workspace(WS, f"{run}_{sample_id}"[:80], source)
    accepted = False
    refusals: list[str] = []
    try:
        for i, args in enumerate(arg_list):
            mode = str(args.get("mode") or ("eoa" if args.get("attack_body") else "contract"))
            try:
                solidity = ws.compose_exploit(
                    deploy_code=str(args.get("deploy_code") or ""),
                    attacker_code=str(args.get("attacker_code") or ""),
                    predicate=str(args.get("predicate") or "eth_profit"),
                    observed_getter=str(args.get("observed_getter") or ""),
                    token_expr=str(args.get("token_expr") or ""),
                    liveness_call=str(args.get("liveness_call") or ""),
                    attack_body=str(args.get("attack_body") or ""),
                    honest_body=str(args.get("honest_body") or ""),
                    mode=mode,
                )
            except ValueError as exc:
                refusals.append(f"refused at composition: {str(exc)[:70]}")
                continue
            ws.write_poc(f"Regate{i}", solidity)
            if not ws.build().ok:
                refusals.append("does not compile under today's template")
                continue
            result = ws.run_poc(f"Regate{i}Poc")
            if any(l.strip().startswith("[PASS]") for l in result.combined.splitlines()):
                accepted = True
                break
            reason = next(
                (l.strip()[:80] for l in result.combined.splitlines()
                 if "Arbiter" in l or "ARBITER" in l),
                "predicate not satisfied",
            )
            refusals.append(reason)
    except Exception as exc:  # noqa: BLE001
        rec["verdict"] = f"error: {type(exc).__name__}: {exc}"[:120]
        ws.cleanup()
        return rec
    ws.cleanup()

    rec["verdict"] = "STILL ACCEPTED" if accepted else "refused"
    rec["why"] = refusals[:3]
    return rec


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--runs", default=str(RIG / "runs" / "*.results.jsonl"))
    ap.add_argument("--workers", type=int, default=max(2, (os.cpu_count() or 4) - 4))
    ap.add_argument("--out", type=Path, default=Path("/tmp/regate.jsonl"))
    args = ap.parse_args()

    sources = load_sources()
    jobs: list[tuple[str, str, str, list[dict]]] = []
    for path in sorted(glob.glob(args.runs)):
        run = Path(path).name.replace(".results.jsonl", "")
        for line in Path(path).read_text(encoding="utf-8").splitlines():
            if not line.strip():
                continue
            row = json.loads(line)
            if not (row.get("outcome") or {}).get("proven"):
                continue
            if row.get("path"):
                continue     # in-repo samples need their repository; handled separately
            source = row.get("source") or sources.get(row.get("sample_id", ""), "")
            jobs.append((run, row["sample_id"], source, exploit_args(row)))

    print(f"re-gating {len(jobs)} claimed proofs through today's harness\n", flush=True)
    from concurrent.futures import ProcessPoolExecutor, as_completed

    records: list[dict] = []
    with ProcessPoolExecutor(max_workers=args.workers) as pool:
        futures = [pool.submit(regate, j) for j in jobs]
        for n, fut in enumerate(as_completed(futures), 1):
            records.append(fut.result())
            if n % 10 == 0:
                print(f"  {n}/{len(jobs)}", flush=True)

    args.out.write_text(
        "\n".join(json.dumps(r, ensure_ascii=False) for r in records), encoding="utf-8"
    )

    def bucket(patched: bool) -> tuple[int, int, int]:
        rows = [r for r in records if r["patched_sample"] is patched]
        kept = sum(1 for r in rows if r["verdict"] == "STILL ACCEPTED")
        gone = sum(1 for r in rows if r["verdict"] == "refused")
        return len(rows), kept, gone

    for label, patched in (("on PATCHED samples (should be refused)", True),
                           ("on VULNERABLE samples (should be kept)", False)):
        total, kept, gone = bucket(patched)
        print(f"\n{label}: {total}")
        print(f"   still accepted by today's gate  {kept}")
        print(f"   now refused                     {gone}")
        print(f"   fragments unrecoverable         {total - kept - gone}")

    print("\n--- what today's gate says about the patched-sample proofs ---")
    for r in sorted(records, key=lambda x: x["sample_id"]):
        if not r["patched_sample"]:
            continue
        print(f"  {r['sample_id'][:44]:46s} {r['verdict']:16s} "
              f"{'; '.join(r.get('why') or [])[:70]}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
