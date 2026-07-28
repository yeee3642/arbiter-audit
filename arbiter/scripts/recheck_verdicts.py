#!/usr/bin/env python3
"""Re-run a finished run's accepted exploits through the harness as it stands now.

A gate added after a run is a claim about that run, and the claim is cheap to check:
recompose every accepted exploit from the fragments in its own turn trace and put it
through the current predicate. Reported in BOTH directions, because a gate that only
removes false positives is being graded on half its effects -- the same change that
refuses three artefacts may refuse four real findings, which has already happened once
in this project.

Pure CPU. No gateway requests.
"""

from __future__ import annotations

import argparse
import json
import os
import sys
from collections import Counter
from concurrent.futures import ProcessPoolExecutor, as_completed
from pathlib import Path

sys.path.insert(0, os.path.expanduser("~/rig/arbiter"))

from arbiter.workspace import Workspace  # noqa: E402

RIG = Path(os.path.expanduser("~/rig/arbiter"))
WS = Path("/tmp/recheck")


def sources() -> dict[str, str]:
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


def fragments(row: dict) -> list[dict]:
    out = []
    for turn in row.get("trace") or []:
        for call in turn.get("tool_calls") or []:
            if call.get("name") != "run_exploit":
                continue
            try:
                out.append(json.loads(call.get("arguments") or ""))
            except (json.JSONDecodeError, TypeError):
                continue
    return out


def recheck(job: tuple[str, str, str, list[dict]]) -> dict:
    sample_id, truth, source, args_list = job
    rec = {"sample_id": sample_id, "truth": truth, "recovered": len(args_list)}
    if not source or not args_list:
        rec["verdict"] = "fragments not recoverable"
        return rec

    ws = Workspace(WS, sample_id[:70], source)
    accepted = False
    reasons: list[str] = []
    try:
        for i, args in enumerate(args_list):
            predicate = str(args.get("predicate") or "")
            mode = str(args.get("mode") or ("eoa" if args.get("attack_body") else "contract"))
            try:
                if predicate == "victim_loss":
                    solidity = ws.compose_victim_loss(
                        deploy_code=str(args.get("deploy_code") or ""),
                        victim_enter=str(args.get("victim_enter") or ""),
                        victim_exit=str(args.get("victim_exit") or ""),
                        attacker_code=str(args.get("attacker_code") or ""),
                        attack_body=str(args.get("attack_body") or ""),
                        mode=mode,
                        token_expr=str(args.get("token_expr") or ""),
                    )
                else:
                    solidity = ws.compose_exploit(
                        deploy_code=str(args.get("deploy_code") or ""),
                        attacker_code=str(args.get("attacker_code") or ""),
                        predicate=predicate or "eth_profit",
                        observed_getter=str(args.get("observed_getter") or ""),
                        token_expr=str(args.get("token_expr") or ""),
                        liveness_call=str(args.get("liveness_call") or ""),
                        attack_body=str(args.get("attack_body") or ""),
                        honest_body=str(args.get("honest_body") or ""),
                        mode=mode,
                    )
            except ValueError as exc:
                reasons.append("composition refused: " + str(exc).splitlines()[0][:60])
                continue
            name = ws.write_poc(f"Recheck{i}", solidity)
            if not ws.build().ok:
                reasons.append("no build")
                continue
            run = ws.run_poc(name)
            if any(l.strip().startswith("[PASS]") for l in run.combined.splitlines()):
                accepted = True
                break
            reasons.append(next(
                (l.strip()[:70] for l in run.combined.splitlines()
                 if "Arbiter" in l or "ARBITER" in l), "predicate not satisfied"))
    except Exception as exc:  # noqa: BLE001
        rec["verdict"] = f"error: {type(exc).__name__}"
        ws.cleanup()
        return rec
    ws.cleanup()
    rec["verdict"] = "accepted" if accepted else "refused"
    rec["why"] = reasons[:2]
    return rec


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--results", type=Path, required=True)
    ap.add_argument("--workers", type=int, default=max(2, (os.cpu_count() or 4) - 4))
    ap.add_argument("--out", type=Path, default=None,
                    help="write per-sample verdicts, so arms can be combined")
    args = ap.parse_args()

    src = sources()
    rows = [
        json.loads(line)
        for line in args.results.read_text(encoding="utf-8").splitlines()
        if line.strip()
    ]
    jobs = [
        (r["sample_id"], r["truth"], r.get("source") or src.get(r["sample_id"], ""),
         fragments(r))
        for r in rows
        if r.get("predicted") == "vuln"
    ]
    print(f"re-checking {len(jobs)} accepted findings through the harness as it stands\n",
          flush=True)

    out: list[dict] = []
    with ProcessPoolExecutor(max_workers=args.workers) as pool:
        for fut in as_completed([pool.submit(recheck, j) for j in jobs]):
            out.append(fut.result())

    for rec in sorted(out, key=lambda r: (r["truth"], r["sample_id"])):
        kind = "FALSE POSITIVE" if rec["truth"] == "safe" else "true positive "
        print(f"  {kind} {rec['sample_id'][:44]:46s} -> {rec['verdict']:12s} "
              f"{'; '.join(rec.get('why') or [])[:56]}")

    def tally(truth: str) -> Counter:
        return Counter(r["verdict"] for r in out if r["truth"] == truth)

    fp, tp = tally("safe"), tally("vuln")
    print(f"\nfalse positives: {sum(fp.values())} -> "
          f"{fp['accepted']} still accepted, {fp['refused']} now refused")
    print(f"true positives:  {sum(tp.values())} -> "
          f"{tp['accepted']} still accepted, {tp['refused']} now refused")
    if args.out:
        args.out.write_text(
            "\n".join(json.dumps(r, ensure_ascii=False) for r in out), encoding="utf-8"
        )
        print(f"\nper-sample verdicts -> {args.out}")
    print("\nA gate is worth having only if the first line moves more than the second.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
