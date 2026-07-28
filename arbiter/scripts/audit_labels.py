#!/usr/bin/env python3
"""Is the ground truth every other number rests on actually right?

An adversarial review pointed at one pair the tool gets exactly backwards -- patched half
called vulnerable, vulnerable half called safe -- and inferred label noise. That is an
inference, not a measurement, and this project is supposed to know the difference. The
labels came from an admission rule that machine-verified each pair, so the rule can simply
be re-run under the harness as it stands now.

For every pair, the reference exploit must PASS on the vulnerable half and FAIL on the
patched one. A pair that does not satisfy both is not evidence of anything, whichever way
it fails:

  * passes on both  -- the "fix" does not fix it, so the patched half is mislabelled
  * fails on both   -- the reference exploit is broken, so the vulnerable half is
                       unsupported and any tool scored on it is being graded against a
                       claim nobody has demonstrated

Pure CPU. No gateway requests.
"""

from __future__ import annotations

import argparse
import json
import os
import sys
from concurrent.futures import ProcessPoolExecutor, as_completed
from pathlib import Path

sys.path.insert(0, os.path.expanduser("~/rig/arbiter"))

from arbiter.workspace import Workspace  # noqa: E402

RIG = Path(os.path.expanduser("~/rig/arbiter"))
WS = Path("/tmp/label-audit")


def run_half(pair: dict, half: str) -> tuple[bool, str]:
    """Compose and run the pair's own reference exploit against one half."""
    source = pair["vulnerable_code"] if half == "V" else pair["patched_code"]
    ws = Workspace(WS, f"{pair['slug'][:50]}_{half}", source)
    try:
        try:
            solidity = ws.compose_exploit(
                deploy_code=pair.get("deploy_code", ""),
                attacker_code=pair.get("attacker_code", ""),
                predicate=pair.get("predicate", "eth_profit"),
                observed_getter=pair.get("observed_getter", "") or "",
                token_expr=pair.get("token_expr", "") or "",
                liveness_call=pair.get("liveness_call", "") or "",
                honest_body=pair.get("honest_body", "") or "",
                # Admission is the one place a baseline is not owed: the PAIR is the
                # discriminator, which is a stronger test than beating a baseline.
                require_honest=False,
            )
        except ValueError as exc:
            return False, f"composition refused: {str(exc).splitlines()[0][:60]}"
        ws.write_poc("Ref", solidity)
        if not ws.build().ok:
            first = next((l.strip()[:60] for l in ws.build().combined.splitlines()
                          if "Error (" in l), "compile failed")
            return False, first
        out = ws.run_poc("RefPoc").combined
        passed = any(l.strip().startswith("[PASS]") for l in out.splitlines())
        why = next((l.strip()[:60] for l in out.splitlines()
                    if "Arbiter" in l or "ARBITER" in l), "")
        return passed, why
    finally:
        ws.cleanup()


def audit(pair: dict) -> dict:
    v_pass, v_why = run_half(pair, "V")
    s_pass, s_why = run_half(pair, "S")
    if v_pass and not s_pass:
        verdict = "sound"
    elif v_pass and s_pass:
        verdict = "PATCH DOES NOT FIX IT"
    elif not v_pass and not s_pass:
        verdict = "REFERENCE EXPLOIT BROKEN"
    else:
        verdict = "INVERTED"
    return {
        "slug": pair["slug"], "class": pair.get("vulnerability_class", ""),
        "verdict": verdict, "v_pass": v_pass, "s_pass": s_pass,
        "why": (v_why or s_why)[:60],
    }


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--pairs", type=Path,
                    default=RIG / "evalsets" / "test_pairs_v2.json")
    ap.add_argument("--workers", type=int, default=max(2, (os.cpu_count() or 4) - 4))
    args = ap.parse_args()

    raw = json.loads(args.pairs.read_text(encoding="utf-8"))
    pairs = raw["pairs"] if isinstance(raw, dict) else raw
    print(f"auditing the ground truth of {len(pairs)} pairs\n", flush=True)

    out: list[dict] = []
    with ProcessPoolExecutor(max_workers=args.workers) as pool:
        for fut in as_completed([pool.submit(audit, p) for p in pairs]):
            out.append(fut.result())

    for rec in sorted(out, key=lambda r: (r["verdict"] != "sound", r["slug"])):
        mark = "  " if rec["verdict"] == "sound" else "**"
        print(f"{mark}{rec['slug'][:44]:46s} V={'pass' if rec['v_pass'] else 'fail'} "
              f"S={'pass' if rec['s_pass'] else 'fail'}  {rec['verdict']:26s} "
              f"{rec['why']}")

    sound = sum(1 for r in out if r["verdict"] == "sound")
    print(f"\n{sound}/{len(out)} pairs still discriminate under the current harness")
    for verdict in ("INVERTED", "PATCH DOES NOT FIX IT", "REFERENCE EXPLOIT BROKEN"):
        n = sum(1 for r in out if r["verdict"] == verdict)
        if n:
            print(f"  {n:3d}  {verdict}")
    print("\nEvery sample scored in this project's headline tables comes from these")
    print("pairs. A pair that no longer discriminates is grading tools against a claim")
    print("nobody has demonstrated, and raising n buys more of that rather than less.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
