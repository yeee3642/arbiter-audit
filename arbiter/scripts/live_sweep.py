#!/usr/bin/env python3
"""Replay every dumped exploit on a real chain and report how many survive.

    python3 scripts/live_sweep.py ~/exploits-casc2 [--json out.json] [--port 8700]

Each exploit gets two chains from genesis -- one where the attack happens and one where
it does not -- and the verdict is computed from balances the node reported. Nothing here
is asserted in Solidity and nothing is pranked.

The interesting number is not how many pass. It is which ones stop passing, because an
exploit that needed the harness to impersonate somebody has nowhere to get that here.
"""

from __future__ import annotations

import argparse
import json
import sys
import tempfile
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from arbiter.live_replay import (  # noqa: E402
    Untranslatable,
    parse_poc,
    parse_poc_exploit,
    parse_poc_other,
    replay,
    replay_exploit,
    replay_other,
)

ETHER = 10**18


def _amt(wei: int) -> str:
    """Enough precision not to hide a rounding attack.

    Three decimals of ether was tried and reported a dust drain out of a hundred-ether
    pool as `100.900 -> 100.900`, which reads as nothing happening. An attack that takes
    a millionth of an ether is still an attack, and the display should not be the thing
    that decides otherwise.
    """
    if wei == 0:
        return "0"
    if wei < 10**12:
        return f"{wei}wei"
    return f"{wei / ETHER:.6f}".rstrip("0").rstrip(".")


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("dump", type=Path, help="directory written by `arbiter dump`")
    ap.add_argument("--port", type=int, default=8700)
    ap.add_argument("--json", type=Path, default=None)
    ap.add_argument("--only", default="", help="substring filter on the sample id")
    args = ap.parse_args()

    projects = sorted(p for p in args.dump.iterdir() if (p / "foundry.toml").is_file())
    if args.only:
        projects = [p for p in projects if args.only in p.name]
    if not projects:
        print(f"no dumped exploits under {args.dump}")
        return 2

    results = []
    port = args.port
    print(f"{'sample':<48} {'shortfall':>14} {'gain':>14}  verdict")
    print("-" * 104)

    for proj in projects:
        sample = proj.name
        target = proj / "src" / "Target.sol"
        pocs = list((proj / "test").glob("*.t.sol"))
        if not target.is_file() or not pocs:
            results.append({"sample_id": sample, "error": "incomplete dump"})
            print(f"{sample[:48]:<48} {'':>14} {'':>14}  incomplete dump")
            continue

        with tempfile.TemporaryDirectory() as tmp:
            # Two templates, tried in order. The victim one is composed from
            # arbSetup/arbEnter/arbExit; the other keeps everything inside arbiterRun
            # and measures a getter instead of a victim. Neither is a fallback for the
            # other -- a proof is written against exactly one of them.
            try:
                rep = parse_poc(pocs[0], target, sample)
                rec = replay(rep, Path(tmp), port)
            except Untranslatable:
                try:
                    xrep = parse_poc_exploit(pocs[0], target, sample)
                    rec = replay_exploit(xrep, Path(tmp), port)
                except Untranslatable:
                    try:
                        orep = parse_poc_other(pocs[0], target, sample)
                        rec = replay_other(orep, Path(tmp), port)
                    except Untranslatable as exc3:
                        rec = {"sample_id": sample,
                               "error": f"untranslatable: {exc3}"}
                    except Exception as exc3:  # noqa: BLE001
                        rec = {"sample_id": sample,
                               "error": f"{type(exc3).__name__}: {exc3}"}
                except Exception as exc2:  # noqa: BLE001
                    rec = {"sample_id": sample,
                           "error": f"{type(exc2).__name__}: {exc2}"}
            except Exception as exc:  # noqa: BLE001
                rec = {"sample_id": sample, "error": f"{type(exc).__name__}: {exc}"}
        port += 2
        results.append(rec)

        if "error" in rec:
            print(f"{sample[:48]:<48} {'':>14} {'':>14}  {rec['error'][:38]}")
        elif rec.get("template") == "liveness":
            print(
                f"{sample[:48]:<48} "
                f"{('worked' if rec.get('worked_before') else 'already broken'):>14} "
                f"{('now broken' if not rec.get('worked_after') else 'still works'):>14}  "
                f"{'AVAILABILITY BROKEN ON A CHAIN' if rec['proven'] else 'not proven live'}"
            )
        elif rec.get("template") == "token":
            print(
                f"{sample[:48]:<48} "
                f"{_amt(rec.get('attack_gain', 0)):>14} "
                f"{('drained' if rec.get('drained') else 'no drain'):>14}  "
                f"{'TOKENS TAKEN ON A CHAIN' if rec['proven'] else 'not proven live'}"
            )
        elif rec.get("template") == "exploit":
            print(
                f"{sample[:48]:<48} "
                f"{('privileged' if rec.get('privileged') else 'not privileged'):>14} "
                f"{('state moved' if rec['after_honest'] != rec['after_attack'] else 'unmoved'):>14}  "
                f"{'STATE SEIZED ON A CHAIN' if rec['proven'] else 'not proven live'}"
            )
        else:
            print(
                f"{sample[:48]:<48} "
                f"{_amt(rec['shortfall']):>14} "
                f"{_amt(rec['attacker_gain']):>14}  "
                f"{'DRAINED ON A CHAIN' if rec['proven'] else 'not proven live'}"
            )

    proven = [r for r in results if r.get("proven")]
    errored = [r for r in results if "error" in r]
    print("-" * 100)
    print(f"{len(proven)} of {len(results)} exploits reproduced as signed transactions; "
          f"{len(errored)} could not be translated or run")
    # An exploit that is proven against the patched half is a false positive whichever
    # environment it runs in, so name them rather than fold them into the count.
    bad = [r["sample_id"] for r in proven if r["sample_id"].startswith("S_")]
    if bad:
        print(f"of those, {len(bad)} were the PATCHED half of a pair: {', '.join(bad)}")

    if args.json:
        args.json.write_text(json.dumps(results, indent=1), encoding="utf-8")
        print(f"transcripts: {args.json}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
