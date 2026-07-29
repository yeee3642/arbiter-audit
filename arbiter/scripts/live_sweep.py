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

from arbiter.live_replay import Untranslatable, parse_poc, replay  # noqa: E402

ETHER = 10**18


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
    print(f"{'sample':<52} {'clean':>9} {'attacked':>9} {'gain':>9}  verdict")
    print("-" * 100)

    for proj in projects:
        sample = proj.name
        target = proj / "src" / "Target.sol"
        pocs = list((proj / "test").glob("*.t.sol"))
        if not target.is_file() or not pocs:
            results.append({"sample_id": sample, "error": "incomplete dump"})
            print(f"{sample[:52]:<52} {'':>9} {'':>9} {'':>9}  incomplete dump")
            continue

        with tempfile.TemporaryDirectory() as tmp:
            try:
                rep = parse_poc(pocs[0], target, sample)
                rec = replay(rep, Path(tmp), port)
            except Untranslatable as exc:
                rec = {"sample_id": sample, "error": f"untranslatable: {exc}"}
            except Exception as exc:  # noqa: BLE001
                rec = {"sample_id": sample, "error": f"{type(exc).__name__}: {exc}"}
        port += 2
        results.append(rec)

        if "error" in rec:
            print(f"{sample[:52]:<52} {'':>9} {'':>9} {'':>9}  {rec['error'][:34]}")
        else:
            print(
                f"{sample[:52]:<52} "
                f"{rec['recovered_clean'] / ETHER:>9.3f} "
                f"{rec['recovered_attacked'] / ETHER:>9.3f} "
                f"{rec['attacker_gain'] / ETHER:>9.3f}  "
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
