#!/usr/bin/env python3
"""Which vulnerability classes each arm actually discriminates.

An overall F1 hides the thing a reader most wants to know: not how often the tool is
right, but on what. The paired benchmark is one pair per class by construction, so a
per-class table is exactly as long as the class list and every row is a whole story --
caught, missed, or caught on both halves.

The last column is the one that costs something. `caught` for the baseline arm means
nothing at all, because a detector that answers yes to every input catches every class
and discriminates none: the measured Bastet arm scored TP 20 / TN 0 / FP 20 / FN 0 on
40 samples, which is the constant-yes floor to the decimal. So the table also prints,
per class, whether the PATCHED half was flagged -- and that column is where an
always-yes arm becomes visible.

    python3 scripts/class_table.py --evalset evalsets/v4_test.json \\
        --arm broad=runs/casc2-broad.results.jsonl \\
        --arm strict=runs/casc2-strict.results.jsonl \\
        [--live /tmp/livesweep.json]
"""

from __future__ import annotations

import argparse
import json
from pathlib import Path


def _preds(path: Path) -> dict[str, str]:
    out: dict[str, str] = {}
    for line in path.read_text(encoding="utf-8").splitlines():
        if line.strip():
            row = json.loads(line)
            out[row["sample_id"]] = row.get("predicted", "")
    return out


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--evalset", type=Path, required=True)
    ap.add_argument("--arm", action="append", default=[],
                    help="name=path/to/results.jsonl, repeatable")
    ap.add_argument("--live", type=Path, default=None,
                    help="live_sweep --json output, adds a chain column")
    args = ap.parse_args()

    items = json.loads(args.evalset.read_text(encoding="utf-8"))["items"]
    arms = [(a.split("=", 1)[0], _preds(Path(a.split("=", 1)[1]))) for a in args.arm]

    live: set[str] = set()
    if args.live and args.live.is_file():
        live = {
            r["sample_id"].split("__")[0]
            for r in json.loads(args.live.read_text(encoding="utf-8"))
            if r.get("proven")
        }

    # Each class has exactly one vulnerable sample and one patched twin.
    vulns = [i for i in items if i["label"] == "vuln"]
    twin = {i["pair"]: i for i in items if i["label"] == "safe"}

    cols = [n for n, _ in arms] + (["live"] if args.live else [])
    head = "".join(f"{c:>9}" for c in cols) + "".join(f"{c + '/S':>11}" for c, _ in arms)
    print(f"{'vulnerability class':<52}{head}")
    print("-" * (52 + len(head)))

    tally = {c: 0 for c in cols}
    both = {n: 0 for n, _ in arms}
    for item in sorted(vulns, key=lambda x: (x.get("true_tag") or "")):
        row = ""
        for name, preds in arms:
            got = preds.get(item["id"]) == "vuln"
            tally[name] += got
            row += f"{('yes' if got else '--'):>9}"
        if args.live:
            got = item["id"] in live
            tally["live"] += got
            row += f"{('yes' if got else '--'):>9}"
        # The patched twin. A "yes" here cancels the yes on its left: the same attack
        # worked against the fix, so whatever it demonstrated was not the defect.
        for name, preds in arms:
            t = twin.get(item["pair"])
            flagged = bool(t and preds.get(t["id"]) == "vuln")
            both[name] += flagged
            row += f"{('BOTH' if flagged else '.'):>11}"
        print(f"{(item.get('true_tag') or '?')[:52]:<52}{row}")

    print("-" * (52 + len(head)))
    print(f"{'caught, of ' + str(len(vulns)) + ' classes':<52}"
          + "".join(f"{tally[c]:>9}" for c in cols)
          + "".join(f"{both[n]:>11}" for n, _ in arms))
    print()
    for name, _ in arms:
        clean = tally[name] - both[name]
        print(f"  {name}: {tally[name]} classes caught, {both[name]} of them also "
              f"flagged on the patched half -> {clean} discriminated")
    print("\n  a constant-yes detector scores 35 caught and 35 BOTH: it discriminates "
          "nothing.\n  the measured Bastet arm scored TP 20 / TN 0 / FP 20 / FN 0 on 40 "
          "samples, which is\n  that floor exactly (mcc 0.000).")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
