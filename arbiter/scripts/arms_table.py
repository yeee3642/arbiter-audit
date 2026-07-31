#!/usr/bin/env python3
"""Every arm on the same twenty pairs, scored the same way.

Until now the arms have been compared on whatever each of them happened to be run on,
and one claim -- classes discriminated, eight against zero -- crossed evaluation sets
entirely. That is the kind of thing a reviewer finds first. This puts all of them on
`v3_authored`: the same forty contracts, the same twenty pairs, the same scorer.

Two numbers per arm, and the second is the one the paired design exists for.

`discriminated` counts PAIRS, not contracts: the arm must flag the vulnerable half AND
stay quiet on its one-to-four-line fix. It is immune to the failure that makes accuracy
meaningless here -- an arm that answers "vulnerable" to everything scores 1.000 recall
and discriminates nothing, and only this column says so.

`executable` counts findings that arrive with a re-runnable execution record. The two
baselines reach zero from completely different architectures, an LLM detector ensemble
and a static analyser, which is what makes it a property of the output format rather
than of one weak tool.

    scripts/arms_table.py
"""

from __future__ import annotations

import json
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from arbiter.score import Confusion  # noqa: E402

RUNS = Path("runs")
IMPACTS = ["High", "Medium", "Low", "Informational", "Optimization"]
CONFIDENCES = ["High", "Medium", "Low"]


def pairs_of(flagged: dict[str, bool]) -> tuple[int, int, int]:
    """(discriminated, both-flagged, neither) over the V_/S_ twins present."""
    disc = both = neither = 0
    for sid, hit in flagged.items():
        if not sid.startswith("V_"):
            continue
        twin = "S_" + sid[2:]
        if twin not in flagged:
            continue
        s_hit = flagged[twin]
        if hit and not s_hit:
            disc += 1
        elif hit and s_hit:
            both += 1
        elif not hit and not s_hit:
            neither += 1
    return disc, both, neither


def from_confusion(flagged: dict[str, bool]) -> Confusion:
    tp = tn = fp = fn = 0
    for sid, hit in flagged.items():
        vuln = sid.startswith("V_")
        if vuln and hit:
            tp += 1
        elif vuln:
            fn += 1
        elif hit:
            fp += 1
        else:
            tn += 1
    return Confusion(tp=tp, tn=tn, fp=fp, fn=fn)


def slither_arm() -> tuple[str, dict[str, bool], int, int]:
    d = json.loads((RUNS / "slither.json").read_text(encoding="utf-8"))
    mi = IMPACTS.index(d["best"]["impact"])
    mc = CONFIDENCES.index(d["best"]["confidence"])
    flagged = {
        r["id"]: any(IMPACTS.index(f["impact"]) <= mi
                     and CONFIDENCES.index(f["confidence"]) <= mc
                     for f in r["findings"])
        for r in d["rows"]
    }
    return (f"Slither (tuned {d['best']['impact']}/{d['best']['confidence']})",
            flagged, d["findings_total"], 0)


def bastet_arm() -> tuple[str, dict[str, bool], int, int] | None:
    p = RUNS / "h2h-bastet.jobs.jsonl"
    if not p.is_file():
        return None
    # One row per (sample, detector), and the arm's verdict is the OR across detectors --
    # which is how the tool itself merges them. `n_findings` is the count that detector
    # returned for that contract.
    flagged: dict[str, bool] = {}
    total = 0
    for line in p.read_text(encoding="utf-8").splitlines():
        if not line.strip():
            continue
        r = json.loads(line)
        sid = r.get("sample", "")
        if not sid:
            continue
        n = r.get("n_findings") or 0
        total += n
        flagged[sid] = flagged.get(sid, False) or bool(n)
    return ("Bastet (as shipped, OR)", flagged, total, 0)


def arbiter_arm(run: str) -> tuple[str, dict[str, bool], int, int] | None:
    p = RUNS / f"{run}.results.jsonl"
    if not p.is_file():
        return None
    flagged: dict[str, bool] = {}
    proven = 0
    for line in p.read_text(encoding="utf-8").splitlines():
        if not line.strip():
            continue
        r = json.loads(line)
        hit = r.get("predicted") == "vuln"
        flagged[r["sample_id"]] = hit
        if hit:
            proven += 1
    return (f"ARBITER ({run})", flagged, proven, proven)


def main() -> int:
    arms = [a for a in (bastet_arm(), slither_arm(),
                        arbiter_arm("refixed2"), arbiter_arm("refixed1"))
            if a and a[1]]
    if not arms:
        print("no arm data under runs/")
        return 2

    print("v3_authored -- 40 contracts, 20 pairs, one scorer\n")
    print(f"{'arm':<34}{'TP':>4}{'TN':>4}{'FP':>4}{'FN':>4}"
          f"{'prec':>8}{'rec':>8}{'spec':>8}{'f1':>8}{'mcc':>8}"
          f"{'pairs':>8}{'exec':>14}")
    print("-" * 118)
    for label, flagged, total, execu in arms:
        c = from_confusion(flagged)
        disc, both, neither = pairs_of(flagged)
        n_pairs = disc + both + neither
        ex = f"{execu} / {total}" if total else "0 / 0"
        print(f"{label:<34}{c.tp:>4}{c.tn:>4}{c.fp:>4}{c.fn:>4}"
              f"{c.precision:>8.3f}{c.recall:>8.3f}{c.specificity:>8.3f}"
              f"{c.f1:>8.3f}{c.mcc:>8.3f}{f'{disc}/{n_pairs}':>8}{ex:>14}")

    print("\npairs  = the arm flagged the vulnerable half AND stayed quiet on its fix")
    print("exec   = findings arriving with a re-runnable execution record")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
