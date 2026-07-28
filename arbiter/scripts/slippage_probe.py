#!/usr/bin/env python3
"""Does the slippage reader agree with the humans who labelled these repositories?

The second evidence tier is only worth having if the harness's own reading of a call is
right often enough to be trusted in place of an execution. So it is measured against the
dataset's labels before it is used to decide anything: how many of the repositories with a
curated Slippage finding does it fire on, and how many of the ones without.

Pure CPU. No gateway requests.
"""

from __future__ import annotations

import argparse
import collections
import csv
import os
import sys
from pathlib import Path

sys.path.insert(0, os.path.expanduser("~/rig/arbiter"))

from arbiter.citation import repo_declarations, scan_slippage  # noqa: E402
from arbiter.repo import SKIP_DIRS  # noqa: E402
from arbiter.triage import triage_all  # noqa: E402

DATASET = Path(os.path.expanduser("~/Bastet/dataset"))
SCORED = Path(os.path.expanduser("~/Bastet/evaluation_results.csv"))


def contracts_in(repo: Path) -> list[Path]:
    out: list[Path] = []
    for dirpath, dirnames, filenames in os.walk(repo):
        dirnames[:] = [d for d in dirnames if d not in SKIP_DIRS]
        for name in filenames:
            if name.endswith(".sol"):
                out.append(Path(dirpath) / name)
    return sorted(out)


def repo_sites(repo: Path, triaged: bool) -> list[tuple[Path, object]]:
    every = contracts_in(repo)
    texts: list[str] = []
    for path in every:
        try:
            texts.append(path.read_text(encoding="utf-8", errors="ignore"))
        except OSError:
            texts.append("")
    # Argument positions are learned from the whole repository's signatures: the router
    # interface a contract calls is declared in another file, and without it only the
    # hard-coded table can fire -- which measured 0.1 recall.
    decls = repo_declarations(texts)

    files = every
    if triaged:
        keep, _ = triage_all(every)
        files = [t.path for t in keep]
    wanted = set(files)

    found: list[tuple[Path, object]] = []
    for path, source in zip(every, texts):
        if path not in wanted:
            continue
        for site in scan_slippage(source, decls):
            found.append((path, site))
    return found


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--kinds", default="min_out_zero,min_out_missing,deadline_now")
    ap.add_argument("--all-files", action="store_true")
    args = ap.parse_args()
    kinds = {k.strip() for k in args.kinds.split(",") if k.strip()}

    truth: dict[str, bool] = {}
    order: list[tuple[str, bool]] = []
    with open(SCORED, encoding="utf-8-sig") as fh:
        for row in csv.DictReader(fh):
            name = (row.get("file_name") or "").strip()
            label = (row.get("true_label") or "").strip().lower() in ("true", "1", "yes")
            order.append((name, label))
            truth.setdefault(name, label)

    print(f"kinds counted: {sorted(kinds)}")
    print(f"{'repository':<32} {'label':<6} {'sites':>6}  kinds")
    tp = tn = fp = fn = 0
    cache: dict[str, list] = {}
    for name, label in order:
        if name not in cache:
            cache[name] = repo_sites(DATASET / name, not args.all_files)
        sites = [s for _, s in cache[name] if s.kind in kinds]
        fired = bool(sites)
        counts = collections.Counter(s.kind for s in sites)
        mark = " " if fired == label else "*"
        print(f"{mark}{Path(name).name[:31]:<31} {str(label):<6} {len(sites):>6}  "
              f"{dict(counts)}")
        if label and fired:
            tp += 1
        elif not label and not fired:
            tn += 1
        elif not label and fired:
            fp += 1
        else:
            fn += 1

    n = tp + tn + fp + fn
    prec = tp / (tp + fp) if (tp + fp) else 0.0
    rec = tp / (tp + fn) if (tp + fn) else 0.0
    f1 = 2 * prec * rec / (prec + rec) if (prec + rec) else 0.0
    print(f"\nTP={tp} TN={tn} FP={fp} FN={fn}")
    print(f"accuracy: {(tp + tn) / n if n else 0}")
    print(f"precision: {prec}")
    print(f"recall: {rec}")
    print(f"f1: {f1}")
    print("\nbaseline on these same rows: TP=9 TN=1 FP=9 FN=1 "
          "accuracy 0.5 precision 0.5 recall 0.9 f1 0.6428571428571429")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
