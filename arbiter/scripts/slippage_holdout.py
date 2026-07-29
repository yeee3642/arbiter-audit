#!/usr/bin/env python3
"""Does the slippage reader generalise, or was it fitted to the twenty rows it beat?

The in-sample result -- f1 0.818 against the baseline's 0.643 on the exact rows the
baseline was scored on -- was obtained while looking at those rows. That is the weakest
possible evidential position and it has to be tested rather than defended.

So this replays the baseline's OWN sampling procedure many times over the whole dataset:
draw ten curated findings carrying the tag and ten that do not, label each row `tag in
row["tag"]` exactly as its evaluator does, predict at repository level, and score. Rows
the baseline was actually scored on can be excluded entirely, which makes the measurement
strictly out-of-sample.

Also reports the constant-yes predictor on every draw, because that is the behaviour the
baseline's decision rule collapses to, and it is the number worth beating.

Pure CPU. No gateway requests.
"""

from __future__ import annotations

import argparse
import csv
import json
import os
import random
import statistics
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))
from arbiter.citation import repo_declarations, scan_slippage  # noqa: E402
from arbiter.repo import SKIP_DIRS  # noqa: E402
from arbiter.triage import triage_all  # noqa: E402

DATASET = Path(os.path.expanduser("~/Bastet/dataset"))
SCORED = Path(os.path.expanduser("~/Bastet/evaluation_results.csv"))
CACHE = Path("/tmp/slippage_sites.json")


def contracts_in(repo: Path) -> list[Path]:
    out: list[Path] = []
    for dirpath, dirnames, filenames in os.walk(repo):
        dirnames[:] = [d for d in dirnames if d not in SKIP_DIRS]
        for name in filenames:
            if name.endswith(".sol"):
                out.append(Path(dirpath) / name)
    return sorted(out)


def repo_kinds(repo_path: str) -> dict[str, int]:
    """How many sites of each kind the harness reads in this repository."""
    repo = DATASET / repo_path
    every = contracts_in(repo)
    texts: list[str] = []
    for path in every:
        try:
            texts.append(path.read_text(encoding="utf-8", errors="ignore"))
        except OSError:
            texts.append("")
    decls = repo_declarations(texts)
    keep, _ = triage_all(every)
    wanted = {t.path for t in keep}
    counts: dict[str, int] = {}
    for path, source in zip(every, texts):
        if path not in wanted:
            continue
        for site in scan_slippage(source, decls):
            counts[site.kind] = counts.get(site.kind, 0) + 1
    return counts


def metrics(tp: int, tn: int, fp: int, fn: int) -> dict[str, float]:
    n = tp + tn + fp + fn
    prec = tp / (tp + fp) if (tp + fp) else 0.0
    rec = tp / (tp + fn) if (tp + fn) else 0.0
    # MCC is reported alongside f1 because f1 is degenerate on a 50/50 split: a predictor
    # that answers "vulnerable" to everything scores 0.667 while carrying no information
    # at all, and that is exactly what the baseline's 53-way OR collapses to. MCC is 0.000
    # for it, and for any other constant answer.
    denom = ((tp + fp) * (tp + fn) * (tn + fp) * (tn + fn)) ** 0.5
    return {
        "accuracy": (tp + tn) / n if n else 0.0,
        "precision": prec,
        "recall": rec,
        "f1": 2 * prec * rec / (prec + rec) if (prec + rec) else 0.0,
        "mcc": ((tp * tn - fp * fn) / denom) if denom else 0.0,
    }


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--tag", default="Slippage")
    ap.add_argument("--draws", type=int, default=200)
    ap.add_argument("--size", type=int, default=10, help="per class, as the baseline uses")
    ap.add_argument("--kinds",
                    default="min_out_zero,min_out_missing,deadline_now,min_out_missing_param")
    ap.add_argument("--include-scored", action="store_true",
                    help="do NOT hold out the rows the baseline was scored on")
    ap.add_argument("--half", choices=("tune", "test", "all"), default="all",
                    help="split the repository pool deterministically. Tuning on the "
                         "held-out pool would consume it, so thresholds are chosen on "
                         "'tune' and the number that gets reported comes from 'test'.")
    args = ap.parse_args()
    kinds = {k.strip() for k in args.kinds.split(",") if k.strip()}

    rows = [
        r for r in csv.DictReader(open(DATASET / "dataset.csv", encoding="utf-8-sig"))
        if (r.get("status") or "").strip() == "Done"
    ]
    held_out: set[str] = set()
    if not args.include_scored:
        with open(SCORED, encoding="utf-8-sig") as fh:
            held_out = {(r.get("file_name") or "").strip() for r in csv.DictReader(fh)}
        rows = [r for r in rows if r["repo_path"] not in held_out]
        print(f"holding out {len(held_out)} repositories the baseline was scored on")

    if args.half != "all":
        # Deterministic and content-free: the hash of the repository name, so the split
        # cannot drift as the dataset is re-read and does not depend on anything measured.
        import hashlib

        def side(repo: str) -> str:
            digest = hashlib.sha256(repo.encode("utf-8")).hexdigest()
            return "tune" if int(digest[:8], 16) % 2 == 0 else "test"

        rows = [r for r in rows if side(r["repo_path"]) == args.half]
        print(f"repository pool restricted to the {args.half!r} half")

    tagged = [r for r in rows if args.tag in str(r.get("tag") or "")]
    untagged = [r for r in rows if args.tag not in str(r.get("tag") or "")]
    print(f"pool: {len(tagged)} findings tagged {args.tag!r}, {len(untagged)} without, "
          f"over {len({r['repo_path'] for r in rows})} repositories")
    if len(tagged) < args.size:
        print("not enough tagged findings left after holding out; nothing to measure")
        return 1

    cache: dict[str, dict[str, int]] = {}
    if CACHE.exists():
        cache = json.loads(CACHE.read_text(encoding="utf-8"))

    needed = sorted({r["repo_path"] for r in tagged + untagged})
    for i, repo in enumerate(needed, 1):
        if repo in cache:
            continue
        if not (DATASET / repo).is_dir():
            cache[repo] = {}
            continue
        cache[repo] = repo_kinds(repo)
        if i % 20 == 0:
            print(f"  scanned {i}/{len(needed)} repositories", flush=True)
            CACHE.write_text(json.dumps(cache), encoding="utf-8")
    CACHE.write_text(json.dumps(cache), encoding="utf-8")

    def fires(repo: str) -> bool:
        return any(n > 0 for k, n in (cache.get(repo) or {}).items() if k in kinds)

    keys = ("accuracy", "precision", "recall", "f1", "mcc")
    ours: dict[str, list[float]] = {k: [] for k in keys}
    yes: dict[str, list[float]] = {k: [] for k in ours}
    rng = random.Random(20260728)

    for _ in range(args.draws):
        picked = rng.sample(tagged, args.size) + rng.sample(untagged, args.size)
        tp = tn = fp = fn = 0
        ytp = ytn = yfp = yfn = 0
        for row in picked:
            label = args.tag in str(row.get("tag") or "")
            pred = fires(row["repo_path"])
            tp += label and pred
            tn += (not label) and (not pred)
            fp += (not label) and pred
            fn += label and (not pred)
            # The rule the baseline's arithmetic collapses to: always positive.
            ytp += label
            yfp += not label
        for key, value in metrics(tp, tn, fp, fn).items():
            ours[key].append(value)
        for key, value in metrics(ytp, ytn, yfp, yfn).items():
            yes[key].append(value)

    def band(values: list[float]) -> str:
        values = sorted(values)
        lo = values[int(0.025 * len(values))]
        hi = values[min(len(values) - 1, int(0.975 * len(values)))]
        return f"{statistics.mean(values):.3f}  [{lo:.3f}, {hi:.3f}]"

    print(f"\n{args.draws} draws of {args.size}+{args.size}, "
          f"{'held out' if not args.include_scored else 'INCLUDING scored rows'}\n")
    print(f"{'metric':<11} {'harness reading':<24} {'constant-yes (the baseline rule)'}")
    for key in keys:
        print(f"{key:<11} {band(ours[key]):<24} {band(yes[key])}")

    wins = sum(1 for a, b in zip(ours["f1"], yes["f1"]) if a > b)
    print(f"\nf1 higher than constant-yes in {wins}/{args.draws} draws")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
