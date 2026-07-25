#!/usr/bin/env python3
"""Does routing throw away findings it should have caught?

Routing cuts 344,008 calls to 42,866. That number is only worth having if the calls it
dropped were the ones that could not have found anything. If instead it silently drops
functions that hold real vulnerabilities, the saving is bought with recall and the whole
cost claim collapses.

The check is a ceiling, not an estimate. For every (repository, tag) pair that ground
truth marks positive, ask a purely structural question: does the routing plan send *any*
function of that repository to *any* detector carrying that tag? If not, no model however
capable can report it -- the finding is unreachable by construction. Reachability is
necessary for detection, never sufficient, so what comes out is an upper bound on recall.

Two ceilings matter and they are different:

  coverage ceiling   a tag with no detector at all is unreachable in any architecture,
                     upstream included. This is upstream's 15-of-42 problem.
  routing ceiling    a tag that has detectors, but whose repository never gets routed to
                     one. This is the cost that routing itself imposes, and the only
                     part we are responsible for.

Reported separately, because conflating them would let us take credit for upstream's
coverage gap or hide our own routing losses inside it.

Run:  python scripts/routing_recall_ceiling.py
"""

from __future__ import annotations

import json
import sys
from collections import defaultdict
from pathlib import Path

import pandas as pd

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from bastet_cc.evaluate import normalize_tag, parse_tags  # noqa: E402
from bastet_cc.routing import fit, load_detectors, route  # noqa: E402
from bastet_cc.solidity import index_repo  # noqa: E402

ROOT = Path(__file__).resolve().parents[2]
DATA = ROOT / "data"
PKG = Path(__file__).resolve().parents[1]
OUT = PKG / "runs" / "routing_recall"


def detector_dirs() -> list[Path]:
    dirs = [PKG / "detectors"]
    synth = PKG / "detectors_synth"
    if (synth / "index.json").exists():
        dirs.append(synth)
    return dirs


def main() -> int:
    splits = json.loads((DATA / "splits.json").read_text())
    # Measured on the synthesis split: DEV and TEST stay unread until their turn.
    repos = splits["train_syn"]

    df = pd.read_csv(DATA / "train.csv")
    truth: dict[str, set[str]] = defaultdict(set)
    for repo, raw in zip(df["repo_path"], df["tag"]):
        truth[str(repo).strip()].update(normalize_tag(t) for t in parse_tags(raw))

    detectors = []
    for d in detector_dirs():
        detectors.extend(load_detectors(d))
    by_tag: dict[str, list] = defaultdict(list)
    for det in detectors:
        for t in det.tags:
            by_tag[normalize_tag(t)].append(det.id)
    print(f"{len(detectors)} detectors from {len(detector_dirs())} director(y/ies), "
          f"covering {len(by_tag)} tags")

    indexes, kept = [], []
    for repo in repos:
        p = DATA / "ex" / "train" / repo
        if not p.is_dir():
            continue
        indexes.append(index_repo(p))
        kept.append(repo)
    print(f"indexed {len(kept)}/{len(repos)} TRAIN-SYN repositories")

    fit(detectors, indexes)

    rows = []
    for repo, ix in zip(kept, indexes):
        tasks = route(detectors, ix)
        # Which tags did this repository's routing plan actually reach?
        reached: set[str] = set()
        for t in tasks:
            for tag in t.detector.tags:
                reached.add(normalize_tag(tag))

        for tag in sorted(truth.get(repo, set())):
            has_detector = tag in by_tag
            rows.append({
                "repo": repo,
                "tag": tag,
                "has_detector": has_detector,
                "routed": tag in reached,
                "n_detectors_for_tag": len(by_tag.get(tag, [])),
                "n_functions": ix["n_functions"],
            })

    out = pd.DataFrame(rows)
    OUT.mkdir(parents=True, exist_ok=True)
    out.to_csv(OUT / "routing_recall_ceiling.csv", index=False)

    total = len(out)
    no_det = int((~out["has_detector"]).sum())
    have_det = out[out["has_detector"]]
    not_routed = int((~have_det["routed"]).sum())
    reachable = int(have_det["routed"].sum())

    print()
    print(f"{'(repository, tag) positives in TRAIN-SYN':<44}{total:>6}")
    print(f"{'  unreachable: no detector for the tag':<44}{no_det:>6}"
          f"   {100 * no_det / total:5.1f}%")
    print(f"{'  unreachable: detector exists, not routed':<44}{not_routed:>6}"
          f"   {100 * not_routed / total:5.1f}%")
    print(f"{'  reachable':<44}{reachable:>6}"
          f"   {100 * reachable / total:5.1f}%")
    print()
    print(f"coverage ceiling on recall (any architecture) : "
          f"{100 * (total - no_det) / total:5.1f}%")
    if len(have_det):
        print(f"routing ceiling, given a detector exists      : "
              f"{100 * reachable / len(have_det):5.1f}%")
        print(f"  -> routing itself costs "
              f"{100 * not_routed / len(have_det):.1f}% of otherwise-reachable positives")

    per_tag = (
        have_det.groupby("tag")
        .agg(n=("routed", "size"), routed=("routed", "sum"))
        .assign(rate=lambda d: d["routed"] / d["n"])
        .sort_values(["rate", "n"])
    )
    lossy = per_tag[per_tag["rate"] < 1.0]
    if len(lossy):
        print(f"\ntags losing positives to routing ({len(lossy)}):")
        print(f"{'tag':<24}{'positives':>10}{'routed':>8}{'rate':>8}")
        for tag, r in lossy.iterrows():
            print(f"{tag:<24}{int(r.n):>10}{int(r.routed):>8}{r.rate:>8.2f}")
    else:
        print("\nno tag loses a single positive to routing")

    (OUT / "summary.json").write_text(json.dumps({
        "split": "train_syn",
        "n_repos_indexed": len(kept),
        "n_detectors": len(detectors),
        "n_tags_with_detector": len(by_tag),
        "positives": total,
        "unreachable_no_detector": no_det,
        "unreachable_not_routed": not_routed,
        "reachable": reachable,
        "coverage_ceiling": (total - no_det) / total,
        "routing_ceiling_given_detector": (
            reachable / len(have_det) if len(have_det) else None
        ),
    }, indent=2))
    print(f"\nWrote {OUT / 'routing_recall_ceiling.csv'}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
