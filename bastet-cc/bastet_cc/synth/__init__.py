"""Detector synthesis (DESIGN §2.3): S1 localize -> S2 induce -> S3 hints -> S4 gate.

Isolation contract: every finding row that enters this package comes from the
TRAIN-SYN split. `train_syn_frames` is the only place ground truth is read, and it
filters on splits.json before anything else sees a row -- DEV/TEST findings cannot
leak into synthesis by construction. Repo *code* statistics (S3 document
frequencies) intentionally cover all 54 train repos per DESIGN §2.3; labels never do.
"""

from __future__ import annotations

import json
from pathlib import Path

import pandas as pd

SEED = 20260725

# bastet-cc/ and its sibling data/ directory.
PKG_ROOT = Path(__file__).resolve().parents[2]
DATA_DIR = PKG_ROOT.parent / "data"
TRAIN_EX_DIR = DATA_DIR / "ex" / "train"
TAG_DEFINITIONS_MD = PKG_ROOT.parent / "Tag Definitions.md"
DETECTORS_DIR = PKG_ROOT / "detectors"
DETECTORS_SYNTH_DIR = PKG_ROOT / "detectors_synth"


def load_splits(data_dir: Path = DATA_DIR) -> dict:
    return json.loads((data_dir / "splits.json").read_text())


def train_syn_frames(data_dir: Path = DATA_DIR):
    """(raw_df, exploded_df, splits) with rows restricted to the TRAIN-SYN split.

    The assert is a tripwire, not a check that can fail under normal operation:
    if it ever fires, split isolation was broken upstream and the run must die.
    """
    from ..tags import explode_labels

    splits = load_splits(data_dir)
    syn = set(splits["train_syn"])
    df = pd.read_csv(data_dir / "train.csv")
    raw = df[df["repo_path"].isin(syn)].copy()
    assert set(raw["repo_path"]) <= syn and len(set(raw["repo_path"]) & set(splits["dev"])) == 0
    exploded = explode_labels(raw)
    return raw, exploded, splits


def index_train_repos(repos: list[str], ex_dir: Path = TRAIN_EX_DIR) -> dict[str, dict]:
    """tree-sitter index for each repo hash; ~0.1s per repo, so no disk cache."""
    from ..solidity import index_repo

    return {r: index_repo(ex_dir / r) for r in sorted(repos)}


def covered_tags(detectors_dir: Path = DETECTORS_DIR) -> set[str]:
    """Canonical tags any upstream hand-written detector claims to detect."""
    from ..tags import canonical_tag

    index = json.loads((detectors_dir / "index.json").read_text())
    return {canonical_tag(t) for d in index for t in d["tags"]}


def missing_tags(splits: dict, detectors_dir: Path = DETECTORS_DIR) -> list[str]:
    """In-taxonomy corpus tags with no detector, ordered by corpus finding count.

    The tag universe comes from splits.json's per_tag_counts (already canonical),
    not from re-reading DEV/TEST rows -- the counts were frozen with the split.
    """
    from ..tags import TAXONOMY

    covered = covered_tags(detectors_dir)
    counts = {
        t: sum(v.values()) for t, v in splits["per_tag_counts"].items()
        if t in TAXONOMY and t not in covered
    }
    return sorted(counts, key=lambda t: (-counts[t], t))
