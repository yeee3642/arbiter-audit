"""Turn Bastet's discarded detector hits into a hypothesis queue.

The instrument audit showed Bastet's *verdict* is worthless: a 53-way OR that fires on
every sample, specificity 0.000, MCC exactly 0.000. But the verdict is an aggregation,
and the aggregation is what destroys the signal. The individual hits underneath it are a
different object, and measurement says they carry information the verdict does not: of
the 11 vulnerable samples ARBITER failed to prove, 8 had a detector fire whose name
matches the real defect -- `avoidTx-origin` on the tx.origin sample, `Unbounded-loop` on
the denial-of-service one, `ERC4626-Rounding` on the rounding one, `FoTTokens` on
fee-on-transfer. Every one of those is a hypothesis the agent never formed.

So the two systems fail in complementary ways. Bastet proposes everything and decides
nothing; ARBITER decides well and proposes badly. This module is the join: Bastet's hits
become the hypothesis queue, and the execution gate still refuses anything that cannot be
proven, so a wrong proposal costs turns rather than precision.

Ranking is by corpus-wide rarity, computed from the detector rows alone and never from
labels. A detector that fires on nearly every sample carries almost no information about
any particular one; a detector that fires rarely and fires *here* is worth trying first.
That ordering is unsupervised, so it introduces no leakage from the evaluation labels.
"""

from __future__ import annotations

import json
import re
from collections import defaultdict
from pathlib import Path


def load_hits(jobs_path: Path) -> dict[str, list[str]]:
    """sample id -> detector names that returned a non-empty finding list."""
    fired: dict[str, list[str]] = defaultdict(list)
    for line in jobs_path.read_text(encoding="utf-8").splitlines():
        if not line.strip():
            continue
        try:
            row = json.loads(line)
        except json.JSONDecodeError:
            continue
        if row.get("n_findings"):
            fired[row["sample"]].append(row["detector"])
    return {k: sorted(set(v)) for k, v in fired.items()}


def rarity(jobs_path: Path) -> dict[str, float]:
    """detector -> share of samples it fires on. Lower is more informative."""
    fired_on: dict[str, set[str]] = defaultdict(set)
    samples: set[str] = set()
    for line in jobs_path.read_text(encoding="utf-8").splitlines():
        if not line.strip():
            continue
        try:
            row = json.loads(line)
        except json.JSONDecodeError:
            continue
        samples.add(row["sample"])
        if row.get("n_findings"):
            fired_on[row["detector"]].add(row["sample"])
    n = len(samples) or 1
    return {d: len(s) / n for d, s in fired_on.items()}


def humanise(detector: str) -> str:
    """Make an n8n node name readable as a hypothesis.

    Names arrive as `SC10-2025-Denial-Of-Service`, `4naly3er-M-avoidTx-origin`,
    `Chainlink-Not-Checking-For-Stale-Price`. Stripping the taxonomy prefixes and the
    separators leaves the part that actually names a vulnerability class.
    """
    text = detector
    text = re.sub(r"^(SC\d+[-:]?\d*|4naly3er)[-_ ]*", "", text)
    text = re.sub(r"^[MHL][-_ ]", "", text)
    text = re.sub(r"[-_]+", " ", text).strip()
    return text or detector


def proposal_block(
    hits: list[str], rare: dict[str, float], limit: int = 14
) -> str:
    """Render the hypothesis queue that goes into the agent's task prompt."""
    if not hits:
        return ""
    ordered = sorted(hits, key=lambda d: (rare.get(d, 1.0), d))[:limit]
    lines = "\n".join(
        f"  - {humanise(d)}  (this detector fires on "
        f"{rare.get(d, 1.0):.0%} of contracts)"
        for d in ordered
    )
    dropped = len(hits) - len(ordered)
    tail = f"\n  ... and {dropped} more, omitted as too common to be informative." if dropped > 0 else ""
    return (
        "\n\nA cheap pattern-matching scanner was run over this contract first. It is "
        "NOT reliable: it flags almost every contract it sees, its true-negative rate is "
        "zero, and its overall verdict carries no information at all. Do not treat any "
        "of this as evidence.\n\n"
        "What it is good for is naming classes you might not otherwise consider. These "
        "are the classes it flagged here, rarest first -- a detector that fires on most "
        "contracts is telling you almost nothing, one that fires rarely and fired here "
        "is worth a look:\n\n"
        f"{lines}{tail}\n\n"
        "Treat these as a queue of hypotheses to test and discard, not as findings. Most "
        "will be wrong. Work through the plausible ones with run_exploit; the harness "
        "will refuse anything you cannot actually demonstrate, so a wrong suggestion "
        "costs you turns and nothing else. If none of them survives contact with the "
        "code, say so with conclude_safe -- following a bad suggestion into a finding "
        "you cannot prove is the one outcome worse than missing the bug."
    )
