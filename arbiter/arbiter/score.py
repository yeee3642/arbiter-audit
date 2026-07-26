"""One scorer, used by every arm.

BENCH_PROTOCOL forbids an arm from carrying its own scoring logic, because that is the
easiest place to win a comparison without improving anything. Both arms emit
``{sample_id: "vuln"|"safe"}`` and this module is the only thing that turns those into
numbers.

It also carries the paired tests. The arms see identical samples, so their errors are
paired and an unpaired comparison would be throwing away most of the available power on
a small evaluation set. McNemar's exact test is computed as an exact binomial sum rather
than with the chi-square approximation, which is not valid at these counts.
"""

from __future__ import annotations

import math
import random
from dataclasses import dataclass
from typing import Any, Iterable, Mapping


@dataclass
class Confusion:
    tp: int = 0
    tn: int = 0
    fp: int = 0
    fn: int = 0

    @property
    def n(self) -> int:
        return self.tp + self.tn + self.fp + self.fn

    @property
    def precision(self) -> float:
        denom = self.tp + self.fp
        return self.tp / denom if denom else 0.0

    @property
    def recall(self) -> float:
        denom = self.tp + self.fn
        return self.tp / denom if denom else 0.0

    @property
    def f1(self) -> float:
        p, r = self.precision, self.recall
        return 2 * p * r / (p + r) if (p + r) else 0.0

    @property
    def accuracy(self) -> float:
        return (self.tp + self.tn) / self.n if self.n else 0.0

    @property
    def specificity(self) -> float:
        """True negative rate. The axis the baseline scores 0.000 on."""
        denom = self.tn + self.fp
        return self.tn / denom if denom else 0.0

    @property
    def mcc(self) -> float:
        """Matthews correlation. Reported because F1 at 50/50 balance flatters a
        constant "yes", which is precisely the baseline's behaviour: MCC of a constant
        predictor is 0 by construction, F1 is 0.667."""
        num = self.tp * self.tn - self.fp * self.fn
        den = math.sqrt(
            (self.tp + self.fp)
            * (self.tp + self.fn)
            * (self.tn + self.fp)
            * (self.tn + self.fn)
        )
        return num / den if den else 0.0

    def as_dict(self) -> dict[str, Any]:
        return {
            "TP": self.tp,
            "TN": self.tn,
            "FP": self.fp,
            "FN": self.fn,
            "precision": round(self.precision, 4),
            "recall": round(self.recall, 4),
            "specificity": round(self.specificity, 4),
            "f1": round(self.f1, 4),
            "accuracy": round(self.accuracy, 4),
            "mcc": round(self.mcc, 4),
        }


def score(
    predictions: Mapping[str, str], truth: Mapping[str, str]
) -> Confusion:
    """Score predictions against ground truth. Both map sample_id -> 'vuln'|'safe'."""
    c = Confusion()
    for sample_id, actual in truth.items():
        predicted = predictions.get(sample_id)
        if predicted is None:
            # An unanswered sample is a missing negative, never silently dropped:
            # dropping it would quietly shrink the denominator in our favour.
            predicted = "safe"
        if actual == "vuln" and predicted == "vuln":
            c.tp += 1
        elif actual == "safe" and predicted == "safe":
            c.tn += 1
        elif actual == "safe" and predicted == "vuln":
            c.fp += 1
        else:
            c.fn += 1
    return c


def constant_yes_baseline(truth: Mapping[str, str]) -> Confusion:
    """The floor a comparison has to clear to mean anything.

    Answering "vulnerable" every time scores F1 0.667 on a balanced set. Any system that
    does not beat this has demonstrated nothing, and the measured Bastet baseline scores
    exactly at it.
    """
    return score({k: "vuln" for k in truth}, truth)


def constant_no_baseline(truth: Mapping[str, str]) -> Confusion:
    """The other degenerate floor, which this suite was missing.

    Answering "safe" every time scores specificity 1.000 and precision 0.000. Its absence
    was an asymmetry in our own fairness machinery: `constant_yes_baseline` existed and
    was used to show that Bastet's F1 is degenerate, while specificity -- the metric this
    project was promoting as decisive -- had no corresponding floor, even though a
    predictor that reads nothing and always answers "safe" beats ARBITER's 0.800 outright.

    Neither degenerate predictor beats the other on MCC: both score 0.000, because
    neither carries information. That is the only comparison that survives both floors,
    and it is the reason MCC rather than specificity belongs in a headline.
    """
    return score({k: "safe" for k in truth}, truth)


def mcnemar_mde(n_discordant: int, alpha: float = 0.05, power: float = 0.80) -> float:
    """Smallest detectable split of the discordant pairs, as a proportion.

    Reported because "not significant" and "underpowered" are different statements and
    the suite previously conflated them. The old `underpowered` flag fired only below
    n=6, which answers "could this design ever reach p<0.05", not "could it detect an
    effect anyone would care about". Returns the proportion p such that a binomial test
    on n_discordant trials distinguishes p from 0.5 at the given alpha and power; at
    n=27 that is about 0.74, meaning roughly three quarters of all disagreements would
    have to fall one way before this design could call it.
    """
    if n_discordant < 1:
        return 1.0
    # Smallest k whose two-sided exact tail is below alpha.
    crit = None
    for k in range(n_discordant // 2, n_discordant + 1):
        tail = sum(math.comb(n_discordant, i) for i in range(k, n_discordant + 1)) * (
            0.5**n_discordant
        )
        if 2 * tail <= alpha:
            crit = k
            break
    if crit is None:
        return 1.0
    # Smallest p at which that critical value is reached with the requested power.
    for step in range(500, 1001):
        p = step / 1000.0
        achieved = sum(
            math.comb(n_discordant, i) * (p**i) * ((1 - p) ** (n_discordant - i))
            for i in range(crit, n_discordant + 1)
        )
        if achieved >= power:
            return round(p, 3)
    return 1.0


# -- paired inference --------------------------------------------------------


def mcnemar_exact(
    a: Mapping[str, str], b: Mapping[str, str], truth: Mapping[str, str]
) -> dict[str, Any]:
    """Exact McNemar on paired correctness.

    b01: samples arm A got right and arm B got wrong.
    b10: samples arm B got right and arm A got wrong.
    Only discordant pairs carry information, which is why the discordant count is
    reported alongside the p-value -- with too few of them the test cannot resolve a
    difference and saying so is more honest than quoting p.
    """
    b01 = b10 = concordant = 0
    discordant_ids: dict[str, str] = {}
    for sample_id, actual in truth.items():
        a_ok = a.get(sample_id, "safe") == actual
        b_ok = b.get(sample_id, "safe") == actual
        if a_ok and not b_ok:
            b01 += 1
            discordant_ids[sample_id] = "a_only"
        elif b_ok and not a_ok:
            b10 += 1
            discordant_ids[sample_id] = "b_only"
        else:
            concordant += 1

    n = b01 + b10
    if n == 0:
        p = 1.0
    else:
        k = min(b01, b10)
        tail = sum(math.comb(n, i) for i in range(k + 1)) * (0.5**n)
        p = min(1.0, 2 * tail)

    return {
        "b01_a_only_correct": b01,
        "b10_b_only_correct": b10,
        "concordant": concordant,
        "discordant": n,
        "p_value_exact": round(p, 6),
        "favours": "b" if b10 > b01 else ("a" if b01 > b10 else "neither"),
        "discordant_samples": discordant_ids,
        "cannot_ever_reach_significance": n < 6,
        "minimum_detectable_split": mcnemar_mde(n),
        "note": (
            "Only discordant pairs carry evidence. `cannot_ever_reach_significance` "
            "fires below 6 discordant pairs, where no two-sided exact test reaches "
            "p<0.05 at any split; it was previously named `underpowered`, which "
            "overstated what it checks. `minimum_detectable_split` is the honest power "
            "statement: the proportion of disagreements that must fall one way before "
            "this design can call the difference at alpha 0.05 and 80% power. A design "
            "that is not flagged here can still be far too small to detect any "
            "realistic effect."
        ),
    }


def bootstrap_delta(
    a: Mapping[str, str],
    b: Mapping[str, str],
    truth: Mapping[str, str],
    metric: str = "f1",
    n_boot: int = 10000,
    seed: int = 20260726,
) -> dict[str, Any]:
    """Paired bootstrap CI for the metric difference (b - a).

    Resamples sample ids, not predictions, so the pairing is preserved. The generator is
    seeded and pure-python so the interval is reproducible without numpy.
    """
    ids = list(truth.keys())
    n = len(ids)
    if n < 10:
        return {
            "refused": True,
            "reason": (
                f"n={n}. A bootstrap resamples the values it was given; below n=10 the "
                "interval cannot be narrower than their range and a '95% CI' would "
                "overstate what was measured."
            ),
            "point_delta": round(
                _metric(score(b, truth), metric) - _metric(score(a, truth), metric), 4
            ),
        }

    rng = _Lcg(seed)
    deltas = []
    for _ in range(n_boot):
        picked = [ids[rng.below(n)] for _ in range(n)]
        sub_truth = {}
        sub_a: dict[str, str] = {}
        sub_b: dict[str, str] = {}
        for j, sample_id in enumerate(picked):
            key = f"{sample_id}#{j}"
            sub_truth[key] = truth[sample_id]
            sub_a[key] = a.get(sample_id, "safe")
            sub_b[key] = b.get(sample_id, "safe")
        deltas.append(
            _metric(score(sub_b, sub_truth), metric)
            - _metric(score(sub_a, sub_truth), metric)
        )
    deltas.sort()
    lo = deltas[int(0.025 * len(deltas))]
    hi = deltas[min(int(0.975 * len(deltas)), len(deltas) - 1)]
    point = _metric(score(b, truth), metric) - _metric(score(a, truth), metric)
    return {
        "refused": False,
        "metric": metric,
        "point_delta": round(point, 4),
        "ci95": [round(lo, 4), round(hi, 4)],
        "excludes_zero": lo > 0 or hi < 0,
        "n_boot": n_boot,
    }


def _metric(c: Confusion, name: str) -> float:
    return {
        "f1": c.f1,
        "precision": c.precision,
        "recall": c.recall,
        "accuracy": c.accuracy,
        "specificity": c.specificity,
        "mcc": c.mcc,
    }[name]


class _Lcg:
    """Deterministic PRNG for the bootstrap.

    This was a hand-rolled linear congruential generator, and it was broken in a way
    that silently narrowed every interval it produced. With a power-of-two modulus and
    an odd multiplier and increment, the low bit of an LCG alternates deterministically:
    the index sequence went 23, 20, 37, 10, 3, 32, ... whose parities are exactly
    1, 0, 1, 0, 1, 0. The evaluation set alternates vulnerable and patched by index, so
    parity *is* the label, and every resample was forced to contain exactly 20 of each.
    Measured: 10,000 of 10,000 resamples had precisely 20 vulnerable samples.

    That is stratified resampling, not the i.i.d. resampling a bootstrap requires, and
    it removes the largest source of variance in a paired comparison on a balanced set.
    Every confidence interval this produced was too narrow, in the direction that
    flattered the conclusion.

    There was never a reason to hand-roll it. `random.Random` is stdlib, pure Python, and
    reproducible from a seed, which was the only property the original was reaching for.
    """

    def __init__(self, seed: int) -> None:
        self._rng = random.Random(seed)

    def below(self, n: int) -> int:
        return self._rng.randrange(n)


def summarise_runs(
    runs: Iterable[Mapping[str, str]], truth: Mapping[str, str]
) -> dict[str, Any]:
    """Aggregate repeated runs of the same arm.

    The gateway has no seed support and is nondeterministic even at temperature 0, so a
    single pass over a small evaluation set is not a measurement. Every headline number
    is therefore a mean over repeats with the full range shown, never one run.
    """
    confusions = [score(r, truth) for r in runs]
    if not confusions:
        return {}
    keys = ["TP", "TN", "FP", "FN", "precision", "recall", "specificity", "f1", "accuracy", "mcc"]
    per_run = [c.as_dict() for c in confusions]
    out: dict[str, Any] = {"repeats": len(confusions), "runs": per_run}
    for key in keys:
        values = [row[key] for row in per_run]
        out[key] = {
            "mean": round(sum(values) / len(values), 4),
            "min": min(values),
            "max": max(values),
        }
    return out
