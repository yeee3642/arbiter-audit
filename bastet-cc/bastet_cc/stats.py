"""Paired inference for the two-arm comparison, and the power to detect it.

The claim the project exists to support is "routed beats broadcast, same model,
same prompts". Until now nothing in the codebase tested it. `upstream_null_test`
compares one arm against an analytic constant, which is a different question, and
it does so with a bootstrap over four observations -- a resample of four numbers
cannot produce an interval narrower than their own range, and reporting 95% from
it overstates what was measured.

Three things live here.

**Paired, not two-sample.** Both arms score the *same* repositories with the
*same* model; only `plan()` differs. A two-sample test throws that away and pays
for between-repository variance -- which dominates, because repositories differ
enormously in size, quality and tag load. McNemar's test conditions on the pairs
where the arms disagree and ignores the rest, which is exactly the right thing:
a repository both arms get right carries no evidence about which is better. With
12 TEST repositories this is the difference between a test that can resolve
something and one that cannot.

**Exact, not asymptotic.** McNemar's chi-square approximation needs the
discordant count b+c to be reasonably large; here it will plausibly be under 20.
The exact binomial version is used unconditionally -- it costs nothing and does
not silently degrade.

**Power, computed before the run rather than regretted after.** `mde()` answers
the question that decides whether the TEST scan is worth its wall-clock: given
n paired decisions, how large must the true improvement be before this design can
see it? If the honest answer is "larger than anything plausible", that is a
finding about the experiment, and it is better known on D2 than on D5.

No SciPy: the binomial tail is a finite exact sum and the bootstrap is a loop.
One less dependency to pin, and the arithmetic is auditable by eye.
"""

from __future__ import annotations

import math
import random
from dataclasses import dataclass, asdict
from typing import Iterable, Sequence

# A bootstrap resamples the observations it was given. Below this many, the
# interval it reports describes the sample's own range and not the sampling
# distribution, so the functions here refuse rather than emit a misleading number.
MIN_BOOTSTRAP_N = 10


@dataclass
class McNemar:
    """b = A right / B wrong, c = A wrong / B right. Concordant pairs are dropped."""
    n_pairs: int
    b: int
    c: int
    p_value: float
    odds_ratio: float | None      # b/c, None when c == 0
    exact: bool = True

    @property
    def discordant(self) -> int:
        return self.b + self.c

    def to_dict(self) -> dict:
        d = asdict(self)
        d["discordant"] = self.discordant
        return d


def _binom_pmf(k: int, n: int, p: float = 0.5) -> float:
    return math.comb(n, k) * (p ** k) * ((1.0 - p) ** (n - k))


def binom_two_sided_p(b: int, n: int) -> float:
    """Exact two-sided binomial p for b successes in n trials against p=0.5.

    Two-sided by doubling the smaller tail, which for p=0.5 is exact rather than
    approximate because the distribution is symmetric.
    """
    if n == 0:
        return 1.0
    k = min(b, n - b)
    tail = sum(_binom_pmf(i, n) for i in range(k + 1))
    return min(1.0, 2.0 * tail)


def mcnemar(pairs: Iterable[tuple[bool, bool]]) -> McNemar:
    """Exact McNemar over (arm_a_correct, arm_b_correct) decision pairs.

    A "pair" is one (repository, tag) decision scored under both arms. Concordant
    pairs -- both right or both wrong -- contribute nothing, which is the point:
    they say the two arms behaved identically there.
    """
    b = c = n = 0
    for a_ok, b_ok in pairs:
        n += 1
        if a_ok and not b_ok:
            b += 1
        elif b_ok and not a_ok:
            c += 1
    return McNemar(
        n_pairs=n, b=b, c=c,
        p_value=binom_two_sided_p(b, b + c),
        odds_ratio=(b / c) if c else None,
    )


def mde(n_discordant: int, alpha: float = 0.05, power: float = 0.80) -> float:
    """Minimum detectable effect, as the discordant split McNemar could resolve.

    Returns the smallest `p = b/(b+c)` distinguishable from 0.5 at the given alpha
    and power, using the normal approximation to the binomial -- appropriate here
    because this is a planning figure, not a reported result.

    Read it as: "of the decisions where the two arms disagree, the routed arm must
    win at least this fraction before the design can call it." A value near 1.0
    means the experiment is underpowered and only a landslide will register.
    """
    if n_discordant <= 0:
        return 1.0
    z_a = 1.959963984540054 if abs(alpha - 0.05) < 1e-9 else _z(1 - alpha / 2)
    z_b = 0.8416212335729143 if abs(power - 0.80) < 1e-9 else _z(power)
    delta = (z_a + z_b) / (2.0 * math.sqrt(n_discordant))
    return min(1.0, 0.5 + delta)


def _z(p: float) -> float:
    """Inverse normal CDF (Acklam's rational approximation, ~1e-9 absolute)."""
    if not 0.0 < p < 1.0:
        raise ValueError("p must be in (0, 1)")
    a = (-3.969683028665376e+01, 2.209460984245205e+02, -2.759285104469687e+02,
         1.383577518672690e+02, -3.066479806614716e+01, 2.506628277459239e+00)
    b = (-5.447609879822406e+01, 1.615858368580409e+02, -1.556989798598866e+02,
         6.680131188771972e+01, -1.328068155288572e+01)
    c = (-7.784894002430293e-03, -3.223964580411365e-01, -2.400758277161838e+00,
         -2.549732539343734e+00, 4.374664141464968e+00, 2.938163982698783e+00)
    d = (7.784695709041462e-03, 3.224671290700398e-01, 2.445134137142996e+00,
         3.754408661907416e+00)
    p_low, p_high = 0.02425, 1 - 0.02425
    if p < p_low:
        q = math.sqrt(-2 * math.log(p))
        return (((((c[0]*q+c[1])*q+c[2])*q+c[3])*q+c[4])*q+c[5]) / \
               ((((d[0]*q+d[1])*q+d[2])*q+d[3])*q+1)
    if p > p_high:
        q = math.sqrt(-2 * math.log(1 - p))
        return -(((((c[0]*q+c[1])*q+c[2])*q+c[3])*q+c[4])*q+c[5]) / \
                ((((d[0]*q+d[1])*q+d[2])*q+d[3])*q+1)
    q = p - 0.5
    r = q * q
    return (((((a[0]*r+a[1])*r+a[2])*r+a[3])*r+a[4])*r+a[5])*q / \
           (((((b[0]*r+b[1])*r+b[2])*r+b[3])*r+b[4])*r+1)


@dataclass
class Interval:
    point: float
    lo: float
    hi: float
    n: int
    method: str

    @property
    def excludes_zero(self) -> bool:
        return self.lo > 0.0 or self.hi < 0.0

    def to_dict(self) -> dict:
        d = asdict(self)
        d["excludes_zero"] = self.excludes_zero
        return d


def paired_bootstrap(
    values_a: Sequence[float],
    values_b: Sequence[float],
    reps: int = 10_000,
    seed: int = 20260725,
    alpha: float = 0.05,
) -> Interval:
    """CI on the mean paired difference (a - b), resampling *units*, not arms.

    The unit must be the repository, not the (repository, tag) decision: decisions
    inside one repository share a codebase, a model pass and an author, so treating
    them as independent understates the interval. Callers pass one aggregate per
    repository.

    Raises below MIN_BOOTSTRAP_N rather than returning an interval that is really
    just the sample range wearing a percentage sign.
    """
    if len(values_a) != len(values_b):
        raise ValueError("paired bootstrap needs equal-length, aligned sequences")
    n = len(values_a)
    if n < MIN_BOOTSTRAP_N:
        raise ValueError(
            f"n={n} is below MIN_BOOTSTRAP_N={MIN_BOOTSTRAP_N}: a bootstrap over "
            f"{n} observations resamples only those {n} values and its interval is "
            f"bounded by their range. Report the raw paired differences instead."
        )
    diffs = [a - b for a, b in zip(values_a, values_b)]
    rng = random.Random(seed)
    means = sorted(
        sum(diffs[rng.randrange(n)] for _ in range(n)) / n for _ in range(reps)
    )
    lo = means[int((alpha / 2) * reps)]
    hi = means[min(reps - 1, int((1 - alpha / 2) * reps))]
    return Interval(point=sum(diffs) / n, lo=lo, hi=hi, n=n,
                    method=f"paired percentile bootstrap, {reps} reps, seed {seed}")


def describe_paired(values_a: Sequence[float], values_b: Sequence[float],
                    label_a: str = "A", label_b: str = "B") -> dict:
    """Bootstrap when n allows it, raw paired differences when it does not.

    Small-n is the expected case on a 12-repository TEST split, so degrading to
    "here are the twelve differences" is the designed behaviour, not an error
    path. A reader can evaluate twelve numbers; they cannot evaluate a bootstrap
    interval that was never entitled to exist.
    """
    diffs = [a - b for a, b in zip(values_a, values_b)]
    n = len(diffs)
    wins = sum(1 for d in diffs if d > 0)
    losses = sum(1 for d in diffs if d < 0)
    out: dict = {
        "n": n,
        "mean_difference": (sum(diffs) / n) if n else None,
        "wins": wins, "losses": losses, "ties": n - wins - losses,
        "differences": [round(d, 6) for d in diffs],
        # Sign test: distribution-free, valid at any n, and the only inferential
        # statement a 12-unit paired design can make without extra assumptions.
        "sign_test_p": binom_two_sided_p(wins, wins + losses),
        "labels": {"a": label_a, "b": label_b},
    }
    try:
        out["bootstrap"] = paired_bootstrap(values_a, values_b).to_dict()
    except ValueError as e:
        out["bootstrap"] = None
        out["bootstrap_declined"] = str(e)
    return out


def format_mcnemar(m: McNemar, label_a: str = "routed",
                   label_b: str = "broadcast") -> str:
    lines = [
        f"McNemar (exact), {m.n_pairs} paired decisions",
        f"  {label_a} right / {label_b} wrong (b) : {m.b}",
        f"  {label_a} wrong / {label_b} right (c) : {m.c}",
        f"  discordant                            : {m.discordant}"
        f"   (concordant {m.n_pairs - m.discordant} carry no evidence)",
        f"  two-sided exact p                     : {m.p_value:.4f}",
    ]
    if m.odds_ratio is not None:
        lines.append(f"  odds ratio b/c                        : {m.odds_ratio:.2f}")
    threshold = mde(m.discordant)
    lines.append(
        f"  MDE at n={m.discordant} discordant       : {threshold:.3f}"
        f"   (need b/(b+c) >= {threshold:.3f} for 80% power)")
    observed = m.b / m.discordant if m.discordant else float("nan")
    if m.discordant:
        verdict = "resolvable" if observed >= threshold else "under-powered"
        lines.append(f"  observed b/(b+c)                      : {observed:.3f}"
                     f"   -> {verdict}")
    return "\n".join(lines)
