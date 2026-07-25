"""Repo-level detection scoring, compatible with upstream Bastet's own metric.

Upstream evaluates one tag at a time as a binary question -- "does this repository
contain a `Slippage` bug?" -- and reports a confusion matrix. Keeping that shape means
our numbers land beside the ones OneSavie has published (F1 0.681 in the README,
F1 0.774 in the CyberSec/ETH-Taipei slides) without any translation.

Three defects in `cli/commands/evaluate/eval.py` are corrected here, because they
change the reported score rather than merely offending taste:

1. Label/sample disagreement. Upstream draws negatives with `dataset["tag"] != tag`
   (exact string inequality) but labels them with `tag in row["tag"]` (substring
   containment). Tags are comma-separated multi-labels -- `"Chainlink, Oracle"`,
   `"Flashloan, Governance"` -- so a row tagged `"Slippage, Logic error"` lands in the
   negative pool and is then labelled positive. The negative class is contaminated by
   construction, and the positive pool simultaneously drops every multi-tag positive.
   Substring matching is wrong for a second reason: `"Oracle"` is contained in no other
   tag here, but `"DoS"` and `"Pause"` style short tags make containment fragile in
   general. Membership over the split list is the only correct test.

2. Unseeded sampling. `.sample()` runs without `random_state`, so two runs evaluate
   two different subsets and the confusion matrices are not comparable. The upstream
   README acknowledges instability but attributes it entirely to the model.

3. `precision = tp / (tp + fp)` raises ZeroDivisionError when a detector predicts no
   positives -- exactly the case worth reporting.

Per-tag results are kept alongside the pooled ones so coverage gaps show up as
structure rather than a single depressed average.
"""

from __future__ import annotations

import math
from dataclasses import dataclass, field, asdict

import pandas as pd


def parse_tags(raw: object) -> set[str]:
    """Split a dataset tag cell into its atomic tags.

    Cells hold one or more comma-separated tags. Whitespace around separators is
    inconsistent in the corpus, and `Logic error` / `Logic Error` both occur.
    """
    if raw is None or (isinstance(raw, float) and math.isnan(raw)):
        return set()
    return {t.strip() for t in str(raw).split(",") if t.strip()}


def normalize_tag(tag: str) -> str:
    """Fold the casing variants the corpus actually contains."""
    return {"logic error": "Logic Error"}.get(tag.strip().lower(), tag.strip())


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
    def accuracy(self) -> float | None:
        return (self.tp + self.tn) / self.n if self.n else None

    @property
    def precision(self) -> float | None:
        # Undefined rather than zero when nothing was predicted positive: a detector
        # that never fires has no precision, and reporting 0.0 hides that distinction.
        d = self.tp + self.fp
        return self.tp / d if d else None

    @property
    def recall(self) -> float | None:
        d = self.tp + self.fn
        return self.tp / d if d else None

    @property
    def f1(self) -> float | None:
        d = 2 * self.tp + self.fp + self.fn
        return 2 * self.tp / d if d else None

    def add(self, predicted: bool, actual: bool) -> None:
        if predicted and actual:
            self.tp += 1
        elif predicted and not actual:
            self.fp += 1
        elif not predicted and actual:
            self.fn += 1
        else:
            self.tn += 1

    def to_dict(self) -> dict:
        return {
            **asdict(self),
            "n": self.n,
            "accuracy": self.accuracy,
            "precision": self.precision,
            "recall": self.recall,
            "f1": self.f1,
        }


@dataclass
class TagSample:
    """The repositories evaluated for one tag, with their true labels."""
    tag: str
    positives: list[str] = field(default_factory=list)
    negatives: list[str] = field(default_factory=list)

    @property
    def repos(self) -> list[tuple[str, bool]]:
        return [(r, True) for r in self.positives] + [(r, False) for r in self.negatives]


def build_sample(
    dataset: pd.DataFrame,
    tag: str,
    sample_size: int,
    seed: int,
    repo_col: str = "repo_path",
    tag_col: str = "tag",
    status_col: str | None = "status",
) -> TagSample:
    """Draw a balanced positive/negative repository sample for one tag.

    Labels are assigned per repository, not per finding: a repo is positive for `tag`
    if any of its findings carries that tag. Upstream compares at the same granularity
    -- it stops walking a repo at the first file that produces output -- so matching
    that keeps the metrics aligned.
    """
    df = dataset
    if status_col and status_col in df.columns:
        df = df[df[status_col].astype(str).str.strip().str.lower() == "done"]

    want = normalize_tag(tag)
    repo_tags: dict[str, set[str]] = {}
    for repo, raw in zip(df[repo_col], df[tag_col]):
        key = str(repo).strip()
        repo_tags.setdefault(key, set()).update(
            normalize_tag(t) for t in parse_tags(raw)
        )

    # Membership, not containment -- the fix for defect (1).
    positives = sorted(r for r, tags in repo_tags.items() if want in tags)
    negatives = sorted(r for r, tags in repo_tags.items() if want not in tags)

    n = min(sample_size, len(positives), len(negatives))
    if n == 0:
        return TagSample(tag=want)

    rng = pd.Series(positives).sample(n=n, random_state=seed)
    rng2 = pd.Series(negatives).sample(n=n, random_state=seed)
    return TagSample(tag=want, positives=list(rng), negatives=list(rng2))


def score(
    sample: TagSample,
    predictions: dict[str, bool],
) -> Confusion:
    """Compare per-repo predictions against the sample's labels.

    A repository absent from `predictions` counts as "no vulnerability found", which
    is what upstream records when a scan completes without emitting findings.
    """
    cm = Confusion()
    for repo, actual in sample.repos:
        cm.add(bool(predictions.get(repo, False)), actual)
    return cm


def score_all(
    samples: dict[str, TagSample],
    predictions: dict[str, dict[str, bool]],
) -> dict:
    """Per-tag and pooled confusion matrices.

    Pooling sums the per-tag matrices rather than averaging their F1s: a tag with two
    evaluable repositories should not weigh as much as one with forty.
    """
    per_tag = {t: score(s, predictions.get(t, {})) for t, s in samples.items()}
    pooled = Confusion()
    for cm in per_tag.values():
        pooled.tp += cm.tp
        pooled.tn += cm.tn
        pooled.fp += cm.fp
        pooled.fn += cm.fn

    evaluable = [t for t, s in samples.items() if s.repos]
    return {
        "pooled": pooled.to_dict(),
        "per_tag": {t: cm.to_dict() for t, cm in per_tag.items()},
        "n_tags_evaluable": len(evaluable),
        "n_tags_requested": len(samples),
    }


# -- upstream's own scorer, reproduced -----------------------------------------
#
# Everything above corrects upstream's evaluator. `upstream_score` deliberately does
# not: it replays `cli/commands/evaluate/eval.py` including all three defects, so the
# same predictions can be reported under both rulers (DESIGN §1.3, E1/E6). Without it
# a claimed improvement could always be dismissed as a change of ruler.
#
# One unavoidable deviation: upstream calls `.sample()` with no `random_state`, which
# is not a scorer, it is a lottery. A seed is threaded through so the replica is
# reproducible; the variance the missing seed causes is itself measured in
# runs/instrument (F1 range 0.1644 across unseeded draws).

UPSTREAM_SAMPLE_SIZE = 100          # upstream's CLI default


def upstream_sample(
    dataset: pd.DataFrame,
    tag: str,
    sample_size: int = UPSTREAM_SAMPLE_SIZE,
    seed: int = 0,
) -> list[tuple[str, int]]:
    """Upstream's positive/negative pools, at finding-row granularity.

    eval.py:25-26 splits the *rows* on `dataset["tag"] == tag`, exact string equality
    against a comma-separated multi-label cell. A repo tagged `"Slippage, Logic error"`
    therefore lands in the negative pool for `Slippage`. eval.py:96 then labels that
    same row with `tag in row["tag"]` -- substring containment -- which calls it
    positive. The row is drawn as a negative and scored as a positive; the negative
    pool is contaminated by construction and the positive pool loses every multi-tag
    finding. Both behaviours are reproduced exactly.

    Returns [(repo_path, true_label)] in upstream's shuffled row order. A repository
    with several findings appears several times, which is also upstream's behaviour:
    its evaluation unit is the row, while its scan is per repository.
    """
    df = dataset
    if "status" in df.columns:
        df = df[df["status"] == "Done"]            # eval.py:20, exact match

    row_tagged = df[df["tag"] == tag]              # eval.py:25
    row_untagged = df[df["tag"] != tag]            # eval.py:26

    n = min(sample_size, len(row_tagged), len(row_untagged))   # eval.py:28-33
    if n == 0:
        return []

    picked_tagged = row_tagged.sample(n=n, random_state=seed)
    picked_untagged = row_untagged.sample(n=n, random_state=seed + 10_000)
    combined = pd.concat([picked_tagged, picked_untagged]).sample(
        frac=1, random_state=seed)                 # eval.py:41-42

    return [
        (str(row["repo_path"]).strip(), 1 if tag in str(row["tag"]) else 0)
        for _, row in combined.iterrows()          # eval.py:96 containment labelling
    ]


def upstream_score(
    dataset: pd.DataFrame,
    predictions: dict[str, dict[str, bool]],
    sample_size: int = UPSTREAM_SAMPLE_SIZE,
    seed: int = 0,
) -> dict:
    """Score repo-level predictions the way upstream's eval.py would.

    `predictions` is `{tag: {repo: bool}}` -- the same structure `score_all` takes and
    `aggregate.aggregate` produces, so one prediction set goes through both scorers
    unchanged. Tags come from `predictions`; a repository missing from a tag's map
    predicts negative, which is what upstream records when a scan finds nothing.

    The pooled/per-tag return shape matches `score_all` so `format_table` renders
    either. Upstream itself computes `tp / (tp + fp)` unguarded and crashes when a
    scanner predicts nothing; `Confusion.precision` returns None there instead. The
    counts, which is what the comparison rests on, are identical.
    """
    per_tag: dict[str, Confusion] = {}
    for tag, repo_preds in predictions.items():
        rows = upstream_sample(dataset, tag, sample_size, seed)
        cm = Confusion()
        for repo, actual in rows:
            cm.add(bool(repo_preds.get(repo, False)), bool(actual))
        per_tag[tag] = cm

    pooled = Confusion()
    for cm in per_tag.values():
        pooled.tp += cm.tp
        pooled.tn += cm.tn
        pooled.fp += cm.fp
        pooled.fn += cm.fn

    f1s = [cm.f1 for cm in per_tag.values() if cm.n]
    return {
        "scorer": "upstream",
        "pooled": pooled.to_dict(),
        "per_tag": {t: cm.to_dict() for t, cm in per_tag.items()},
        "macro_f1": (sum(v or 0.0 for v in f1s) / len(f1s)) if f1s else None,
        "n_tags_evaluable": sum(1 for cm in per_tag.values() if cm.n),
        "n_tags_requested": len(per_tag),
        "sample_size": sample_size,
        "seed": seed,
    }


def format_table(result: dict) -> str:
    """Upstream prints a four-row grid; this keeps that and adds the per-tag breakdown."""
    p = result["pooled"]

    def pct(v: float | None) -> str:
        return "  n/a" if v is None else f"{v:5.3f}"

    lines = [
        "+----------------+---------+",
        "| Metric         |   Value |",
        "+================+=========+",
        f"| True Positive  | {p['tp']:>7} |",
        f"| True Negative  | {p['tn']:>7} |",
        f"| False Positive | {p['fp']:>7} |",
        f"| False Negative | {p['fn']:>7} |",
        "+----------------+---------+",
        f"accuracy:  {pct(p['accuracy'])}",
        f"precision: {pct(p['precision'])}",
        f"recall:    {pct(p['recall'])}",
        f"f1:        {pct(p['f1'])}",
        "",
        f"{'tag':<22}{'n':>5}{'TP':>5}{'FP':>5}{'FN':>5}{'TN':>5}{'prec':>8}{'rec':>8}{'f1':>8}",
    ]
    for tag, cm in sorted(
        result["per_tag"].items(),
        key=lambda kv: (-(kv[1]["f1"] or -1), kv[0]),
    ):
        if not cm["n"]:
            continue
        lines.append(
            f"{tag:<22}{cm['n']:>5}{cm['tp']:>5}{cm['fp']:>5}{cm['fn']:>5}{cm['tn']:>5}"
            f"{pct(cm['precision']):>8}{pct(cm['recall']):>8}{pct(cm['f1']):>8}"
        )
    return "\n".join(lines)
