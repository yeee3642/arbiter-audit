"""Score a run in Bastet's own output format, so the two can be read side by side.

Bastet's evaluator prints a confusion table and four rates, and decides at REPOSITORY
level: a repository is positive iff any detector fired on any file in it. Comparing our
per-contract verdicts against that without saying so would be comparing different units,
so this module implements Bastet's aggregation rule explicitly and prints the identical
table.

The aggregation rule is deliberately Bastet's, not one that flatters us: a repository is
positive iff ANY contract in it was reported vulnerable. That is the rule that makes its
53-way OR saturate, and adopting it means we inherit the same exposure -- one false
positive anywhere in a 189-file repository marks the whole repository positive.
"""

from __future__ import annotations

import csv
import json
from collections import defaultdict
from dataclasses import dataclass
from pathlib import Path
from typing import Any


@dataclass
class Counts:
    tp: int = 0
    tn: int = 0
    fp: int = 0
    fn: int = 0

    @property
    def n(self) -> int:
        return self.tp + self.tn + self.fp + self.fn

    @property
    def accuracy(self) -> float:
        return (self.tp + self.tn) / self.n if self.n else 0.0

    @property
    def precision(self) -> float:
        d = self.tp + self.fp
        return self.tp / d if d else 0.0

    @property
    def recall(self) -> float:
        d = self.tp + self.fn
        return self.tp / d if d else 0.0

    @property
    def f1(self) -> float:
        p, r = self.precision, self.recall
        return 2 * p * r / (p + r) if (p + r) else 0.0


def render(counts: Counts) -> str:
    """Byte-compatible with Bastet's tabulate grid, so the two can be diffed."""
    rows = [
        ("True Positive", counts.tp),
        ("True Negative", counts.tn),
        ("False Positive", counts.fp),
        ("False Negative", counts.fn),
    ]
    sep = "+----------------+---------+"
    head = "+================+=========+"
    out = [sep, "| Metric         |   Value |", head]
    for label, value in rows:
        out.append(f"| {label:<14} | {value:>7} |")
        out.append(sep)
    out.append(f"accuracy: {counts.accuracy}")
    out.append(f"precision: {counts.precision}")
    out.append(f"recall: {counts.recall}")
    out.append(f"f1: {counts.f1}")
    return "\n".join(out)


def load_results(path: Path) -> list[dict[str, Any]]:
    return [
        json.loads(line)
        for line in path.read_text(encoding="utf-8").splitlines()
        if line.strip()
    ]


def load_repo_truth(csv_path: Path) -> dict[str, bool]:
    """Read Bastet's evaluation_results.csv: file_name, predicted_label, true_label.

    The file is CRLF and its paths are relative to `dataset/`, both of which have bitten
    this project before, so both are normalised here rather than at every call site.
    """
    truth: dict[str, bool] = {}
    text = csv_path.read_text(encoding="utf-8-sig").replace("\r\n", "\n")
    for row in csv.DictReader(text.splitlines()):
        name = (row.get("file_name") or "").strip()
        raw = (row.get("true_label") or "").strip().lower()
        if not name:
            continue
        truth[Path(name).name] = raw in ("true", "1", "yes")
    return truth


def score_samples(rows: list[dict[str, Any]]) -> Counts:
    """Per-contract scoring, for runs over a labelled evaluation set."""
    c = Counts()
    for row in rows:
        actual = row.get("truth")
        if actual not in ("vuln", "safe"):
            continue
        predicted = row.get("predicted", "safe")
        if actual == "vuln" and predicted == "vuln":
            c.tp += 1
        elif actual == "safe" and predicted == "safe":
            c.tn += 1
        elif actual == "safe" and predicted == "vuln":
            c.fp += 1
        else:
            c.fn += 1
    return c


def load_scored_rows(csv_path: Path) -> list[tuple[str, bool]]:
    """Bastet's evaluation_results.csv, row order and duplicates preserved.

    Duplicates are not noise, they are the unit of scoring: that file is one row per
    curated *finding*, and its `file_name` column holds the repository that finding was
    found in. So the same repository legitimately appears three times, and -- because the
    label is `tag in row["tag"]` for the finding while the prediction is made over the
    whole repository -- it can appear with both True and False. Two of the twenty rows in
    the run being compared against are of exactly that shape, which puts a hard ceiling of
    18/20 on any repository-level predictor, Bastet's included.
    """
    out: list[tuple[str, bool]] = []
    text = csv_path.read_text(encoding="utf-8-sig").replace("\r\n", "\n")
    for row in csv.DictReader(text.splitlines()):
        name = (row.get("file_name") or "").strip()
        if not name:
            continue
        out.append((name, (row.get("true_label") or "").strip().lower() in ("true", "1", "yes")))
    return out


def proven_classes(rows: list[dict[str, Any]]) -> dict[str, set[str]]:
    """Per repository, the classes ARBITER proved a finding for.

    Only proven findings count. An unproven one is an opinion, and the whole argument of
    this project is that an opinion is what the baseline emits 53 times per file.
    """
    out: dict[str, set[str]] = defaultdict(set)
    for row in rows:
        outcome = row.get("outcome") or {}
        if not outcome.get("proven"):
            continue
        repo = Path(str(row.get("repo") or "")).name
        for finding in outcome.get("findings") or []:
            cls = str(finding.get("vuln_class") or "").strip()
            if cls:
                out[repo].add(cls)
    return out


def score_by_tag(
    rows: list[dict[str, Any]], scored: list[tuple[str, bool]], tag: str
) -> tuple[Counts, list[tuple[str, bool, bool, str]]]:
    """Score exactly the rows Bastet was scored on, asking exactly its question.

    Its evaluator samples ten findings carrying `tag` and ten that do not, labels each row
    `tag in row["tag"]`, and predicts 1 if any detector returned a non-empty list for any
    file in that repository. The prediction ignores the tag entirely, which is why the
    same run returns the same answer whichever tag is being scored.

    Here the prediction is class-conditional and proof-carrying: positive iff ARBITER
    proved a finding of that class, by executing an exploit, somewhere in the repository.
    """
    by_repo = proven_classes(rows)
    audited = {Path(str(r.get("repo") or "")).name for r in rows}
    counts = Counts()
    detail: list[tuple[str, bool, bool, str]] = []
    for repo_path, actual in scored:
        repo = Path(repo_path).name
        classes = by_repo.get(repo, set())
        predicted = any(tag.lower() == c.lower() for c in classes)
        if repo not in audited:
            note = "NOT AUDITED"
        else:
            note = ", ".join(sorted(classes)) if classes else "-"
        if actual and predicted:
            counts.tp += 1
        elif not actual and not predicted:
            counts.tn += 1
        elif not actual and predicted:
            counts.fp += 1
        else:
            counts.fn += 1
        detail.append((repo, actual, predicted, note))
    return counts, detail


def score_repos(
    rows: list[dict[str, Any]], truth: dict[str, bool]
) -> tuple[Counts, list[tuple[str, bool, bool, int, int]]]:
    """Bastet's rule: a repository is positive iff any contract in it is positive."""
    by_repo: dict[str, list[dict[str, Any]]] = defaultdict(list)
    for row in rows:
        repo = row.get("repo") or "(unknown)"
        by_repo[Path(repo).name].append(row)

    c = Counts()
    detail: list[tuple[str, bool, bool, int, int]] = []
    for repo, items in sorted(by_repo.items()):
        if repo not in truth:
            continue
        actual = truth[repo]
        flagged = [i for i in items if i.get("predicted") == "vuln"]
        predicted = bool(flagged)
        if actual and predicted:
            c.tp += 1
        elif not actual and not predicted:
            c.tn += 1
        elif not actual and predicted:
            c.fp += 1
        else:
            c.fn += 1
        detail.append((repo, actual, predicted, len(flagged), len(items)))
    return c, detail
