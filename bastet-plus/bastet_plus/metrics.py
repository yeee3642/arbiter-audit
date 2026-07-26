"""Evaluation metrics.

Rewritten from ``cli/commands/evaluate/eval.py``, which had four problems that
made its numbers hard to trust:

  1. it stopped walking a repo at the **first** file that produced any output
     (``if ans == 1: break``), so a repo was scored on a prefix of itself;
  2. any non-empty output counted as a hit for the tag under test -- a slippage
     workflow that reported a reentrancy bug scored a true positive;
  3. ``tp/(tp+fp)`` and ``tp/(tp+fn)`` divide by zero when a workflow reports
     nothing, which crashes the run at the very end;
  4. ``y_true`` mixed ``bool`` and ``int``, and the sample was redrawn on every
     invocation with no seed, so two runs were never comparable.

Here the unit of evaluation is the (file, vulnerability class) pair, a finding
is attributed to a class by the detector that produced it, and every ratio is
guarded. Wilson intervals are reported because a 20-file benchmark cannot
support three significant figures and it is better to say so.
"""

from __future__ import annotations

import math
from dataclasses import dataclass, field


def _safe_div(a: float, b: float) -> float:
    return a / b if b else 0.0


def wilson(hits: int, n: int, z: float = 1.96) -> tuple[float, float]:
    """95% Wilson score interval for a proportion. Honest about small n."""
    if n == 0:
        return (0.0, 0.0)
    p = hits / n
    denom = 1 + z * z / n
    centre = (p + z * z / (2 * n)) / denom
    half = z * math.sqrt(p * (1 - p) / n + z * z / (4 * n * n)) / denom
    return (max(0.0, centre - half), min(1.0, centre + half))


@dataclass
class Confusion:
    tp: int = 0
    fp: int = 0
    fn: int = 0
    tn: int = 0

    def add(self, predicted: bool, actual: bool) -> None:
        if predicted and actual:
            self.tp += 1
        elif predicted and not actual:
            self.fp += 1
        elif not predicted and actual:
            self.fn += 1
        else:
            self.tn += 1

    @property
    def precision(self) -> float:
        return _safe_div(self.tp, self.tp + self.fp)

    @property
    def recall(self) -> float:
        return _safe_div(self.tp, self.tp + self.fn)

    @property
    def f1(self) -> float:
        return _safe_div(2 * self.tp, 2 * self.tp + self.fp + self.fn)

    @property
    def accuracy(self) -> float:
        return _safe_div(self.tp + self.tn, self.tp + self.tn + self.fp + self.fn)

    @property
    def fpr(self) -> float:
        """Fraction of genuinely clean (file, class) pairs that raised an alarm."""
        return _safe_div(self.fp, self.fp + self.tn)

    def as_dict(self) -> dict:
        pl, ph = wilson(self.tp, self.tp + self.fp)
        rl, rh = wilson(self.tp, self.tp + self.fn)
        return {
            "tp": self.tp, "fp": self.fp, "fn": self.fn, "tn": self.tn,
            "precision": round(self.precision, 4),
            "precision_ci95": [round(pl, 3), round(ph, 3)],
            "recall": round(self.recall, 4),
            "recall_ci95": [round(rl, 3), round(rh, 3)],
            "f1": round(self.f1, 4),
            "accuracy": round(self.accuracy, 4),
            "false_positive_rate": round(self.fpr, 4),
        }


@dataclass
class EvalResult:
    overall: Confusion = field(default_factory=Confusion)
    # File-level: "does this file need a human to look at it?" Reported
    # alongside the per-class numbers because they answer different questions
    # and a harness can be strong at one and weak at the other. Per-class
    # attribution is strict -- a finding merged from six detectors counts as a
    # prediction for all six of their classes -- so a harness that localises the
    # right file but spreads the class label will score far worse there.
    file_level: Confusion = field(default_factory=Confusion)
    per_class: dict[str, Confusion] = field(default_factory=dict)
    localization_hits: int = 0
    localization_total: int = 0
    line_hits: int = 0
    findings_reported: int = 0
    findings_on_clean_files: int = 0
    clean_files: int = 0
    clean_files_with_any_alarm: int = 0
    severity_histogram: dict[str, int] = field(default_factory=dict)
    per_file: list[dict] = field(default_factory=list)

    def as_dict(self) -> dict:
        return {
            "overall": self.overall.as_dict(),
            "file_level": self.file_level.as_dict(),
            "per_class": {k: v.as_dict() for k, v in sorted(self.per_class.items())},
            "localization_accuracy": round(_safe_div(self.localization_hits, self.localization_total), 4),
            "localization_n": self.localization_total,
            "findings_with_line_number": self.line_hits,
            "total_findings_reported": self.findings_reported,
            "findings_on_clean_files": self.findings_on_clean_files,
            "clean_files": self.clean_files,
            "clean_files_with_any_alarm": self.clean_files_with_any_alarm,
            "clean_file_alarm_rate": round(_safe_div(self.clean_files_with_any_alarm, self.clean_files), 4),
            "noise_per_clean_file": round(_safe_div(self.findings_on_clean_files, self.clean_files), 2),
            "severity_histogram": dict(sorted(self.severity_histogram.items())),
        }


def evaluate(results: dict[str, list], labels: dict) -> EvalResult:
    """Score a harness run.

    ``results`` maps a benchmark file name to the list of ``Finding`` objects
    the harness reported for it. Scoring unit is the (file, class) pair: for
    every file, for every class in the benchmark, did the harness raise that
    class or not, and should it have?
    """
    classes = labels["classes"]
    det_class = labels["detector_class"]
    ev = EvalResult()

    for case in labels["cases"]:
        fname = case["file"]
        truth = set(case["classes"])
        findings = results.get(fname, [])

        # A finding belongs to the class of the detector that produced it.
        # (Detectors merged across packs carry a comma-joined name.)
        predicted: dict[str, list] = {}
        for f in findings:
            for det in str(f.detector).split(","):
                cls = det_class.get(det.strip())
                if cls:
                    predicted.setdefault(cls, []).append(f)

        for cls in classes:
            hit = cls in predicted
            actual = cls in truth
            ev.overall.add(hit, actual)
            ev.per_class.setdefault(cls, Confusion()).add(hit, actual)

            # Localisation is only meaningful on true positives.
            if hit and actual:
                ev.localization_total += 1
                want = {w.lower() for w in case["functions"]}
                got = {_fn(f.function_name) for f in predicted[cls]}
                if want & got:
                    ev.localization_hits += 1

        ev.file_level.add(bool(findings), bool(truth))
        ev.findings_reported += len(findings)
        for f in findings:
            ev.severity_histogram[f.severity] = ev.severity_histogram.get(f.severity, 0) + 1
            if getattr(f, "line", None):
                ev.line_hits += 1

        if not truth:
            ev.clean_files += 1
            ev.findings_on_clean_files += len(findings)
            if findings:
                ev.clean_files_with_any_alarm += 1

        ev.per_file.append({
            "file": fname,
            "truth": sorted(truth),
            "predicted": sorted(predicted),
            "n_findings": len(findings),
        })

    return ev


def _fn(name: str) -> str:
    name = (name or "").strip().lower()
    if "(" in name:
        name = name.split("(")[0]
    if "." in name:
        name = name.rsplit(".", 1)[-1]
    return name.strip()


# --------------------------------------------------------------------------


def render_table(rows: list[list], headers: list[str]) -> str:
    """Minimal grid table -- avoids a dependency on ``tabulate``."""
    cols = len(headers)
    data = [[str(c) for c in r] for r in rows]
    widths = [max(len(headers[i]), *(len(r[i]) for r in data)) if data else len(headers[i])
              for i in range(cols)]
    sep = "+" + "+".join("-" * (w + 2) for w in widths) + "+"
    out = [sep, "| " + " | ".join(h.ljust(widths[i]) for i, h in enumerate(headers)) + " |",
           "+" + "+".join("=" * (w + 2) for w in widths) + "+"]
    for r in data:
        out.append("| " + " | ".join(r[i].ljust(widths[i]) for i in range(cols)) + " |")
        out.append(sep)
    return "\n".join(out)
