"""Repo-level aggregation and calibration: the decision layer the metric asks for.

The pipeline produces function-level findings; the scorer asks a repository-level
question ("does this repo contain a `Slippage` bug?"). Something has to convert one
into the other, and upstream's converter is implicit: any node that emits anything at
all makes the repo positive. That is the degenerate corner of this module --
`upstream_calibration()` is `prior=1, multiplier=1, tau=0`, and `aggregate()` under it
provably equals `upstream_predictions()` (see `upstream_equivalence_report`). Keeping
the control arm as a parameterization rather than a separate code path is what makes
the comparison a knob rather than a rewrite (DESIGN §1.4, §2.6).

Three design choices, each of which could have gone the other way:

- **max, not noisy-OR.** Noisy-OR rewards volume: ten low-quality alarms from a bad
  detector outrank one alarm from a good one, which is precisely the failure mode
  (FP storms) this layer exists to suppress. Max means a repository is positive
  because its *best* piece of evidence is good enough, never because there was a lot
  of bad evidence.
- **one global tau, not per-tag tau.** DEV holds 10 repositories. A per-tag threshold
  grid over ~20 tags fits noise by construction; per-detector priors already supply
  the per-detector differentiation, and tau only has to place the global operating
  point.
- **Laplace-smoothed per-detector priors.** A detector that fired twice and was right
  twice is not a 1.0-precision detector; (tp+alpha)/(tp+fp+beta) with a clip keeps
  small samples away from both extremes, and the clip floor keeps a detector that was
  wrong on DEV from being silenced everywhere.

Fitting reads DEV labels only. TEST labels never enter this module -- callers pass
`repos`, and every function scores exactly the repositories it is handed.
"""

from __future__ import annotations

from dataclasses import dataclass, field, replace
from typing import Iterable, Sequence

import pandas as pd

from .evaluate import Confusion
from .findings import Finding
from .tags import canonical_tag

# DESIGN §2.5 step 5. `unverified` is deliberately below 1.0: a finding nobody
# challenged is weaker evidence than one that survived a challenge.
DEFAULT_MULTIPLIER: dict[str, float] = {
    "confirmed": 1.0,
    "unverified": 0.7,
    "uncertain": 0.4,
    "rejected": 0.0,
}

# DESIGN §1.3: tau sweep range. 0.10 is the floor because the product of a clipped
# prior (>=0.2) and a plausible confidence (>=0.5) already sits near it -- below that
# the threshold stops discriminating and the arm degenerates towards upstream.
TAU_GRID: tuple[float, ...] = (0.10, 0.15, 0.20, 0.25, 0.30, 0.35,
                               0.40, 0.45, 0.50, 0.55, 0.60)

# Laplace pseudo-counts and the clip applied afterwards (DESIGN §1.3).
PRIOR_ALPHA = 1.0
PRIOR_BETA = 2.0
PRIOR_CLIP: tuple[float, float] = (0.2, 0.95)

# Prior for a detector that never fired on the calibration split: the smoothing
# prior with zero observations, i.e. alpha/beta.
def _uninformed_prior(alpha: float = PRIOR_ALPHA, beta: float = PRIOR_BETA,
                      clip: tuple[float, float] = PRIOR_CLIP) -> float:
    return min(clip[1], max(clip[0], alpha / beta))


@dataclass
class Calibration:
    """Everything that turns findings into repo-level decisions.

    `detector_prior`, `tau` and `verify_multiplier` are the DESIGN §1.3 fields.
    The rest carry defaults so the documented three-field construction still works:
    `default_prior` covers detectors unseen during fitting, `verify_off_tags` is the
    per-tag verifier override DESIGN §2.5 requires to live here, and `diagnostics`
    holds whatever the fitter learned along the way (tau sweep, per-detector FP
    rates, the verifier enablement table) so a run manifest can record it.
    """
    detector_prior: dict[str, float] = field(default_factory=dict)
    tau: float = 0.0
    verify_multiplier: dict[str, float] = field(
        default_factory=lambda: dict(DEFAULT_MULTIPLIER))
    default_prior: float = field(default_factory=_uninformed_prior)
    verify_off_tags: set[str] = field(default_factory=set)
    diagnostics: dict = field(default_factory=dict)

    def prior(self, detector_id: str) -> float:
        return self.detector_prior.get(detector_id, self.default_prior)

    def multiplier(self, finding: Finding) -> float:
        """Verdict multiplier, with the per-tag verifier override applied.

        A tag on the off-list is one where DEV showed the verifier destroying recall
        (cross-function bugs it cannot see). Turning it off means the verdict is
        discarded, not that it is trusted -- the finding falls back to the
        `unverified` weight it would have carried had no verifier run.
        """
        mult = self.verify_multiplier
        if finding.tag in self.verify_off_tags:
            return mult.get("unverified", DEFAULT_MULTIPLIER["unverified"])
        return mult.get(finding.verdict,
                        mult.get("unverified", DEFAULT_MULTIPLIER["unverified"]))

    def to_dict(self) -> dict:
        return {
            "detector_prior": dict(sorted(self.detector_prior.items())),
            "tau": self.tau,
            "verify_multiplier": dict(self.verify_multiplier),
            "default_prior": self.default_prior,
            "verify_off_tags": sorted(self.verify_off_tags),
            "diagnostics": self.diagnostics,
        }

    @staticmethod
    def from_dict(d: dict) -> "Calibration":
        return Calibration(
            detector_prior=dict(d.get("detector_prior") or {}),
            tau=float(d.get("tau", 0.0)),
            verify_multiplier=dict(d.get("verify_multiplier") or DEFAULT_MULTIPLIER),
            default_prior=float(d.get("default_prior", _uninformed_prior())),
            verify_off_tags=set(d.get("verify_off_tags") or ()),
            diagnostics=dict(d.get("diagnostics") or {}),
        )


def upstream_calibration() -> Calibration:
    """The control arm: every detector fully trusted, no verifier, no threshold.

    `tau=0.0` with the `score >= tau` rule means any finding at all flips the repo
    positive, because confidence is clamped to [0, 1] and the prior and multiplier
    are 1.0 -- the score of any finding is its confidence, which is >= 0. This is
    upstream Bastet's behaviour exactly, not an approximation of it.
    """
    return Calibration(
        detector_prior={},
        tau=0.0,
        verify_multiplier={k: 1.0 for k in DEFAULT_MULTIPLIER},
        default_prior=1.0,
    )


# -- scoring --------------------------------------------------------------------


def finding_score(finding: Finding, calib: Calibration) -> float:
    """prior(detector) x confidence x verdict multiplier (DESIGN §1.3)."""
    return calib.prior(finding.detector_id) * finding.confidence * calib.multiplier(finding)


def aggregate_scores(findings: Iterable[Finding],
                     calib: Calibration) -> dict[str, dict[str, float]]:
    """{tag: {repo: score}} by max over that repo's findings for that tag.

    Only (tag, repo) pairs with at least one finding appear; a pair with no evidence
    has no score at all rather than a score of zero, which keeps `tau=0` from
    promoting silence into a positive.
    """
    scores: dict[str, dict[str, float]] = {}
    for f in findings:
        s = finding_score(f, calib)
        by_repo = scores.setdefault(f.tag, {})
        if s > by_repo.get(f.repo, float("-inf")):
            by_repo[f.repo] = s
    return scores


def aggregate(findings: Iterable[Finding], calib: Calibration,
              repos: Sequence[str] | None = None,
              tags: Sequence[str] | None = None) -> dict[str, dict[str, bool]]:
    """{tag: {repo: bool}} ready for `evaluate.score_all` / `evaluate.upstream_score`.

    `repos`/`tags` are optional and only materialize explicit negatives: both scorers
    already read a missing repo as "nothing found", so passing them changes the shape
    of the output, never a decision.
    """
    scores = aggregate_scores(findings, calib)
    tag_set = list(tags) if tags is not None else list(scores)
    out: dict[str, dict[str, bool]] = {}
    for tag in tag_set:
        by_repo = scores.get(tag, {})
        preds = {r: (s >= calib.tau) for r, s in by_repo.items()}
        if repos is not None:
            for r in repos:
                preds.setdefault(r, False)
        out[tag] = preds
    return out


def upstream_predictions(findings: Iterable[Finding],
                         repos: Sequence[str] | None = None
                         ) -> dict[str, dict[str, bool]]:
    """Upstream's rule written out literally: one finding anywhere -> repo positive.

    This exists to be compared against `aggregate(findings, upstream_calibration())`.
    If the two ever disagree, the degenerate parameterization has stopped being the
    control arm and every A/B number in the report is suspect.
    """
    out: dict[str, dict[str, bool]] = {}
    for f in findings:
        out.setdefault(f.tag, {})[f.repo] = True
    if repos is not None:
        for by_repo in out.values():
            for r in repos:
                by_repo.setdefault(r, False)
    return out


def upstream_equivalence_report(findings: Iterable[Finding],
                                repos: Sequence[str] | None = None) -> dict:
    """Check the control-arm identity and report the disagreements, if any."""
    findings = list(findings)
    calibrated = aggregate(findings, upstream_calibration(), repos=repos)
    literal = upstream_predictions(findings, repos=repos)
    pairs_a = {(t, r) for t, d in calibrated.items() for r, v in d.items() if v}
    pairs_b = {(t, r) for t, d in literal.items() for r, v in d.items() if v}
    return {
        "equivalent": pairs_a == pairs_b,
        "n_findings": len(findings),
        "n_positive_pairs": len(pairs_b),
        "only_calibrated": sorted(pairs_a - pairs_b),
        "only_literal": sorted(pairs_b - pairs_a),
    }


# -- truth handling -------------------------------------------------------------


def truth_map(truth: pd.DataFrame, repos: Sequence[str] | None = None,
              repo_col: str = "repo_path", tag_col: str = "tag",
              status_col: str | None = "status") -> dict[str, set[str]]:
    """{repo: {canonical tags}} for the repositories being calibrated on.

    Multi-label cells are split and folded with `tags.canonical_tag`, the same
    function `findings.parse_findings` uses, so a detector's tag and a ground-truth
    tag are comparable strings. Repos in `repos` with no rows stay in the map with an
    empty set -- they are true negatives for every tag, not missing data.
    """
    df = truth
    if status_col and status_col in df.columns:
        df = df[df[status_col].astype(str).str.strip().str.lower() == "done"]
    wanted = set(repos) if repos is not None else None

    out: dict[str, set[str]] = {r: set() for r in (wanted or ())}
    for repo, cell in zip(df[repo_col], df[tag_col]):
        key = str(repo).strip()
        if wanted is not None and key not in wanted:
            continue
        tags = {canonical_tag(t) for t in str(cell or "").split(",") if t.strip()}
        out.setdefault(key, set()).update(tags)
    return out


def scoreable_tags(truth: dict[str, set[str]], repos: Sequence[str]) -> list[str]:
    """Tags with at least one positive repository in the calibration set.

    Both scorers need a positive pool to build a sample, so a tag with none is
    unscoreable and cannot contribute to the objective. Tags that only ever appear
    as false positives are therefore invisible here -- that is a property of the
    metric we are being judged on, and the fitter deliberately mirrors it rather
    than optimizing something the report will not show.
    """
    counts: dict[str, int] = {}
    for r in repos:
        for t in truth.get(r, set()):
            counts[t] = counts.get(t, 0) + 1
    return sorted(t for t, n in counts.items() if n > 0)


# -- evaluation on the calibration split ----------------------------------------


def confusion_by_tag(predictions: dict[str, dict[str, bool]],
                     truth: dict[str, set[str]],
                     repos: Sequence[str],
                     tags: Sequence[str]) -> dict[str, Confusion]:
    """Every (repo, tag) in `repos` x `tags` is one decision -- no sampling.

    This is the corrected scorer's unit (DESIGN §3.3): with 10 DEV repos and ~20
    tags it is 200 paired decisions, which is what makes a threshold sweep on DEV
    mean anything at all.
    """
    out: dict[str, Confusion] = {}
    for tag in tags:
        cm = Confusion()
        preds = predictions.get(tag, {})
        for repo in repos:
            cm.add(bool(preds.get(repo, False)), tag in truth.get(repo, set()))
        out[tag] = cm
    return out


def macro_f1(confusions: dict[str, Confusion]) -> float:
    """Unweighted mean F1 over tags; an undefined F1 counts as 0.

    Macro rather than pooled because coverage is the story: a tag we cannot detect
    at all should drag the headline number down by a full tag's worth.
    """
    if not confusions:
        return 0.0
    return sum((cm.f1 or 0.0) for cm in confusions.values()) / len(confusions)


def evaluate_calibration(findings: Iterable[Finding], calib: Calibration,
                         truth: dict[str, set[str]], repos: Sequence[str],
                         tags: Sequence[str] | None = None) -> dict:
    """macro-F1 + per-tag confusions for one calibration on one repo set."""
    findings = list(findings)
    tags = list(tags) if tags is not None else scoreable_tags(truth, repos)
    preds = aggregate(findings, calib, repos=repos, tags=tags)
    cms = confusion_by_tag(preds, truth, repos, tags)
    pooled = Confusion()
    for cm in cms.values():
        pooled.tp += cm.tp
        pooled.tn += cm.tn
        pooled.fp += cm.fp
        pooled.fn += cm.fn
    return {
        "macro_f1": macro_f1(cms),
        "pooled": pooled.to_dict(),
        "per_tag": {t: cm.to_dict() for t, cm in cms.items()},
        "n_tags": len(tags),
        "tau": calib.tau,
    }


# -- fitting --------------------------------------------------------------------


def detector_stats(findings: Iterable[Finding], truth: dict[str, set[str]],
                   repos: Sequence[str] | None = None) -> dict[str, dict]:
    """Per-detector hit/miss counts at finding granularity.

    A finding counts as a hit when its detector's tag really is one of the repo's
    ground-truth tags. This is not the same as the finding being correct -- the
    function it points at may be innocent while the repo is guilty of that tag
    elsewhere -- but repo x tag is the granularity we are scored at, and it is the
    only granularity the labels support.
    """
    keep = set(repos) if repos is not None else None
    stats: dict[str, dict] = {}
    for f in findings:
        if keep is not None and f.repo not in keep:
            continue
        s = stats.setdefault(f.detector_id, {"tp": 0, "fp": 0, "n": 0, "tag": f.tag})
        s["n"] += 1
        if f.tag in truth.get(f.repo, set()):
            s["tp"] += 1
        else:
            s["fp"] += 1
    for s in stats.values():
        s["fp_rate"] = s["fp"] / s["n"] if s["n"] else 0.0
    return stats


def fit_priors(findings: Iterable[Finding], truth: dict[str, set[str]],
               repos: Sequence[str] | None = None,
               alpha: float = PRIOR_ALPHA, beta: float = PRIOR_BETA,
               clip: tuple[float, float] = PRIOR_CLIP) -> dict[str, float]:
    """Laplace-smoothed precision per detector, clipped (DESIGN §1.3)."""
    lo, hi = clip
    out: dict[str, float] = {}
    for det, s in detector_stats(findings, truth, repos).items():
        raw = (s["tp"] + alpha) / (s["tp"] + s["fp"] + beta)
        out[det] = min(hi, max(lo, raw))
    return out


def verify_enablement_table(findings: Iterable[Finding], truth: dict[str, set[str]],
                            repos: Sequence[str] | None = None,
                            detector_meta: dict[str, dict] | None = None,
                            fp_rate_threshold: float = 0.5) -> list[dict]:
    """The DEV table DESIGN §2.5(4) wants out of the fitter.

    Policy encoded: synthesized ON, gated forced ON, hand-written OFF unless its DEV
    false-positive rate exceeds the threshold. `detector_meta` is optional -- without
    it every detector is treated as hand-written, which is the conservative default
    (verification costs calls, so the burden of proof is on turning it on).
    """
    meta = detector_meta or {}
    rows: list[dict] = []
    for det, s in sorted(detector_stats(findings, truth, repos).items()):
        m = meta.get(det, {})
        gated = bool(m.get("gated"))
        synth = bool(m.get("synthesized")) or m.get("source_workflow") == "synthesized"
        if gated:
            enable, why = True, "gated"
        elif synth:
            enable, why = True, "synthesized"
        elif s["fp_rate"] > fp_rate_threshold:
            enable, why = True, f"fp_rate {s['fp_rate']:.2f} > {fp_rate_threshold}"
        else:
            enable, why = False, "handwritten"
        rows.append({"detector_id": det, "tag": s["tag"], "n_findings": s["n"],
                     "tp": s["tp"], "fp": s["fp"], "fp_rate": round(s["fp_rate"], 4),
                     "verify": enable, "reason": why})
    return rows


def verify_impact(findings: Iterable[Finding], calib: Calibration,
                  truth: dict[str, set[str]], repos: Sequence[str]) -> dict:
    """Delta precision/recall from honouring verdicts versus ignoring them.

    Only meaningful once a verify pass has actually written verdicts; with an
    all-`unverified` finding set both sides are identical by construction and the
    deltas are zero, which is the honest answer rather than a crash.
    """
    findings = list(findings)
    blind = replace(calib, verify_multiplier={k: calib.verify_multiplier.get(
        "unverified", DEFAULT_MULTIPLIER["unverified"]) for k in DEFAULT_MULTIPLIER})
    tags = scoreable_tags(truth, repos)
    with_v = evaluate_calibration(findings, calib, truth, repos, tags)
    without_v = evaluate_calibration(findings, blind, truth, repos, tags)

    def delta(key: str) -> dict[str, float | None]:
        a, b = with_v["per_tag"], without_v["per_tag"]
        out = {}
        for t in tags:
            va, vb = a[t][key], b[t][key]
            out[t] = None if (va is None or vb is None) else round(va - vb, 4)
        return out

    return {
        "macro_f1_with_verify": with_v["macro_f1"],
        "macro_f1_without_verify": without_v["macro_f1"],
        "delta_precision_by_tag": delta("precision"),
        "delta_recall_by_tag": delta("recall"),
        "n_verdicts": {v: sum(1 for f in findings if f.verdict == v)
                       for v in DEFAULT_MULTIPLIER},
    }


def fit_calibration(findings: list[Finding], truth: pd.DataFrame,
                    repos: list[str]) -> Calibration:
    """DESIGN §1.3: priors from DEV, then sweep tau for max macro-F1.

    Multipliers stay fixed at DEFAULT_MULTIPLIER during the sweep -- they encode a
    prior belief about verification, and re-fitting them on 10 repositories would
    spend the split's entire statistical budget on four numbers.

    Ties on macro-F1 go to the larger tau: at equal score, fewer positives is the
    safer operating point, and it moves further from the upstream corner.
    """
    tmap = truth_map(truth, repos)
    tags = scoreable_tags(tmap, repos)
    priors = fit_priors(findings, tmap, repos)

    sweep: list[dict] = []
    best: tuple[float, float] | None = None   # (macro_f1, tau)
    for tau in TAU_GRID:
        cand = Calibration(detector_prior=priors, tau=tau)
        res = evaluate_calibration(findings, cand, tmap, repos, tags)
        sweep.append({"tau": tau, "macro_f1": res["macro_f1"],
                      "tp": res["pooled"]["tp"], "fp": res["pooled"]["fp"],
                      "fn": res["pooled"]["fn"], "tn": res["pooled"]["tn"]})
        if best is None or (res["macro_f1"], tau) >= best:
            best = (res["macro_f1"], tau)

    tau = best[1] if best else TAU_GRID[0]
    calib = Calibration(detector_prior=priors, tau=tau)
    calib.diagnostics = {
        "fit_repos": list(repos),
        "n_findings": len(findings),
        "scoreable_tags": tags,
        "tau_sweep": sweep,
        "best_macro_f1": best[0] if best else None,
        "upstream_macro_f1": evaluate_calibration(
            findings, upstream_calibration(), tmap, repos, tags)["macro_f1"],
        "detector_stats": detector_stats(findings, tmap, repos),
        "verify_enablement": verify_enablement_table(findings, tmap, repos),
    }
    return calib


def grid_search(findings: list[Finding], truth: pd.DataFrame, repos: list[str],
                taus: Sequence[float] = TAU_GRID,
                alphas: Sequence[float] = (0.5, 1.0, 2.0),
                betas: Sequence[float] = (1.0, 2.0, 4.0),
                clips: Sequence[tuple[float, float]] = ((0.0, 1.0), (0.2, 0.95),
                                                        (0.35, 0.9)),
                ) -> tuple[Calibration, list[dict]]:
    """Joint sweep over tau and the prior's smoothing/clipping parameters.

    Returns the best calibration and the full grid, because the *shape* of the grid
    is the finding worth reporting: a metric that is flat in tau says the decision
    layer has nothing to work with, and that is a result, not a failure to tune.

    This is a bigger search than `fit_calibration` performs, so it overfits DEV
    harder; the honest use is sensitivity analysis, with `fit_calibration` shipping
    the number. Ties break towards larger tau, then smaller alpha/beta ratio.
    """
    tmap = truth_map(truth, repos)
    tags = scoreable_tags(tmap, repos)

    rows: list[dict] = []
    best_row: dict | None = None
    best_calib: Calibration | None = None
    for alpha in alphas:
        for beta in betas:
            for clip in clips:
                priors = fit_priors(findings, tmap, repos, alpha, beta, clip)
                default = _uninformed_prior(alpha, beta, clip)
                for tau in taus:
                    cand = Calibration(detector_prior=priors, tau=tau,
                                       default_prior=default)
                    res = evaluate_calibration(findings, cand, tmap, repos, tags)
                    row = {"tau": tau, "alpha": alpha, "beta": beta,
                           "clip_lo": clip[0], "clip_hi": clip[1],
                           "macro_f1": res["macro_f1"],
                           "pooled_f1": res["pooled"]["f1"],
                           "tp": res["pooled"]["tp"], "fp": res["pooled"]["fp"]}
                    rows.append(row)
                    key = (row["macro_f1"], tau, -alpha / beta)
                    if best_row is None or key > (best_row["macro_f1"],
                                                  best_row["tau"],
                                                  -best_row["alpha"] / best_row["beta"]):
                        best_row, best_calib = row, cand

    assert best_calib is not None and best_row is not None
    best_calib.diagnostics = {
        "fit_repos": list(repos),
        "scoreable_tags": tags,
        "grid_best": best_row,
        "grid_size": len(rows),
        "upstream_macro_f1": evaluate_calibration(
            findings, upstream_calibration(), tmap, repos, tags)["macro_f1"],
    }
    return best_calib, rows


def format_sweep(calib: Calibration) -> str:
    """The tau sweep as a table -- the calibration plot in text form."""
    sweep = (calib.diagnostics or {}).get("tau_sweep") or []
    lines = [f"{'tau':>6}{'macroF1':>10}{'TP':>6}{'FP':>6}{'FN':>6}{'TN':>6}"]
    ups = (calib.diagnostics or {}).get("upstream_macro_f1")
    if ups is not None:
        lines.append(f"{'0.00*':>6}{ups:>10.4f}{'':>6}{'':>6}{'':>6}{'':>6}"
                     "   <- upstream corner (prior=1, tau=0, no verify)")
    for row in sweep:
        mark = "  <- selected" if row["tau"] == calib.tau else ""
        lines.append(f"{row['tau']:>6.2f}{row['macro_f1']:>10.4f}{row['tp']:>6}"
                     f"{row['fp']:>6}{row['fn']:>6}{row['tn']:>6}{mark}")
    return "\n".join(lines)
