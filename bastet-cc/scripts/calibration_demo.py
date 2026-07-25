"""Acceptance run for the decision layer: aggregate.py, verify.py, upstream_score().

Nothing here is a unit test with a hidden assertion budget -- every section prints the
numbers it checks, because the claim being made ("the upstream arm is a corner of our
parameter space, not a different program") is only worth anything if it is visible.

Sections:
  A  upstream degeneracy: aggregate(prior=1, tau=0) == "any finding -> positive"
  B  noisy-OR vs max, on the exact failure the design cites
  C  fit_calibration on DEV with synthetic findings; tau sweep
  D  same predictions, both scorers, both calibrations -> the score delta
  E  verdict multipliers: verify_impact with injected verdicts
  F  real findings from runs/d1_routed_dev1 through the whole layer
  G  verify.py offline: context extraction, checks, tag definition, prompt
  H  verify.py live: a handful of real findings against the 550B endpoint

DEV split only. TEST repositories are filtered out of the ground truth before it is
read, and the filter is asserted.
"""

from __future__ import annotations

import asyncio
import json
import os
import random
import sys
from pathlib import Path

import pandas as pd

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

from bastet_cc import evaluate                                    # noqa: E402
from bastet_cc.aggregate import (                                 # noqa: E402
    Calibration, aggregate, aggregate_scores, evaluate_calibration, finding_score,
    fit_calibration, format_sweep, grid_search, macro_f1, scoreable_tags,
    truth_map, upstream_calibration, upstream_equivalence_report, verify_impact,
)
from bastet_cc.findings import Finding                            # noqa: E402
from bastet_cc.llm import LLMClient                               # noqa: E402
from bastet_cc.routing import load_detectors                      # noqa: E402
from bastet_cc.runstore import RunStore                           # noqa: E402
from bastet_cc.solidity import index_repo                         # noqa: E402
from bastet_cc.tags import canonical_tag                          # noqa: E402
from bastet_cc.verify import (                                    # noqa: E402
    VerifyPolicy, detector_checks, function_context, load_detector_meta,
    tag_definition, verify_findings, verdict_counts,
)

DATA = ROOT.parent / "data"
BASE_URL = "https://llm-api.zoolab.org/v1"
API_KEY = os.environ.get("AIS3_API_KEY") or sys.exit(
    "set AIS3_API_KEY (the AIS3 LLM gateway token); it is deliberately not in the repo"
)
MODEL = "ais3/nemotron-3-ultra-550b"
SEED = 20260725


def rule(title: str) -> None:
    print("\n" + "=" * 78)
    print(title)
    print("=" * 78)


def load_dev():
    splits = json.loads((DATA / "splits.json").read_text())
    dev, test = splits["dev"], set(splits["test"])
    df = pd.read_csv(DATA / "train.csv")
    df = df[df["repo_path"].isin(dev)].copy()
    assert not (set(df["repo_path"]) & test), "TEST leaked into the calibration frame"
    return dev, df


def synth_findings(dev: list[str], truth: dict[str, set[str]],
                   detectors, seed: int = SEED) -> list[Finding]:
    """A fake detector fleet with a known noise profile.

    Three populations, so the layer has something to separate: `sharp` detectors fire
    mostly when the tag is really there, `noisy` ones fire on everything, and the rest
    sit in between. Confidences are drawn per population, not per finding correctness
    -- a detector that is wrong is usually confident about it, which is the whole
    reason a per-detector prior beats trusting self-reported confidence.
    """
    rng = random.Random(seed)
    profiles: dict[str, tuple[float, float, tuple[float, float]]] = {}
    for i, d in enumerate(detectors):
        if i % 3 == 0:
            profiles[d.id] = (0.75, 0.05, (0.6, 0.95))    # sharp
        elif i % 3 == 1:
            profiles[d.id] = (0.55, 0.30, (0.5, 0.9))     # ordinary
        else:
            profiles[d.id] = (0.60, 0.75, (0.7, 0.95))    # noisy: confident and wrong

    out: list[Finding] = []
    for repo in dev:
        for d in detectors:
            tag = canonical_tag(d.tags[0]) if d.tags else ""
            if not tag:
                continue
            p_hit, p_fp, (c_lo, c_hi) = profiles[d.id]
            positive = tag in truth.get(repo, set())
            p = p_hit if positive else p_fp
            if rng.random() >= p:
                continue
            # A firing detector reports 1-4 functions: volume is what noisy-OR would
            # reward and max deliberately ignores.
            for k in range(rng.randint(1, 4)):
                out.append(Finding(
                    repo=repo, detector_id=d.id, tag=tag, subtag="",
                    severity="Medium", path=f"contracts/Fake{k}.sol",
                    contract=f"Fake{k}", function=f"f{k}",
                    description="synthetic", evidence=f"L{10 * k + 1}-L{10 * k + 9}",
                    confidence=round(rng.uniform(c_lo, c_hi), 2),
                ))
    return out


def both_scorers(name: str, findings, calib, df, dev, tmap, tags) -> dict:
    """One prediction set under all three rulers.

    `objective` is what `fit_calibration` maximizes: every (repo, tag) pair in DEV is
    one decision, no sampling. `fixed` is `evaluate.score_all`, which draws a balanced
    positive/negative repo sample per tag, and `upstream` is the replica of eval.py.
    The three can disagree on the same predictions -- that disagreement is the point
    of reporting all three, and it is why the fitter's objective is stated explicitly
    instead of being left implicit in whichever scorer runs last.
    """
    preds = aggregate(findings, calib, repos=dev, tags=tags)
    objective = evaluate_calibration(findings, calib, tmap, dev, tags)
    samples = {t: evaluate.build_sample(df, t, sample_size=len(dev), seed=SEED)
               for t in tags}
    fixed = evaluate.score_all(samples, preds)
    fixed_macro = macro_f1({t: evaluate.Confusion(**{k: cm[k] for k in
                                                     ("tp", "tn", "fp", "fn")})
                            for t, cm in fixed["per_tag"].items() if cm["n"]})
    ups = evaluate.upstream_score(df, preds, sample_size=len(df), seed=SEED)
    return {
        "name": name,
        "objective_macro_f1": objective["macro_f1"],
        "objective_tp": objective["pooled"]["tp"],
        "objective_fp": objective["pooled"]["fp"],
        "fixed_macro_f1": fixed_macro,
        "fixed_pooled_f1": fixed["pooled"]["f1"],
        "fixed_tp": fixed["pooled"]["tp"], "fixed_fp": fixed["pooled"]["fp"],
        "fixed_fn": fixed["pooled"]["fn"],
        "upstream_macro_f1": ups["macro_f1"],
        "upstream_pooled_f1": ups["pooled"]["f1"],
        "upstream_tp": ups["pooled"]["tp"], "upstream_fp": ups["pooled"]["fp"],
        "upstream_fn": ups["pooled"]["fn"],
    }


def main() -> int:
    dev, df = load_dev()
    tmap = truth_map(df, dev)
    tags = scoreable_tags(tmap, dev)
    detectors = load_detectors(ROOT / "detectors")
    findings = synth_findings(dev, tmap, detectors)

    print(f"DEV repos: {len(dev)}   ground-truth rows: {len(df)}   "
          f"scoreable tags: {len(tags)}")
    print(f"detectors: {len(detectors)}   synthetic findings: {len(findings)}")

    # -- A ---------------------------------------------------------------------
    rule("A. upstream equivalence: prior=1, multiplier=1, tau=0")
    rep = upstream_equivalence_report(findings, repos=dev)
    print(json.dumps({k: v for k, v in rep.items()
                      if k not in ("only_calibrated", "only_literal")}, indent=2))
    print(f"disagreements: calibrated-only={len(rep['only_calibrated'])}, "
          f"literal-only={len(rep['only_literal'])}")
    assert rep["equivalent"], "upstream corner is NOT reproducible -- control arm broken"
    print("OK  aggregate(findings, upstream_calibration()) == upstream_predictions()")

    ups_calib = upstream_calibration()
    lo = min(f.confidence for f in findings)
    print(f"lowest synthetic confidence {lo:.2f} still scores "
          f"{min(finding_score(f, ups_calib) for f in findings):.2f} >= tau=0.0 "
          "-> every finding fires, which is upstream's rule")

    # -- A2 --------------------------------------------------------------------
    rule("A2. upstream_score() vs the E6 reference replica (DEV rows only)")
    import importlib.util
    spec = importlib.util.spec_from_file_location(
        "e6", ROOT / "scripts" / "e6_scorer_forensics.py")
    e6 = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(e6)

    oracle = {t: {r: (t in tmap.get(r, set())) for r in dev} for t in tags}
    mismatch = []
    checked = 0
    for tag in tags:
        ref = e6.upstream_sample_and_score(df, tag, tmap, seed=SEED,
                                           sample_size=len(df))
        if ref is None:
            continue
        mine = evaluate.upstream_score(df, {tag: oracle[tag]},
                                       sample_size=len(df), seed=SEED)
        cm = mine["per_tag"][tag]
        checked += 1
        if (ref.tp, ref.fp, ref.fn, ref.tn) != (cm["tp"], cm["fp"], cm["fn"], cm["tn"]):
            mismatch.append((tag, (ref.tp, ref.fp, ref.fn, ref.tn),
                             (cm["tp"], cm["fp"], cm["fn"], cm["tn"])))
    print(f"tags cross-checked against scripts/e6_scorer_forensics: {checked}, "
          f"confusion-matrix mismatches: {len(mismatch)}")
    assert not mismatch, mismatch
    print("OK  evaluate.upstream_score reproduces the independent E6 replica exactly")
    perfect = evaluate.upstream_score(df, oracle, sample_size=len(df), seed=SEED)
    print(f"a PERFECT predictor scored by the upstream replica on DEV: "
          f"macro-F1 {perfect['macro_f1']:.4f}, pooled F1 "
          f"{perfect['pooled']['f1']:.4f} (a sound scorer would say 1.0)")

    # -- B ---------------------------------------------------------------------
    rule("B. max vs noisy-OR on the case DESIGN 2.6 names")
    good = Finding(repo="r", detector_id="good", tag="T", subtag="", severity="High",
                   path="p", contract="c", function="f", description="", evidence="",
                   confidence=0.9)
    calib = Calibration(detector_prior={"good": 0.9, "bad": 0.25}, tau=0.30)
    s_good = finding_score(good, calib)

    def bad_alarms(n: int) -> list[Finding]:
        return [Finding(repo="r", detector_id="bad", tag="T", subtag="",
                        severity="Low", path="p", contract="c", function=f"f{i}",
                        description="", evidence="", confidence=0.3)
                for i in range(n)]

    print(f"one good alarm (prior 0.90, conf 0.90): max={s_good:.3f} -> "
          f"{'POSITIVE' if s_good >= calib.tau else 'negative'} at tau={calib.tau}")
    print(f"{'n junk alarms':>14}{'max':>8}{'noisy-OR':>10}{'max says':>10}"
          f"{'noisy-OR says':>15}")
    for n in (1, 5, 10, 20, 40):
        alarms = bad_alarms(n)
        mx = max(finding_score(f, calib) for f in alarms)
        nor = 1.0
        for f in alarms:
            nor *= (1 - finding_score(f, calib))
        nor = 1 - nor
        print(f"{n:>14}{mx:>8.3f}{nor:>10.3f}"
              f"{('POSITIVE' if mx >= calib.tau else 'negative'):>10}"
              f"{('POSITIVE' if nor >= calib.tau else 'negative'):>15}")
    print("-> volume alone drives noisy-OR over tau, and past the good detector's "
          "score entirely; max is invariant to how loud a weak detector is. "
          "That is the FP storm DESIGN 2.6 refuses to reward.")

    # -- C ---------------------------------------------------------------------
    rule("C. fit_calibration on DEV (tau sweep, global threshold)")
    calib = fit_calibration(findings, df, dev)
    print(format_sweep(calib))
    print(f"\nselected tau = {calib.tau}")
    priors = sorted(calib.detector_prior.items(), key=lambda kv: kv[1])
    print(f"priors fitted for {len(priors)} detectors; "
          f"lowest {priors[0][0]}={priors[0][1]:.3f}, "
          f"highest {priors[-1][0]}={priors[-1][1]:.3f}")
    print(f"clip in effect: min={min(v for _, v in priors):.2f} "
          f"max={max(v for _, v in priors):.2f}")

    rt = Calibration.from_dict(json.loads(json.dumps(calib.to_dict())))
    assert rt.tau == calib.tau and rt.detector_prior == calib.detector_prior
    assert aggregate(findings, rt, repos=dev) == aggregate(findings, calib, repos=dev)
    print("calibration survives a json round-trip (manifest-persistable): OK")

    best, grid = grid_search(findings, df, dev)
    print(f"\ngrid_search over tau x (alpha, beta, clip): {len(grid)} cells, "
          f"best macro-F1={best.diagnostics['grid_best']['macro_f1']:.4f} at "
          f"tau={best.tau}, alpha={best.diagnostics['grid_best']['alpha']}, "
          f"beta={best.diagnostics['grid_best']['beta']}, "
          f"clip=({best.diagnostics['grid_best']['clip_lo']}, "
          f"{best.diagnostics['grid_best']['clip_hi']})")
    spread = max(r["macro_f1"] for r in grid) - min(r["macro_f1"] for r in grid)
    print(f"macro-F1 across the grid: min={min(r['macro_f1'] for r in grid):.4f} "
          f"max={max(r['macro_f1'] for r in grid):.4f} spread={spread:.4f} "
          "(a flat grid would mean the layer has no signal to work with)")

    # -- D ---------------------------------------------------------------------
    rule("D. same predictions, two scorers, two calibrations")
    preds_ups = aggregate(findings, ups_calib, repos=dev, tags=tags)
    preds_cal = aggregate(findings, calib, repos=dev, tags=tags)
    rows = [both_scorers("upstream (prior=1, tau=0)", findings, ups_calib,
                         df, dev, tmap, tags),
            both_scorers(f"calibrated (tau={calib.tau})", findings, calib,
                         df, dev, tmap, tags)]

    def cell(v):
        return "  n/a" if v is None else f"{v:5.3f}"

    print(f"{'calibration':<28}{'objective':>11}{'obj TP/FP':>12}"
          f"{'fixed macroF1':>15}{'fixed TP/FP':>13}{'ups macroF1':>13}{'ups F1':>9}")
    for r in rows:
        print(f"{r['name']:<28}{cell(r['objective_macro_f1']):>11}"
              f"{str(r['objective_tp']) + '/' + str(r['objective_fp']):>12}"
              f"{cell(r['fixed_macro_f1']):>15}"
              f"{str(r['fixed_tp']) + '/' + str(r['fixed_fp']):>13}"
              f"{cell(r['upstream_macro_f1']):>13}"
              f"{cell(r['upstream_pooled_f1']):>9}")
    d_obj = rows[1]["objective_macro_f1"] - rows[0]["objective_macro_f1"]
    d_fixed = rows[1]["fixed_macro_f1"] - rows[0]["fixed_macro_f1"]
    d_ups = (rows[1]["upstream_macro_f1"] or 0) - (rows[0]["upstream_macro_f1"] or 0)
    print(f"\ndelta (calibrated - upstream): objective {d_obj:+.4f}, "
          f"fixed scorer {d_fixed:+.4f}, upstream scorer {d_ups:+.4f}")
    print("the fitter moves its own objective; the sampled scorers rebalance the "
          "negative pool per tag and need not agree on synthetic noise")
    n_pos_ups = sum(v for d in preds_ups.values() for v in d.values())
    n_pos_cal = sum(v for d in preds_cal.values() for v in d.values())
    print(f"positive (repo,tag) decisions: upstream {n_pos_ups}, calibrated {n_pos_cal} "
          f"(of {len(tags) * len(dev)} possible)")

    # -- E ---------------------------------------------------------------------
    rule("E. verdict multipliers (verify_impact)")
    rng = random.Random(SEED + 1)
    verdicts = ["confirmed", "rejected", "uncertain", "unverified"]
    verified = [Finding(**{**f.__dict__,
                          "verdict": rng.choices(verdicts, [0.25, 0.45, 0.2, 0.1])[0]})
                for f in findings]
    print("injected verdicts:", verdict_counts(verified))
    impact = verify_impact(verified, calib, tmap, dev)
    print(f"macro-F1 honouring verdicts : {impact['macro_f1_with_verify']:.4f}")
    print(f"macro-F1 ignoring verdicts  : {impact['macro_f1_without_verify']:.4f}")
    hurt = {t: d for t, d in impact["delta_recall_by_tag"].items() if d and d < -0.29}
    print(f"tags losing >0.29 recall to the verifier (DESIGN 2.5 per-tag off-list): "
          f"{sorted(hurt)}")
    calib_off = Calibration(detector_prior=calib.detector_prior, tau=calib.tau,
                            verify_off_tags=set(hurt))
    res_off = evaluate_calibration(verified, calib_off, tmap, dev, tags)
    print(f"macro-F1 with those tags' verifier disabled: {res_off['macro_f1']:.4f}")

    table = calib.diagnostics["verify_enablement"]
    on = [r for r in table if r["verify"]]
    print(f"verify enablement table: {len(table)} detectors, {len(on)} ON "
          f"(reasons: {sorted({r['reason'].split()[0] for r in on})})")

    # -- F ---------------------------------------------------------------------
    rule("F. real findings from runs/d1_routed_dev1")
    store = RunStore(ROOT / "runs" / "d1_routed_dev1")
    real = store.load_findings()
    real_repos = sorted({f.repo for f in real})
    assert set(real_repos) <= set(dev), "real findings must come from DEV"
    rtags = scoreable_tags(tmap, real_repos)
    print(f"{len(real)} findings, repos={real_repos}, "
          f"tags in findings={sorted({f.tag for f in real})}")
    r_ups = evaluate_calibration(real, ups_calib, tmap, real_repos, rtags)
    r_cal = fit_calibration(real, df, real_repos)
    r_fit = evaluate_calibration(real, r_cal, tmap, real_repos, rtags)
    print(f"upstream corner : macro-F1 {r_ups['macro_f1']:.4f}  "
          f"TP={r_ups['pooled']['tp']} FP={r_ups['pooled']['fp']} "
          f"FN={r_ups['pooled']['fn']}")
    print(f"fitted (tau={r_cal.tau:.2f}): macro-F1 {r_fit['macro_f1']:.4f}  "
          f"TP={r_fit['pooled']['tp']} FP={r_fit['pooled']['fp']} "
          f"FN={r_fit['pooled']['fn']}")
    print("(one repo, 8 tags -- reported to show the layer runs on real output, "
          "not as a result)")
    sc = aggregate_scores(real, r_cal)
    print("per-tag max scores:",
          {t: round(max(v.values()), 3) for t, v in sorted(sc.items())})

    # -- G ---------------------------------------------------------------------
    rule("G. verify.py offline: context, checks, definitions")
    repo = real_repos[0]
    ix = index_repo(DATA / "ex" / "train" / repo)
    print(f"indexed {repo}: {ix['n_files']} files, {ix['n_functions']} functions")
    meta = load_detector_meta()
    print(f"detector meta loaded for {len(meta)} detectors "
          f"(synthesized={sum(1 for m in meta.values() if m['synthesized'])}, "
          f"gated={sum(1 for m in meta.values() if m['gated'])})")
    policy = VerifyPolicy()
    n_on = sum(1 for f in real if policy.enabled(f, meta.get(f.detector_id)))
    print(f"default policy (handwritten OFF): {n_on}/{len(real)} findings enabled")
    n_on_all = sum(1 for f in real if VerifyPolicy.all_on().enabled(f, meta.get(f.detector_id)))
    print(f"all_on policy: {n_on_all}/{len(real)} findings enabled")

    resolved = 0
    for f in real:
        if function_context(ix, f):
            resolved += 1
    print(f"context resolved from the index for {resolved}/{len(real)} findings")

    f0 = next(f for f in real if function_context(ix, f))
    ctx = function_context(ix, f0)
    print(f"\nexample: {f0.detector_id} @ {f0.path}:{f0.contract}.{f0.function}")
    print(f"  context {len(ctx)} chars, {len(ctx.splitlines())} lines")
    print(f"  tag definition: {tag_definition(f0.tag)[:90]}...")
    print(f"  detector checks: {len(detector_checks(f0.detector_id))} extracted")
    for c in detector_checks(f0.detector_id)[:2]:
        print(f"    - {c[:80]}")
    print("  context head:")
    for line in ctx.splitlines()[:4]:
        print("    " + line[:88])

    # -- H ---------------------------------------------------------------------
    rule("H. verify.py live against 550B")
    subset = real[:10]
    vstore = RunStore(ROOT / "runs" / "calib_demo")

    async def live() -> list:
        client = LLMClient(BASE_URL, API_KEY, MODEL, max_concurrency=6,
                           log_path=vstore.llm_log_path)
        try:
            return await verify_findings(subset, ix, client, vstore,
                                         policy=VerifyPolicy.all_on())
        finally:
            await client.aclose()   # same loop, or httpx tears down after it closes

    out = asyncio.run(live())
    print("verdicts:", verdict_counts(out))
    for f in out:
        print(f"  {f.verdict:<11} {f.tag:<18} {f.contract}.{f.function}")

    before = evaluate_calibration(subset, calib, tmap, real_repos, rtags)["macro_f1"]
    after = evaluate_calibration(out, calib, tmap, real_repos, rtags)["macro_f1"]
    print(f"macro-F1 on this subset before/after verification: {before:.4f} -> {after:.4f}")

    rule("SUMMARY")
    print(json.dumps({
        "upstream_equivalent": rep["equivalent"],
        "fitted_tau": calib.tau,
        "synthetic": {"fixed_macro_f1": rows, },
        "grid_cells": len(grid),
        "live_verdicts": verdict_counts(out),
    }, indent=2, default=str)[:1200])
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
