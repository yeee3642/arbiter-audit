"""The decision layer, and the identity the whole A/B rests on.

`aggregate(findings, upstream_calibration())` must equal `upstream_predictions(...)`
exactly. That identity is what makes the control arm a *parameterisation* rather
than a second implementation -- and if it ever breaks, every A/B number in the
report is comparing against something that is no longer upstream's rule. The
codebase already provides `upstream_equivalence_report()` for this; nothing was
calling it.
"""

from __future__ import annotations

import pandas as pd
import pytest

from bastet_cc.aggregate import (Calibration, DEFAULT_MULTIPLIER, aggregate,
                                 aggregate_scores, confusion_by_tag, detector_stats,
                                 finding_score, fit_calibration, fit_priors,
                                 macro_f1, scoreable_tags, truth_map,
                                 upstream_calibration, upstream_equivalence_report,
                                 upstream_predictions)


class TestControlArmIdentity:
    def test_degenerate_calibration_equals_the_literal_upstream_rule(self, finding_factory):
        findings = [
            finding_factory(repo="r1", tag="Slippage", confidence=0.05),
            finding_factory(repo="r2", tag="DoS", confidence=1.0),
            finding_factory(repo="r1", tag="DoS", confidence=0.5, verdict="rejected"),
        ]
        report = upstream_equivalence_report(findings, repos=["r1", "r2", "r3"])
        assert report["equivalent"], report

    def test_identity_holds_even_for_rejected_findings(self, finding_factory):
        # Upstream has no verifier, so a rejected finding must still flip the
        # repo positive under the control parameterisation. This is the case
        # most likely to break if someone "improves" the multiplier defaults.
        findings = [finding_factory(repo="r1", verdict="rejected", confidence=0.0)]
        assert aggregate(findings, upstream_calibration())["Slippage"]["r1"] is True
        assert upstream_predictions(findings)["Slippage"]["r1"] is True

    def test_zero_confidence_still_fires_upstream(self, finding_factory):
        # score = 1.0 * 0.0 * 1.0 = 0.0, and the rule is `>= tau` with tau = 0.0.
        f = finding_factory(confidence=0.0)
        assert finding_score(f, upstream_calibration()) == 0.0
        assert aggregate([f], upstream_calibration())["Slippage"]["r1"] is True

    def test_silence_is_never_promoted_to_a_positive(self, finding_factory):
        # tau=0 with `>= tau` would make every repo positive if absent pairs got
        # a score of 0. They must have no score at all.
        preds = aggregate([], upstream_calibration(), repos=["r1"], tags=["Slippage"])
        assert preds["Slippage"]["r1"] is False


class TestScoring:
    def test_max_not_noisy_or(self, finding_factory):
        # Ten weak alarms must not outrank one strong one.
        weak = [finding_factory(repo="r1", detector_id=f"d{i}", confidence=0.1)
                for i in range(10)]
        calib = Calibration(detector_prior={f"d{i}": 0.5 for i in range(10)}, tau=0.3)
        scores = aggregate_scores(weak, calib)
        assert scores["Slippage"]["r1"] == pytest.approx(0.5 * 0.1 * 0.7)
        assert aggregate(weak, calib)["Slippage"]["r1"] is False

    def test_verdict_multiplier_orders_confirmed_above_unverified(self, finding_factory):
        calib = Calibration(detector_prior={"d1": 1.0}, tau=0.0)
        s = {v: finding_score(finding_factory(verdict=v, confidence=1.0), calib)
             for v in DEFAULT_MULTIPLIER}
        assert s["confirmed"] > s["unverified"] > s["uncertain"] > s["rejected"]

    def test_verify_off_tag_falls_back_to_unverified_not_to_trust(self, finding_factory):
        # Switching the verifier off for a tag must discard the verdict, not
        # honour it. A rejected finding on an off-list tag should score as
        # unverified (0.7), not as rejected (0.0).
        calib = Calibration(detector_prior={"d1": 1.0}, tau=0.0,
                            verify_off_tags={"Slippage"})
        f = finding_factory(verdict="rejected", confidence=1.0)
        assert finding_score(f, calib) == pytest.approx(0.7)

    def test_unknown_detector_gets_the_uninformed_prior(self, finding_factory):
        calib = Calibration(detector_prior={"known": 0.9}, tau=0.0)
        assert calib.prior("never_seen") == pytest.approx(0.5)  # clip(alpha/beta)


class TestPriors:
    def test_laplace_smoothing_keeps_small_samples_off_the_extremes(self, finding_factory):
        # Two findings, both right: raw precision 1.0, smoothed and clipped to 0.75.
        findings = [finding_factory(repo="r1"), finding_factory(repo="r2")]
        truth = {"r1": {"Slippage"}, "r2": {"Slippage"}}
        priors = fit_priors(findings, truth, ["r1", "r2"])
        assert priors["d1"] == pytest.approx(3 / 4)
        assert 0.2 <= priors["d1"] <= 0.95

    def test_a_detector_wrong_every_time_is_floored_not_silenced(self, finding_factory):
        findings = [finding_factory(repo=f"r{i}") for i in range(10)]
        truth = {f"r{i}": set() for i in range(10)}
        priors = fit_priors(findings, truth, [f"r{i}" for i in range(10)])
        assert priors["d1"] == pytest.approx(0.2), "clip floor must keep it alive"

    def test_detector_stats_counts_at_repo_x_tag_granularity(self, finding_factory):
        findings = [finding_factory(repo="r1", function="a"),
                    finding_factory(repo="r1", function="b")]
        stats = detector_stats(findings, {"r1": {"Slippage"}}, ["r1"])
        # Both findings hit because the repo genuinely carries the tag, even
        # though at most one of them can point at the right function.
        assert stats["d1"] == {"tp": 2, "fp": 0, "n": 2, "tag": "Slippage",
                               "fp_rate": 0.0}


class TestTruthAndTags:
    def test_repos_with_no_rows_are_true_negatives_not_missing(self):
        df = pd.DataFrame({"repo_path": ["r1"], "tag": ["DoS"], "status": ["Done"]})
        tmap = truth_map(df, ["r1", "r2"])
        assert tmap["r2"] == set()

    def test_scoreable_tags_needs_a_positive(self):
        tmap = {"r1": {"DoS"}, "r2": set()}
        assert scoreable_tags(tmap, ["r1", "r2"]) == ["DoS"]

    def test_macro_f1_counts_an_undefined_tag_as_zero(self):
        from bastet_cc.evaluate import Confusion
        cms = {"good": Confusion(tp=1, fp=0, fn=0, tn=1), "dead": Confusion()}
        assert macro_f1(cms) == pytest.approx(0.5)

    def test_confusion_by_tag_scores_the_full_cross_product(self):
        cms = confusion_by_tag({"T": {"r1": True}}, {"r1": {"T"}, "r2": set()},
                               ["r1", "r2"], ["T"])
        assert cms["T"].n == 2


class TestCalibrationFitting:
    def test_fit_records_the_sweep_and_the_upstream_corner(self, finding_factory):
        findings = [finding_factory(repo="r1", confidence=0.9),
                    finding_factory(repo="r2", confidence=0.2)]
        truth_df = pd.DataFrame({
            "repo_path": ["r1", "r2"], "tag": ["Slippage", "DoS"],
            "status": ["Done", "Done"]})
        calib = fit_calibration(findings, truth_df, ["r1", "r2"])
        d = calib.diagnostics
        assert d["tau_sweep"], "the sweep must be recorded for format_sweep()"
        assert "upstream_macro_f1" in d
        assert calib.tau in [row["tau"] for row in d["tau_sweep"]]

    def test_roundtrip_through_dict_preserves_the_decision(self, finding_factory):
        calib = Calibration(detector_prior={"d1": 0.8}, tau=0.35,
                            verify_off_tags={"DoS"})
        back = Calibration.from_dict(calib.to_dict())
        f = finding_factory(confidence=0.9)
        assert finding_score(f, back) == pytest.approx(finding_score(f, calib))
        assert back.verify_off_tags == {"DoS"}
