"""Paired inference: exact values, and the refusals.

Half of these check arithmetic against hand-computable binomial values. The
other half check that the module *declines* to produce a number when the design
cannot support one -- which is the behaviour that distinguishes this from the
n=4 bootstrap it replaces.
"""

from __future__ import annotations

import math

import pytest

from bastet_cc.stats import (MIN_BOOTSTRAP_N, binom_two_sided_p, describe_paired,
                             format_mcnemar, mcnemar, mde, paired_bootstrap, _z)


class TestExactBinomial:
    @pytest.mark.parametrize("b,n,expected", [
        (0, 0, 1.0),
        (0, 10, 0.001953125),        # 2 * (1/1024)
        (10, 10, 0.001953125),       # symmetric
        (5, 10, 1.0),                # dead centre
        (8, 10, 0.109375),           # 2 * (45+10+1)/1024
        (1, 5, 0.375),               # 2 * (1+5)/32
    ])
    def test_matches_hand_computed_values(self, b, n, expected):
        assert binom_two_sided_p(b, n) == pytest.approx(expected)

    def test_is_symmetric_in_b(self):
        for n in range(1, 25):
            for b in range(n + 1):
                assert binom_two_sided_p(b, n) == pytest.approx(
                    binom_two_sided_p(n - b, n))

    def test_never_exceeds_one(self):
        assert all(binom_two_sided_p(b, n) <= 1.0
                   for n in range(0, 30) for b in range(n + 1))


class TestInverseNormal:
    @pytest.mark.parametrize("p,expected", [
        (0.975, 1.959963984540054),
        (0.80, 0.8416212335729143),
        (0.5, 0.0),
        (0.025, -1.959963984540054),
    ])
    def test_known_quantiles(self, p, expected):
        assert _z(p) == pytest.approx(expected, abs=1e-6)

    def test_extreme_tails_stay_finite(self):
        assert math.isfinite(_z(1e-8)) and math.isfinite(_z(1 - 1e-8))

    def test_rejects_out_of_range(self):
        with pytest.raises(ValueError):
            _z(0.0)


class TestMcNemar:
    def test_concordant_pairs_are_ignored(self):
        a = mcnemar([(True, False)] * 3 + [(False, True)] * 1)
        b = mcnemar([(True, False)] * 3 + [(False, True)] * 1
                    + [(True, True)] * 500 + [(False, False)] * 500)
        assert a.p_value == b.p_value
        assert a.discordant == b.discordant == 4
        assert b.n_pairs == 1004

    def test_perfect_agreement_is_not_significant(self):
        m = mcnemar([(True, True)] * 50)
        assert m.discordant == 0
        assert m.p_value == 1.0
        assert m.odds_ratio is None

    def test_one_sided_sweep_is_significant(self):
        m = mcnemar([(True, False)] * 10)
        assert m.b == 10 and m.c == 0
        assert m.p_value == pytest.approx(0.001953125)

    def test_odds_ratio_reports_direction(self):
        m = mcnemar([(True, False)] * 9 + [(False, True)] * 3)
        assert m.odds_ratio == pytest.approx(3.0)

    def test_symmetry_gives_p_of_one(self):
        m = mcnemar([(True, False)] * 5 + [(False, True)] * 5)
        assert m.p_value == 1.0

    def test_format_names_the_power_verdict(self):
        text = format_mcnemar(mcnemar([(True, False)] * 9 + [(False, True)]))
        assert "under-powered" in text
        text2 = format_mcnemar(mcnemar([(True, False)] * 60 + [(False, True)] * 10))
        assert "resolvable" in text2


class TestPower:
    def test_mde_falls_as_evidence_accumulates(self):
        values = [mde(n) for n in (5, 10, 50, 240, 1000)]
        assert values == sorted(values, reverse=True)

    def test_mde_is_a_probability(self):
        assert all(0.5 <= mde(n) <= 1.0 for n in range(1, 500))

    def test_tiny_designs_need_a_landslide(self):
        # The planning fact that decides whether the TEST scan can resolve
        # anything: with ten disagreements you need to win better than 94%.
        assert mde(10) > 0.94

    def test_realistic_design_is_workable(self):
        # 12 TEST repos x ~20 tags = 240 decisions; if most are discordant the
        # design can see a 59/41 split.
        assert mde(240) == pytest.approx(0.590, abs=0.01)

    def test_zero_discordant_is_unresolvable(self):
        assert mde(0) == 1.0


class TestBootstrapRefusals:
    def test_refuses_below_the_threshold(self):
        with pytest.raises(ValueError, match="below MIN_BOOTSTRAP_N"):
            paired_bootstrap([0.6] * 4, [0.5] * 4)

    def test_error_explains_why_rather_than_just_failing(self):
        try:
            paired_bootstrap([0.6] * 4, [0.5] * 4)
        except ValueError as e:
            assert "bounded by their range" in str(e)

    def test_accepts_at_the_threshold(self):
        iv = paired_bootstrap([0.6] * MIN_BOOTSTRAP_N, [0.5] * MIN_BOOTSTRAP_N)
        assert iv.n == MIN_BOOTSTRAP_N
        assert iv.point == pytest.approx(0.1)

    def test_rejects_misaligned_sequences(self):
        with pytest.raises(ValueError, match="equal-length"):
            paired_bootstrap([1.0] * 10, [1.0] * 9)

    def test_is_seeded(self):
        a = paired_bootstrap(list(range(12)), [0.0] * 12)
        b = paired_bootstrap(list(range(12)), [0.0] * 12)
        assert (a.lo, a.hi) == (b.lo, b.hi)

    def test_identical_arms_give_an_interval_containing_zero(self):
        iv = paired_bootstrap([0.5] * 12, [0.5] * 12)
        assert iv.point == 0.0
        assert not iv.excludes_zero


class TestDescribePaired:
    def test_degrades_to_raw_differences_at_small_n(self):
        out = describe_paired([0.6, 0.7, 0.5, 0.8], [0.5, 0.5, 0.5, 0.5])
        assert out["bootstrap"] is None
        assert "bootstrap_declined" in out
        assert len(out["differences"]) == 4
        assert out["wins"] == 3 and out["ties"] == 1

    def test_sign_test_is_available_at_any_n(self):
        out = describe_paired([1.0] * 5, [0.0] * 5)
        assert out["sign_test_p"] == pytest.approx(0.0625)

    def test_ties_are_excluded_from_the_sign_test(self):
        out = describe_paired([1.0, 1.0, 0.5], [0.0, 0.0, 0.5])
        assert out["wins"] == 2 and out["losses"] == 0 and out["ties"] == 1
        assert out["sign_test_p"] == pytest.approx(0.5)   # 2 of 2, not 2 of 3

    def test_bootstrap_appears_once_n_allows(self):
        out = describe_paired([0.6] * 12, [0.5] * 12)
        assert out["bootstrap"] is not None
        assert out["bootstrap"]["n"] == 12
