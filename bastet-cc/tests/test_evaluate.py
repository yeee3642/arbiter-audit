"""The scorer's arithmetic, and the fidelity of the upstream replica.

Two different obligations. `Confusion` must be correct -- every headline number
passes through it. `upstream_sample` must be *faithfully wrong*: it reproduces
three defects on purpose, and a test that asserted correct behaviour there would
be asserting that the control arm has stopped being a control.
"""

from __future__ import annotations

import pandas as pd
import pytest

from bastet_cc.evaluate import (Confusion, TagSample, build_sample, normalize_tag,
                                parse_tags, score, score_all, upstream_sample)


class TestConfusion:
    def test_counts_route_to_the_right_cell(self):
        cm = Confusion()
        cm.add(True, True); cm.add(True, False)
        cm.add(False, True); cm.add(False, False)
        assert (cm.tp, cm.fp, cm.fn, cm.tn) == (1, 1, 1, 1)
        assert cm.n == 4

    def test_precision_is_none_not_zero_when_nothing_predicted(self):
        # A detector that never fires has undefined precision. Reporting 0.0
        # would make it indistinguishable from one that fires and is always
        # wrong -- and upstream's eval.py raises ZeroDivisionError here.
        cm = Confusion(tp=0, fp=0, fn=5, tn=5)
        assert cm.precision is None
        assert cm.recall == 0.0

    def test_recall_is_none_when_no_positives_exist(self):
        cm = Confusion(tp=0, fp=3, fn=0, tn=7)
        assert cm.recall is None
        assert cm.precision == 0.0

    def test_f1_matches_the_textbook_definition(self):
        cm = Confusion(tp=3, fp=1, fn=2, tn=4)
        p, r = 3 / 4, 3 / 5
        assert cm.f1 == pytest.approx(2 * p * r / (p + r))

    def test_f1_is_none_on_an_empty_matrix(self):
        assert Confusion().f1 is None

    def test_constant_yes_on_a_balanced_sample_scores_two_thirds(self):
        # The floor the whole instrument audit rests on. If this ever changes,
        # the null-model argument in the README changes with it.
        n = 29
        cm = Confusion(tp=n, fp=n, fn=0, tn=0)
        assert cm.f1 == pytest.approx(2 / 3)
        assert cm.accuracy == pytest.approx(0.5)

    def test_constant_yes_degrades_as_the_sample_unbalances(self):
        # Upstream's sampler forces 50/50, which is the balance point where a
        # constant answer scores highest. Away from it the floor collapses.
        f1s = [Confusion(tp=p, fp=n, fn=0, tn=0).f1 for p, n in
               ((29, 29), (17, 29), (10, 40), (5, 45))]
        assert f1s == sorted(f1s, reverse=True)
        assert f1s[0] == pytest.approx(0.667, abs=1e-3)
        assert f1s[-1] == pytest.approx(0.182, abs=1e-3)


class TestTagParsing:
    def test_multi_label_cells_split_on_comma(self):
        assert parse_tags("Slippage, Logic error") == {"Slippage", "Logic error"}

    def test_whitespace_variants_collapse(self):
        assert parse_tags(" DoS ,Reentrancy ") == {"DoS", "Reentrancy"}

    def test_nan_is_empty_not_a_crash(self):
        assert parse_tags(float("nan")) == set()
        assert parse_tags(None) == set()

    def test_casing_variant_folds(self):
        assert normalize_tag("logic error") == "Logic Error"
        assert normalize_tag("Logic Error") == "Logic Error"

    def test_unknown_tag_passes_through_stripped(self):
        assert normalize_tag("  Novel Thing ") == "Novel Thing"


@pytest.fixture
def multilabel_df():
    # r1 is tagged "Slippage, Logic error" -- the row that upstream's sampler
    # draws as a Slippage *negative* and then labels positive.
    return pd.DataFrame({
        "repo_path": ["r1", "r2", "r3", "r4"],
        "tag": ["Slippage, Logic error", "Slippage", "DoS", "DoS, Reentrancy"],
        "status": ["Done"] * 4,
    })


class TestCorrectedSampling:
    def test_membership_not_containment(self, multilabel_df):
        s = build_sample(multilabel_df, "Slippage", sample_size=10, seed=0)
        assert set(s.positives) == {"r1", "r2"}
        assert set(s.negatives) == {"r3", "r4"}

    def test_sampling_is_seeded_and_reproducible(self, multilabel_df):
        a = build_sample(multilabel_df, "Slippage", sample_size=1, seed=7)
        b = build_sample(multilabel_df, "Slippage", sample_size=1, seed=7)
        assert (a.positives, a.negatives) == (b.positives, b.negatives)

    def test_empty_sample_when_a_tag_has_no_positives(self, multilabel_df):
        s = build_sample(multilabel_df, "Nonexistent", sample_size=10, seed=0)
        assert s.repos == []

    def test_missing_repo_scores_as_no_finding(self):
        s = TagSample(tag="T", positives=["a"], negatives=["b"])
        cm = score(s, predictions={})
        assert (cm.tp, cm.fn, cm.tn) == (0, 1, 1)

    def test_pooling_sums_matrices_rather_than_averaging_f1(self):
        samples = {
            "big": TagSample("big", positives=["a", "b"], negatives=["c", "d"]),
            "tiny": TagSample("tiny", positives=["e"], negatives=["f"]),
        }
        preds = {"big": {"a": True, "b": True}, "tiny": {"f": True}}
        out = score_all(samples, preds)
        # 2 TP + 0 FP from big, 0 TP + 1 FP from tiny.
        assert out["pooled"]["tp"] == 2
        assert out["pooled"]["fp"] == 1
        assert out["n_tags_evaluable"] == 2


class TestUpstreamReplicaIsFaithfullyWrong:
    """These assert that known defects are still reproduced.

    If one starts failing, either upstream's eval.py was fixed (update the
    replica and say so) or the replica drifted (fix it) -- but the two must not
    silently diverge, because the whole A/B rests on scoring both arms under the
    same broken ruler.
    """

    def test_negative_pool_is_contaminated_by_multi_label_rows(self):
        # Constructed so the multi-label row is the *only* candidate negative:
        # asserting on a random draw from several negatives would make the test
        # depend on the seed rather than on the defect.
        df = pd.DataFrame({
            "repo_path": ["r1", "r2"],
            "tag": ["Slippage, Logic error", "Slippage"],
            "status": ["Done", "Done"],
        })
        rows = upstream_sample(df, "Slippage", sample_size=10, seed=0)
        labels = {repo: label for repo, label in rows}
        # r1 is drawn as a negative (`!= "Slippage"`) and then labelled positive
        # (`"Slippage" in "Slippage, Logic error"`). One row, both pools.
        assert labels["r1"] == 1, "multi-label row must be drawn negative, labelled positive"
        assert labels["r2"] == 1
        # Every sampled row is labelled positive, so a scanner answering "yes"
        # everywhere is unbeatable on this tag -- the contamination is not
        # cosmetic, it removes the negative class entirely.
        assert set(labels.values()) == {1}

    def test_positive_pool_loses_every_multi_tag_positive(self, multilabel_df):
        rows = upstream_sample(multilabel_df, "Slippage", sample_size=10, seed=0)
        # Only r2 has the exact string "Slippage", so the tagged pool has size 1
        # and min() caps the whole sample at 1 per class.
        assert len(rows) == 2

    def test_status_filter_is_exact_match_like_upstream(self):
        df = pd.DataFrame({"repo_path": ["a", "b"], "tag": ["T", "U"],
                           "status": ["done", "Done"]})
        rows = upstream_sample(df, "T", sample_size=10, seed=0)
        # upstream compares == "Done", so lowercase "done" is dropped entirely,
        # leaving no positives and therefore no sample.
        assert rows == []

    def test_replica_is_seeded_even_though_upstream_is_not(self, multilabel_df):
        a = upstream_sample(multilabel_df, "Slippage", 10, seed=3)
        b = upstream_sample(multilabel_df, "Slippage", 10, seed=3)
        c = upstream_sample(multilabel_df, "Slippage", 10, seed=4)
        assert a == b
        assert isinstance(c, list)
