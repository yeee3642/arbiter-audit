"""Label-free arm comparison.

Two things are worth guarding here. First the arithmetic, which is boring. Second
the honesty of the framing: `localisable` is an architectural consequence of the
broadcast arm's whole-file payload, not a measurement of model quality, and the
renderer has to keep saying so. A future refactor that quietly drops the `(arch)`
marker would turn a structural fact into an implied quality claim, which is
exactly the kind of overreach this project spends its first three sections
criticising upstream for.
"""

from __future__ import annotations

import json

import pytest

from bastet_cc.structural import (compare_structural, format_structural, profile,
                                  read_cost)


@pytest.fixture
def make(finding_factory):
    return finding_factory


# -- profile arithmetic ---------------------------------------------------------


def test_profile_counts_sites_not_findings(make):
    """Two detectors reporting the same function is one site, two findings."""
    fs = [make(detector_id="d1", path="A.sol", contract="A", function="f"),
          make(detector_id="d2", path="A.sol", contract="A", function="f"),
          make(detector_id="d1", path="A.sol", contract="A", function="g")]
    p = profile("run", fs)
    assert (p.n_findings, p.n_sites) == (3, 2)
    assert p.redundancy == pytest.approx(1.5)
    assert p.n_detectors == 2


def test_offtarget_share_counts_vendor_and_nonprod(make):
    fs = [make(path="contracts/Vault.sol"),
          make(path="contracts/mocks/MockERC20.sol"),
          make(path="lib/openzeppelin/ERC20.sol"),
          make(path="test/Vault.t.sol")]
    p = profile("run", fs)
    assert p.by_file_class["core"] == 1
    assert p.offtarget_share == pytest.approx(0.75)


def test_localisable_share_reads_the_unmatched_marker(make):
    fs = [make(evidence="L1-L2"),
          make(evidence="L3-L4 [unmatched]"),
          make(evidence="L5-L6 [unmatched]")]
    assert profile("run", fs).localisable_share == pytest.approx(1 / 3)


def test_empty_arm_reports_none_not_zero(make):
    """A share of 0.0 and "no findings at all" must not render identically."""
    p = profile("run", [])
    assert p.n_findings == 0
    assert p.redundancy is None
    assert p.offtarget_share is None
    assert p.localisable_share is None


# -- cost -----------------------------------------------------------------------


def test_read_cost_absent_artefacts_is_empty_not_zero(tmp_path):
    """A zero would render as "this arm was free"; the truth is "unknown"."""
    assert read_cost(tmp_path) == {}


def test_read_cost_reads_both_plan_and_usage(tmp_path):
    (tmp_path / "tasks.jsonl").write_text(
        json.dumps({"task_id": "t1", "code_chars": 100}) + "\n"
        + json.dumps({"task_id": "t2", "code_chars": 50}) + "\n")
    (tmp_path / "llm_log.jsonl").write_text(
        json.dumps({"input_tokens": 10, "output_tokens": 2}) + "\n"
        + json.dumps({"input_tokens": 20, "output_tokens": 3}) + "\n")
    cost = read_cost(tmp_path)
    assert cost["planned_calls"] == 2
    assert cost["code_chars"] == 150
    assert cost["actual_calls"] == 2
    assert cost["input_tokens"] == 30


def test_read_cost_survives_a_torn_line(tmp_path):
    (tmp_path / "tasks.jsonl").write_text(
        json.dumps({"code_chars": 10}) + "\n" + '{"code_ch')
    assert read_cost(tmp_path)["planned_calls"] == 1


# -- comparison -----------------------------------------------------------------


def test_site_agreement_restricted_to_shared_repos(make):
    """A repo only one arm scanned is a scope difference, not a disagreement."""
    a = [make(repo="r1", function="f"), make(repo="r2", function="z")]
    b = [make(repo="r1", function="f"), make(repo="r1", function="g")]
    res = compare_structural(profile("a", a), profile("b", b), a, b)

    assert res["shared_repos"] == ["r1"]
    assert res["repos_only_in_a"] == ["r2"]
    assert res["sites"] == {"both": 1, "only_a": 0, "only_b": 1,
                            "jaccard": pytest.approx(0.5)}


def test_disjoint_repos_is_flagged_not_scored(make):
    a = [make(repo="r1")]
    b = [make(repo="r2")]
    res = compare_structural(profile("a", a), profile("b", b), a, b)
    assert res["comparable"] is False
    assert res["sites"]["jaccard"] is None


def test_tag_asymmetry_is_reported_per_side(make):
    a = [make(repo="r1", tag="Reentrancy"), make(repo="r1", tag="DoS")]
    b = [make(repo="r1", tag="ERC20"), make(repo="r1", tag="DoS")]
    res = compare_structural(profile("a", a), profile("b", b), a, b)
    assert res["tags"] == {"both": ["DoS"], "only_a": ["Reentrancy"],
                           "only_b": ["ERC20"]}


# -- rendering ------------------------------------------------------------------


def test_renderer_marks_the_architectural_row_and_disclaims_ranking(make):
    a = [make(repo="r1", evidence="L1")]
    b = [make(repo="r1", evidence="L1 [unmatched]")]
    text = format_structural(
        compare_structural(profile("a", a), profile("b", b), a, b), "routed", "broadcast")

    localisable = next(l for l in text.splitlines() if "localisable" in l)
    assert "(arch)" in localisable
    assert "does not rank" in text or "No row here ranks" in text


def test_renderer_shows_na_for_an_empty_arm(make):
    a = [make(repo="r1")]
    text = format_structural(
        compare_structural(profile("a", a), profile("b", []), a, []), "routed", "empty")
    assert "n/a" in text


def test_renderer_columns_do_not_abut(make):
    """Long run ids must not run together into an unreadable header."""
    a = [make(repo="r1")]
    text = format_structural(
        compare_structural(profile("a", a), profile("b", a), a, a),
        "d1_routed_dev1", "d1_broadcast_dev1")
    header = text.splitlines()[0]
    assert "d1_routed_dev1d1_broadcast_dev1" not in header
    assert "d1_routed_dev1" in header and "d1_broadcast_dev1" in header


def test_renderer_omits_cost_rows_when_unknown(make):
    a = [make(repo="r1")]
    text = format_structural(
        compare_structural(profile("a", a), profile("b", a), a, a), "a", "b")
    assert "LLM calls" not in text
