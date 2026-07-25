"""Report emitters, and the provenance rule that keeps SARIF honest.

The load-bearing tests here are about where a line number came from. A first cut
of `line_span` fell back to parsing `evidence` when the parser-backed fields were
absent -- and `evidence` is written by the model. The effect showed up immediately:
the broadcast arm, which sends whole files and cannot localise anything by
construction, reported 100% localised findings and got SARIF regions for all 90 of
them. An unverified model assertion had been laundered into the same return value
as a parsed fact, and then into a line annotation on somebody's pull request.

So provenance is three-valued and every emitter has to say which it has:

  parser  start_line came from the tree-sitter index -> annotate the line
  site    the function resolved, the line range is the model's claim -> annotate,
          labelled, because a reviewer two lines off still finds it by name
  none    only the file is known -> file-level result, never `startLine: 1`
"""

from __future__ import annotations

import json

import pytest

from bastet_cc.emit import (SUPPRESSED_VERDICTS, gate_summary, to_json, to_markdown,
                            to_sarif)
from bastet_cc.findings import asserted_span, is_bound, line_span, localisation


@pytest.fixture
def make(finding_factory):
    return finding_factory


# -- provenance -----------------------------------------------------------------


def test_parser_span_wins_over_the_models_claim(make):
    f = make(evidence="L99-L120", start_line=10, end_line=20)
    assert localisation(f) == "parser"
    assert line_span(f) == (10, 20)
    assert asserted_span(f) == (99, 120)      # still readable, just not preferred


def test_line_span_never_falls_back_to_evidence(make):
    """The regression that mattered: no laundering of model output."""
    f = make(evidence="L50-L52")              # no start_line
    assert line_span(f) is None
    assert asserted_span(f) == (50, 52)
    assert localisation(f) == "site"


def test_unmatched_evidence_is_not_localised_at_all(make):
    f = make(evidence="L115-L135 [unmatched]")
    assert is_bound(f) is False
    assert localisation(f) == "none"
    assert line_span(f) is None


def test_single_line_reference_expands_to_a_span(make):
    assert asserted_span(make(evidence="L42")) == (42, 42)


def test_reversed_span_is_normalised(make):
    assert line_span(make(start_line=30, end_line=10)) == (30, 30)


def test_no_line_information_anywhere(make):
    assert asserted_span(make(evidence="see the withdraw function")) is None


# -- SARIF ----------------------------------------------------------------------


def test_sarif_is_wellformed(make):
    log = to_sarif([make()])
    assert log["version"] == "2.1.0"
    assert log["runs"][0]["tool"]["driver"]["name"] == "Bastet-CC"
    assert len(log["runs"][0]["results"]) == 1
    json.dumps(log)                            # must be serialisable


def test_file_level_result_has_no_region(make):
    """A `startLine: 1` here would be a location a reviewer chases for nothing."""
    log = to_sarif([make(evidence="L115-L135 [unmatched]")])
    phys = log["runs"][0]["results"][0]["locations"][0]["physicalLocation"]
    assert "region" not in phys
    assert phys["artifactLocation"]["uri"] == "A.sol"
    assert log["runs"][0]["results"][0]["properties"]["localisation"] == "none"


def test_parser_backed_result_gets_the_parsed_region(make):
    log = to_sarif([make(start_line=10, end_line=20, evidence="L99")])
    region = log["runs"][0]["results"][0]["locations"][0]["physicalLocation"]["region"]
    assert region == {"startLine": 10, "endLine": 20}


def test_asserted_region_is_emitted_but_labelled(make):
    log = to_sarif([make(evidence="L50-L52")])
    res = log["runs"][0]["results"][0]
    assert res["locations"][0]["physicalLocation"]["region"]["startLine"] == 50
    assert res["properties"]["localisation"] == "site"
    assert "model's own claim" in res["message"]["text"]


def test_run_properties_count_each_provenance(make):
    log = to_sarif([
        make(start_line=1, end_line=2),                 # parser
        make(evidence="L5"),                            # site
        make(evidence="L9 [unmatched]"),                # none
    ])
    assert log["runs"][0]["properties"]["localisation"] == {
        "parser": 1, "site": 1, "none": 1}


def test_one_rule_per_detector(make):
    log = to_sarif([make(detector_id="d1"), make(detector_id="d1"),
                    make(detector_id="d2")])
    rules = log["runs"][0]["tool"]["driver"]["rules"]
    assert [r["id"] for r in rules] == ["d1", "d2"]


def test_detector_help_becomes_the_rule_description(make):
    log = to_sarif([make(detector_id="d1")],
                   detector_help={"d1": "Full prompt text for d1."})
    rule = log["runs"][0]["tool"]["driver"]["rules"][0]
    assert rule["fullDescription"]["text"] == "Full prompt text for d1."


def test_severity_maps_to_github_levels(make):
    levels = {}
    for sev in ("High", "Medium", "Low"):
        log = to_sarif([make(severity=sev)])
        levels[sev] = log["runs"][0]["results"][0]["level"]
    assert levels == {"High": "error", "Medium": "warning", "Low": "note"}


def test_fingerprint_ignores_wording_and_line_drift(make):
    """A reworded description or shifted code must not reopen a dismissed alert."""
    a = make(description="original wording", start_line=10, end_line=20)
    b = make(description="completely rewritten", start_line=80, end_line=90)
    fp = lambda f: to_sarif([f])["runs"][0]["results"][0]["partialFingerprints"]
    assert fp(a) == fp(b)


def test_fingerprint_separates_different_sites(make):
    a = make(function="withdraw")
    b = make(function="deposit")
    fp = lambda f: to_sarif([f])["runs"][0]["results"][0]["partialFingerprints"]
    assert fp(a) != fp(b)


def test_rejected_findings_are_excluded_by_default(make):
    log = to_sarif([make(verdict="rejected"), make(verdict="confirmed")])
    assert len(log["runs"][0]["results"]) == 1


def test_uncertain_findings_are_kept(make):
    """"We could not settle this" is actionable; "we refuted this" is not."""
    assert "uncertain" not in SUPPRESSED_VERDICTS
    log = to_sarif([make(verdict="uncertain")])
    assert len(log["runs"][0]["results"]) == 1


def test_included_suppressed_findings_are_marked(make):
    log = to_sarif([make(verdict="rejected")], include_suppressed=True)
    res = log["runs"][0]["results"][0]
    assert res["suppressions"][0]["justification"] == "verdict=rejected"


def test_empty_input_is_a_valid_empty_log():
    log = to_sarif([])
    assert log["runs"][0]["results"] == []
    assert log["runs"][0]["tool"]["driver"]["rules"] == []


# -- Markdown -------------------------------------------------------------------


def test_markdown_orders_by_severity(make):
    md = to_markdown([make(severity="Low", function="lo"),
                      make(severity="High", function="hi")])
    assert md.index("| High |") < md.index("| Low |")


def test_markdown_states_the_provenance_split(make):
    md = to_markdown([make(start_line=1, end_line=2), make(evidence="L5"),
                      make(evidence="L9 [unmatched]")])
    assert "1 exact (parser-backed)" in md
    assert "model-asserted" in md
    assert "file-level only" in md


def test_markdown_flags_an_asserted_line_inline(make):
    md = to_markdown([make(evidence="L50-L52")])
    assert "A.sol:50?" in md            # the ? marks it unverified
    assert "was not verified" in md


def test_markdown_permalinks_when_given_a_repo_url(make):
    md = to_markdown([make(start_line=10, end_line=20)],
                     repo_url="https://github.com/o/r/blob/main")
    assert "https://github.com/o/r/blob/main/A.sol#L10-L20" in md


def test_markdown_empty_is_not_a_scary_report():
    assert "No findings." in to_markdown([])


# -- JSON and the gate ----------------------------------------------------------


def test_json_roundtrips(make):
    data = json.loads(to_json([make(function="f")]))
    assert data[0]["function"] == "f"


def test_gate_fails_on_high_by_default(make):
    s = gate_summary([make(severity="High")])
    assert s["passed"] is False and s["blocking"] == 1


def test_gate_passes_when_only_lower_severities(make):
    s = gate_summary([make(severity="Medium"), make(severity="Low")])
    assert s["passed"] is True and s["blocking"] == 0


def test_gate_never_fails_on_a_refuted_finding(make):
    """Failing a build on a finding our own verifier rejected gets gates disabled."""
    s = gate_summary([make(severity="High", verdict="rejected")])
    assert s["passed"] is True
    assert s["suppressed"] == 1
    assert s["total"] == 0


def test_gate_with_no_fail_levels_always_passes(make):
    assert gate_summary([make(severity="High")], fail_on=())["passed"] is True


def test_gate_reports_the_provenance_split(make):
    s = gate_summary([make(start_line=1, end_line=2), make(evidence="L9 [unmatched]")])
    assert s["localisation"] == {"parser": 1, "none": 1}
