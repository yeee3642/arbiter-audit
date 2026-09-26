"""The figure driver on a fresh clone, and the two stale-input bugs it carried.

`figures` is documented as needing no API key, so it has to work for someone who
just cloned the repository and holds neither the corpus nor train.csv. It did
not: the coverage figure's ground-truth lookup was a bare `next()` over two paths
that are both absent on a clone, so the whole command died on StopIteration after
rebuilding nothing.

The other two bugs were the same species as the one this project criticises
upstream for -- an artefact left behind when the narrative moved on:

- the null-floor figure hardcoded four re-run F1s while runs.jsonl had grown to
  five, so the figure and summary.json disagreed on the sample size;
- the cost ladder still rendered "1.7 s per call, N-way concurrency" after the
  README had disowned exactly that estimate, and it is the figure a reader looks
  at rather than the paragraph.

These tests do not check that the plots are pretty. They check that the driver
reads its inputs from disk and degrades honestly.
"""

from __future__ import annotations

import json
import re

import pytest

matplotlib = pytest.importorskip("matplotlib")

from bastet_cc import report


def _svg_text(path) -> str:
    """Matplotlib mirrors every text object into an SVG comment; read those."""
    raw = path.read_text(encoding="utf-8")
    return "\n".join(re.findall(r"<!-- (.*?) -->", raw, re.DOTALL))


# -- degradation without ground truth -------------------------------------------


def test_build_all_skips_only_the_coverage_figure(tmp_path, monkeypatch, capsys):
    """No train.csv anywhere: five figures, not a crash."""
    monkeypatch.setattr(report, "REPO_ROOT", report.REPO_ROOT)   # explicit no-op
    written = report.build_all(tmp_path)

    names = {p.stem.replace(".dark", "") for p in written}
    assert "fig5_coverage_gap" not in names
    for expected in ("fig1_measurement_audit", "fig2_null_floor",
                     "fig3_metric_flip", "fig4_balance_sensitivity",
                     "fig6_cost_ladder"):
        assert expected in names, f"{expected} was not rebuilt"

    assert "skipped fig5_coverage_gap" in capsys.readouterr().out


def test_build_all_writes_both_light_and_dark(tmp_path):
    written = report.build_all(tmp_path)
    assert any(".dark" in p.name for p in written)
    assert any(".dark" not in p.name for p in written)


# -- the cost ladder no longer asserts a latency it cannot measure ---------------


def test_cost_ladder_caption_uses_the_measured_rate_cap(tmp_path):
    stages = [("upstream", 344_008, 535_000_000),
              ("filtered", 112_616, 246_039_484),
              ("routed", 42_866, 60_731_740)]
    written = report.fig_cost_ladder(stages, rpm=120, recall_loss=0.016,
                                    mode="light", outdir=tmp_path)
    text = _svg_text(next(p for p in written if p.suffix == ".svg"))

    assert "120/min" in text
    assert "regardless of concurrency" in text
    # The disowned estimate must not come back.
    assert "1.7 s" not in text
    assert "way concurrency" not in text


def test_cost_ladder_hours_divide_by_the_cap(tmp_path):
    """344,008 calls at 120/min is 47.8 h; 42,866 is 5.95 h."""
    stages = [("upstream", 344_008, 535_000_000), ("routed", 42_866, 60_731_740)]
    written = report.fig_cost_ladder(stages, rpm=120, mode="light", outdir=tmp_path)
    text = _svg_text(next(p for p in written if p.suffix == ".svg"))
    assert "48 h" in text          # 47.8 rounded to whole hours
    assert "6.0 h" in text


def test_gateway_rpm_matches_the_probe_artifact():
    """The constant is a measurement, so it must agree with the 429 body on disk."""
    probe = report.REPO_ROOT / "runs" / "probe" / "phase7_sustained_w32.json"
    if not probe.exists():                          # pragma: no cover
        pytest.skip("probe artefact absent")
    body = probe.read_text(encoding="utf-8")
    assert f"Current limit: {report.GATEWAY_RPM}" in body


# -- the null-floor figure reads its draws rather than carrying them -------------


def test_null_floor_rerun_count_matches_the_artifact(tmp_path):
    """The figure's sample size must equal the number of rows in runs.jsonl."""
    runs = report.REPO_ROOT / "runs" / "upstream_null" / "runs.jsonl"
    if not runs.exists():                           # pragma: no cover
        pytest.skip("null-test artefact absent")
    on_disk = [json.loads(l) for l in runs.read_text().splitlines() if l.strip()]
    n_expected = sum(1 for r in on_disk if r.get("f1") is not None)

    summary = json.loads(
        (report.REPO_ROOT / "runs" / "upstream_null" / "summary.json").read_text())
    assert summary["n_runs"] == n_expected, (
        "summary.json is stale relative to runs.jsonl; rerun "
        "scripts/upstream_null_test.py --analyse")

    # And the driver must pass that many draws to the figure, not a frozen list.
    src = (report.REPO_ROOT / "bastet_cc" / "report.py").read_text(encoding="utf-8")
    assert "reruns=[0.5556" not in src, "re-run F1s are hardcoded again"
    assert "reruns=reruns" in src
