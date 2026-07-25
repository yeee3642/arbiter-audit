"""Presentation figures for the AIS3 2026 write-up.

Every claim this project makes about upstream Bastet is a *measurement* claim, and a
measurement claim that only exists as a number in a table gets argued with. Rendered
side by side -- a perfect predictor scoring 0.901, the whole system landing on top of
"always say yes", the same confusion matrix producing opposite verdicts under two
metrics -- the numbers stop being contestable.

Three rules hold across every function here:

- **Data enters through parameters.** The `load_*` helpers know where the CSVs live;
  the `fig_*` functions know nothing but their arguments, so a figure can be redrawn
  against a rerun, a different split, or a hand-built counterexample without editing
  this file. Nothing is measured here -- every number comes from a completed run.
- **Light and dark are both selected**, not flipped. The dark steps are the same eight
  hues re-stepped for the dark surface (see the dataviz palette), validated as a set
  against their own surface, because an automatic inversion puts saturated marks on
  black at the wrong lightness.
- **Identity never rests on color alone.** Two-series figures carry a legend *and*
  direct labels; the one sub-3:1 hue on the light surface (aqua) is not used for a
  mark whose value is unlabeled.

Run:  python -m bastet_cc.report      # writes runs/figures/*.{png,svg}, light + dark
"""

from __future__ import annotations

import csv
import json
from collections import Counter
from pathlib import Path

import matplotlib

matplotlib.use("Agg")  # figures are files, never an interactive window

import matplotlib.pyplot as plt
from matplotlib.lines import Line2D
from matplotlib.patches import Path as MPath  # noqa: F401  (kept for typing clarity)
from matplotlib.path import Path as _Path
from matplotlib.patches import PathPatch

REPO_ROOT = Path(__file__).resolve().parent.parent
FIGURE_DIR = REPO_ROOT / "runs" / "figures"

# The dataviz reference palette. Both columns are validated instances: the light
# triple (#2a78d6, #eb6834, #1baf7a) and its dark restep both clear every hard gate
# under --pairs all, which is the gate that matters here because several figures put
# non-adjacent marks side by side (scatter rows, split bars).
PALETTE = {
    "light": {
        "surface": "#fcfcfb",
        "plane": "#f9f9f7",
        "primary": "#0b0b0b",
        "secondary": "#52514e",
        "muted": "#898781",
        "grid": "#e1e0d9",
        "axis": "#c3c2b7",
        "s1": "#2a78d6",
        "s2": "#eb6834",
        "s3": "#1baf7a",
        "critical": "#d03b3b",
        "good": "#0ca30c",
        "track": "#ebeae4",
    },
    "dark": {
        "surface": "#1a1a19",
        "plane": "#0d0d0d",
        "primary": "#ffffff",
        "secondary": "#c3c2b7",
        "muted": "#898781",
        "grid": "#2c2c2a",
        "axis": "#383835",
        "s1": "#3987e5",
        "s2": "#d95926",
        "s3": "#199e70",
        "critical": "#d03b3b",
        "good": "#0ca30c",
        "track": "#333330",
    },
}

MODES = ("light", "dark")

# Mark specs from the dataviz skill, in points (matplotlib's unit) rather than px.
BAR_CAP_PT = 18.0       # bars never fill their slot; the leftover band is air
END_RADIUS_PT = 4.0     # rounded data-end, square at the baseline
LINE_PT = 2.0
MARKER_PT = 8.0         # >= 8px marker, worn with a 2px surface ring
SURFACE_GAP_PT = 2.0


# --------------------------------------------------------------------------- chrome


def _new_fig(mode: str, figsize: tuple[float, float], nrows: int = 1, ncols: int = 1):
    """A figure already wearing the mode's surface, ink, and hairline chrome."""
    c = PALETTE[mode]
    fig, axes = plt.subplots(nrows, ncols, figsize=figsize, facecolor=c["surface"])
    for ax in (axes.ravel() if hasattr(axes, "ravel") else [axes]):
        ax.set_facecolor(c["surface"])
        ax.tick_params(colors=c["muted"], labelsize=9.5, length=0)
        for side in ("top", "right", "left", "bottom"):
            ax.spines[side].set_visible(False)
    return fig, axes, c


def _grid(ax, c, axis: str = "x"):
    """Hairline, solid, one step off the surface -- never dashed, never in front."""
    ax.grid(axis=axis, color=c["grid"], linewidth=0.8, linestyle="-")
    ax.set_axisbelow(True)


def _title(fig, c, title: str, subtitle: str, y: float = 0.985):
    fig.text(0.012, y, title, ha="left", va="top", fontsize=16.5, fontweight="600",
             color=c["primary"])
    fig.text(0.012, y - 0.045, subtitle, ha="left", va="top", fontsize=11.5,
             color=c["secondary"], wrap=True)


def _footnote(fig, c, text: str, y: float = 0.012):
    fig.text(0.012, y, text, ha="left", va="bottom", fontsize=8.5, color=c["muted"])


def _px_per_data(ax) -> tuple[float, float]:
    """Data units per point, needed to size a corner radius that is fixed on screen."""
    ax.figure.canvas.draw()
    bb = ax.get_window_extent()
    dpi = ax.figure.dpi
    x0, x1 = ax.get_xlim()
    y0, y1 = ax.get_ylim()
    return ((x1 - x0) / bb.width * dpi / 72.0, (y1 - y0) / bb.height * dpi / 72.0)


def _round_end_bar(ax, base, value, centre, thickness, color, horizontal=True,
                   radius_pt=END_RADIUS_PT, **kw):
    """One bar: square where it meets the baseline, 4pt-rounded at the data end.

    matplotlib has no per-corner radius, so the outline is built as an explicit path.
    The radius is converted from points at call time, which is why callers set the
    axis limits before drawing bars -- a later limit change would skew the corners.
    """
    ux, uy = _px_per_data(ax)
    half = thickness / 2.0
    if horizontal:
        r = min(radius_pt * ux, abs(value - base) * 0.9, half * 0.95)
        s = 1.0 if value >= base else -1.0
        lo, hi = centre - half, centre + half
        v = [(base, lo), (value - s * r, lo), (value, lo), (value, lo + r),
             (value, hi - r), (value, hi), (value - s * r, hi), (base, hi), (base, lo)]
    else:
        r = min(radius_pt * uy, abs(value - base) * 0.9, half * 0.95)
        s = 1.0 if value >= base else -1.0
        lo, hi = centre - half, centre + half
        v = [(lo, base), (lo, value - s * r), (lo, value), (lo + r, value),
             (hi - r, value), (hi, value), (hi, value - s * r), (hi, base), (lo, base)]
    codes = [_Path.MOVETO, _Path.LINETO, _Path.CURVE3, _Path.CURVE3,
             _Path.LINETO, _Path.CURVE3, _Path.CURVE3, _Path.LINETO, _Path.CLOSEPOLY]
    patch = PathPatch(_Path(v, codes), facecolor=color, edgecolor="none", **kw)
    ax.add_patch(patch)
    return patch


def _thickness(ax, n_slots: int, span: float, cap_pt: float = BAR_CAP_PT) -> float:
    """Bar thickness in data units, capped so wide plots keep thin marks."""
    _, uy = _px_per_data(ax)
    return min(span / n_slots * 0.62, cap_pt * uy)


def save(fig, name: str, outdir: Path, mode: str) -> list[Path]:
    """PNG for slides, SVG for anything that will be scaled or recolored."""
    outdir.mkdir(parents=True, exist_ok=True)
    stem = name if mode == "light" else f"{name}.dark"
    written = []
    for ext, dpi in (("png", 200), ("svg", 200)):
        p = outdir / f"{stem}.{ext}"
        fig.savefig(p, dpi=dpi, facecolor=fig.get_facecolor(), bbox_inches="tight",
                    pad_inches=0.28)
        written.append(p)
    plt.close(fig)
    return written


# ------------------------------------------------------------------------- loaders


def load_perfect_predictor(path: Path) -> list[dict]:
    rows = []
    with open(path, newline="", encoding="utf-8") as fh:
        for r in csv.DictReader(fh):
            rows.append({
                "tag": r["tag"],
                "n_pos": int(r["n_pos_repos"]),
                "f1": float(r["upstream_f1"]),
                "lo": float(r["upstream_f1_min"]),
                "hi": float(r["upstream_f1_max"]),
                "fixed": float(r["fixed_f1"]),
            })
    return rows


def load_instrument_audit(path: Path, benchmark: str) -> dict[str, dict]:
    """Confusion-matrix rows for one benchmark, keyed by predictor name."""
    out = {}
    with open(path, newline="", encoding="utf-8") as fh:
        for r in csv.DictReader(fh):
            bench, _, pred = r["predictor"].partition(" :: ")
            if bench.strip().strip('"') != benchmark:
                continue
            out[pred.strip()] = {
                k: (float(r[k]) if r[k] not in ("", None) else None)
                for k in ("precision", "recall", "f1", "accuracy",
                          "balanced_accuracy", "mcc")
            }
    return out


def load_balance_sensitivity(path: Path) -> list[tuple[int, int, float]]:
    with open(path, newline="", encoding="utf-8") as fh:
        return [(int(r["pos"]), int(r["neg"]), float(r["constant_yes_f1"]))
                for r in csv.DictReader(fh)]


def load_coverage(train_csv: Path, detector_index: Path) -> dict:
    """Tag frequencies from ground truth, crossed with which tags own a detector.

    Tag strings are normalized through `tags.canonical_tag` because train.csv writes
    both `Logic Error` and `Logic error`; counting them apart would invent a 43rd tag
    and understate the largest covered class.
    """
    from .tags import canonical_tag

    detectors = json.loads(detector_index.read_text(encoding="utf-8"))
    covered = {canonical_tag(t) for d in detectors for t in d.get("tags", [])}

    counts: Counter[str] = Counter()
    pairs: set[tuple[str, str]] = set()
    n_rows = 0
    with open(train_csv, newline="", encoding="utf-8") as fh:
        for r in csv.DictReader(fh):
            n_rows += 1
            for raw in r["tag"].split(","):
                if not raw.strip():
                    continue
                t = canonical_tag(raw)
                counts[t] += 1
                pairs.add((r["repo_path"], t))

    reachable = sum(1 for _, t in pairs if t in covered)
    return {
        "counts": counts,
        "covered": covered & set(counts),
        "n_detectors": len(detectors),
        "n_pairs": len(pairs),
        "n_findings": n_rows,
        "source": train_csv,
        "unreachable_share": 1.0 - reachable / len(pairs),
    }


def load_routing_summary(path: Path) -> dict:
    return json.loads(path.read_text(encoding="utf-8"))


# --------------------------------------------------------------------- 1. the audit


def fig_measurement_audit(rows, *, macro_f1: float, target: float = 1.0,
                          n_seeds: int = 10, mode: str = "light",
                          outdir: Path = FIGURE_DIR) -> list[Path]:
    """A perfect predictor, scored by the upstream scorer, per tag.

    The whole argument is the distance between each dot and the rule at 1.000: the
    predictor is right about every repository, so nothing below the rule can be a
    detection failure. Sorted worst-first because the worst rows are the argument.
    """
    rows = sorted(rows, key=lambda r: r["f1"])
    c = PALETTE[mode]
    fig, ax, c = _new_fig(mode, (12.4, 11.0))
    y = list(range(len(rows)))

    ax.set_xlim(0.50, 1.045)
    # headroom above the top row so the two reference labels sit in empty space
    # instead of over the marks they annotate
    ax.set_ylim(-0.8, len(rows) + 1.6)
    ax.set_yticks(y)
    ax.set_yticklabels([f"{r['tag']}  ({r['n_pos']})" for r in rows],
                       fontsize=10, color=c["secondary"])
    ax.set_xticks([0.5, 0.6, 0.7, 0.8, 0.9, 1.0])
    _grid(ax, c, "x")

    for yi, r in zip(y, rows):
        # full scale behind the mark, so a short range still reads as "how far from 1"
        ax.plot([r["f1"], target], [yi, yi], color=c["track"], lw=5.5,
                solid_capstyle="butt", zorder=1)
        ax.plot([r["lo"], r["hi"]], [yi, yi], color=c["s1"], lw=5.5, alpha=0.32,
                solid_capstyle="round", zorder=2)
        ax.plot([r["f1"]], [yi], marker="o", ms=MARKER_PT, color=c["s1"],
                markeredgecolor=c["surface"], markeredgewidth=SURFACE_GAP_PT, zorder=3)

    ax.axvline(target, color=c["primary"], lw=1.6, zorder=4)
    ax.axvline(macro_f1, color=c["s2"], lw=LINE_PT, zorder=4)

    ax.annotate(f"correct answer\n{target:.3f}", xy=(target, len(rows) + 1.5),
                xytext=(-6, 0), textcoords="offset points", ha="right", va="top",
                fontsize=10.5, fontweight="600", color=c["primary"])
    ax.annotate(f"macro-F1 actually awarded\n{macro_f1:.3f}",
                xy=(macro_f1, len(rows) + 1.5), xytext=(-8, 0),
                textcoords="offset points", ha="right", va="top", fontsize=10.5,
                fontweight="600", color=c["s2"])

    ax.legend(handles=[
        Line2D([], [], marker="o", ls="none", ms=MARKER_PT, color=c["s1"],
               markeredgecolor=c["surface"], markeredgewidth=SURFACE_GAP_PT,
               label="F1 awarded to a perfect predictor"),
        Line2D([], [], color=c["s1"], alpha=0.32, lw=5.5,
               label=f"range over {n_seeds} sampling seeds [min, max]"),
        Line2D([], [], color=c["track"], lw=5.5,
               label="measurement error (gap to 1.000)"),
    ], loc="upper left", frameon=False, fontsize=10.5, labelcolor=c["secondary"],
        handletextpad=0.9, borderaxespad=0.6)

    _title(fig, c,
           "A predictor that is right about every repository scores 0.901, not 1.000",
           "Upstream's scorer resamples negatives per tag, so the ceiling it awards is "
           "below the ceiling that exists.\nEvery point of the gap below is measurement "
           "error, not detection error — no model can recover it.")
    ax.set_xlabel("F1 awarded by the upstream scorer", fontsize=10.5,
                  color=c["secondary"], labelpad=10)
    _footnote(fig, c, "Tag label shows (number of positive repositories). "
                      "Source: runs/e6/e6_perfect_predictor.csv")
    fig.subplots_adjust(top=0.885, left=0.16, right=0.985, bottom=0.075)
    return save(fig, "fig1_measurement_audit", outdir, mode)


# ---------------------------------------------------------------------- 2. the floor


def fig_floor(*, published: float, reruns: list[float], null_f1: float,
              published_label: str = "Upstream's published F1",
              rerun_label: str = "Upstream re-run here, 4 times",
              null_label: str = 'Null model: answer "vulnerable" every time',
              mode: str = "light", outdir: Path = FIGURE_DIR) -> list[Path]:
    """Where the system lands relative to a model that has no model in it.

    Plotted on one axis with the null model as a rule rather than a fourth bar,
    because the claim is not "the null model is close" -- it is that the system does
    not clear it, which only reads if the null model is a threshold on the same scale.
    """
    mean = sum(reruns) / len(reruns)
    c = PALETTE[mode]
    fig, ax, c = _new_fig(mode, (12.0, 5.6))

    ax.set_xlim(0.50, 0.80)
    ax.set_ylim(-0.45, 2.95)
    rows = [(2, published_label), (1, rerun_label), (0, null_label)]
    ax.set_yticks([r[0] for r in rows])
    ax.set_yticklabels([r[1] for r in rows], fontsize=11, color=c["secondary"])
    ax.set_xticks([0.50, 0.55, 0.60, 0.65, 0.70, 0.75, 0.80])
    _grid(ax, c, "x")

    # A wash, not a block: the region only has to read as "at or under the floor".
    ax.axvspan(0.50, null_f1, color=c["track"], alpha=0.55, zorder=0)
    ax.axvline(null_f1, color=c["critical"], lw=2.4, zorder=5)
    ax.annotate(f"null floor {null_f1:.4f}", xy=(null_f1, 2.88), xytext=(9, 0),
                textcoords="offset points", ha="left", va="center", fontsize=11,
                fontweight="600", color=c["critical"])

    ax.plot([published], [2], marker="D", ms=MARKER_PT + 1, color=c["s2"],
            markeredgecolor=c["surface"], markeredgewidth=SURFACE_GAP_PT, zorder=6)
    ax.annotate(f"{published:.4f}", xy=(published, 2), xytext=(13, 0),
                textcoords="offset points", ha="left", va="center", fontsize=11,
                fontweight="600", color=c["primary"])

    ax.plot([min(reruns), max(reruns)], [1, 1], color=c["s1"], lw=5.5, alpha=0.30,
            solid_capstyle="round", zorder=2)
    for v in reruns:
        ax.plot([v], [1], marker="o", ms=MARKER_PT, color=c["s1"],
                markeredgecolor=c["surface"], markeredgewidth=SURFACE_GAP_PT, zorder=6)
    ax.plot([mean], [1], marker="|", ms=24, color=c["primary"], lw=2.4, zorder=7)
    # mean sits on top of the null rule, so its label goes left and the spread right
    ax.annotate(f"mean {mean:.4f}", xy=(mean, 1), xytext=(-10, 20),
                textcoords="offset points", ha="right", va="center", fontsize=11,
                fontweight="600", color=c["primary"])
    ax.annotate(f"4 runs: {min(reruns):.4f} – {max(reruns):.4f}",
                xy=(max(reruns), 1), xytext=(13, 0), textcoords="offset points",
                ha="left", va="center", fontsize=10, color=c["secondary"])

    ax.plot([null_f1], [0], marker="o", ms=MARKER_PT, color=c["critical"],
            markeredgecolor=c["surface"], markeredgewidth=SURFACE_GAP_PT, zorder=6)
    ax.annotate(f"{null_f1:.4f}", xy=(null_f1, 0), xytext=(13, 0),
                textcoords="offset points", ha="left", va="center", fontsize=11,
                fontweight="600", color=c["primary"])

    ax.legend(handles=[
        Line2D([], [], marker="D", ls="none", ms=MARKER_PT + 1, color=c["s2"],
               markeredgecolor=c["surface"], markeredgewidth=SURFACE_GAP_PT,
               label="published number"),
        Line2D([], [], marker="o", ls="none", ms=MARKER_PT, color=c["s1"],
               markeredgecolor=c["surface"], markeredgewidth=SURFACE_GAP_PT,
               label="one measured run"),
        Line2D([], [], color=c["critical"], lw=2.4, label="null-model floor"),
    ], loc="upper left", frameon=False, fontsize=10.5, labelcolor=c["secondary"],
        handletextpad=0.9, borderaxespad=0.3)

    delta = mean - null_f1
    _title(fig, c,
           "The whole pipeline is statistically indistinguishable from “always say yes”",
           "Four independent re-runs of upstream Bastet on 550B, against a predictor "
           "that reads nothing and answers “vulnerable” to every question.")
    fig.text(0.012, 0.115,
             f"Net gain of the entire system over the null model: {delta:+.4f}",
             fontsize=13.5, fontweight="600", color=c["critical"])
    ax.set_xlabel("F1", fontsize=10.5, color=c["secondary"], labelpad=10)
    _footnote(fig, c, "Shaded region is at or below the null floor. "
                      "Source: runs/instrument/instrument_audit.csv, runs/upstream_null.",
              y=0.025)
    fig.subplots_adjust(top=0.80, left=0.285, right=0.985, bottom=0.29)
    return save(fig, "fig2_null_floor", outdir, mode)


# ------------------------------------------------------------------- 3. metric flip


def fig_metric_flip(metrics, *, mode: str = "light",
                    outdir: Path = FIGURE_DIR) -> list[Path]:
    """One confusion matrix, four metrics, two opposite verdicts.

    `metrics` is a list of (name, null_value, system_value, note) so the caller decides
    which metrics are in scope and how an undefined value (MCC of a constant predictor)
    is substituted -- that substitution is an editorial choice, not a fact, and does not
    belong hard-coded in a plotting function.
    """
    c = PALETTE[mode]
    fig, ax, c = _new_fig(mode, (11.6, 6.6))
    n = len(metrics)
    ax.set_xlim(-0.62, n - 0.38)
    ax.set_ylim(0, 1.12)
    ax.set_xticks(range(n))
    ax.set_xticklabels([m[0] for m in metrics], fontsize=11.5, color=c["secondary"])
    ax.set_yticks([0, 0.25, 0.5, 0.75, 1.0])
    _grid(ax, c, "y")

    th = _thickness(ax, n * 2 + 1, n + 0.24)
    # The two bars of a pair can land within 0.014 of each other (that is the point of
    # the figure), so the pair is spread wide enough that two 5-character value labels
    # never collide -- the surface gap alone is not enough separation for the text.
    off = max(th / 2 + SURFACE_GAP_PT * _px_per_data(ax)[0] / 2, 0.145)
    for i, (name, null_v, sys_v, note) in enumerate(metrics):
        _round_end_bar(ax, 0, null_v, i - off, th, c["s2"], horizontal=False, zorder=3)
        _round_end_bar(ax, 0, sys_v, i + off, th, c["s1"], horizontal=False, zorder=3)
        ax.annotate(f"{null_v:.3f}", xy=(i - off, null_v), xytext=(0, 8),
                    textcoords="offset points", ha="center", fontsize=10,
                    color=c["secondary"])
        ax.annotate(f"{sys_v:.3f}", xy=(i + off, sys_v), xytext=(0, 8),
                    textcoords="offset points", ha="center", fontsize=10,
                    color=c["secondary"])
        d = sys_v - null_v
        top = max(null_v, sys_v)
        emph = i in (0, 1)  # the two metrics the story turns on get the loud label
        ax.annotate(f"{d:+.3f}", xy=(i, top), xytext=(0, 30),
                    textcoords="offset points", ha="center",
                    fontsize=13 if emph else 11,
                    fontweight="600" if emph else "normal",
                    color=c["critical"] if emph and d < 0.05 else
                    (c["primary"] if emph else c["muted"]))
        if note:
            ax.annotate(note, xy=(i, 0), xytext=(0, -34), textcoords="offset points",
                        ha="center", fontsize=8.5, color=c["muted"])

    ax.annotate("“no better than nothing”", xy=(0, 1.06), ha="center", fontsize=10.5,
                fontstyle="italic", color=c["critical"])
    ax.annotate("“a strong detector”", xy=(1, 1.06), ha="center", fontsize=10.5,
                fontstyle="italic", color=c["s1"])

    ax.legend(handles=[
        Line2D([], [], color=c["s2"], lw=9, solid_capstyle="butt",
               label="null model (constant “vulnerable”)"),
        Line2D([], [], color=c["s1"], lw=9, solid_capstyle="butt",
               label="upstream Bastet, published run"),
    ], loc="upper right", frameon=False, fontsize=10.5, labelcolor=c["secondary"],
        handletextpad=0.9, borderaxespad=0.2)

    _title(fig, c,
           "The same confusion matrix supports two opposite conclusions",
           "Identical predictions, identical ground truth — only the metric changes. "
           "The reported metric is a choice,\nand on this benchmark that choice decides "
           "the verdict.")
    ax.set_ylabel("score", fontsize=10.5, color=c["secondary"], labelpad=10)
    _footnote(fig, c, "Source: runs/instrument/instrument_audit.csv "
                      "(README benchmark, 58 questions, 29 positive).", y=0.045)
    fig.subplots_adjust(top=0.80, left=0.075, right=0.985, bottom=0.175)
    return save(fig, "fig3_metric_flip", outdir, mode)


# ------------------------------------------------------------------ 4. balance curve


def fig_balance_sensitivity(points, *, sampler_pos_share: float = 0.5,
                            mode: str = "light",
                            outdir: Path = FIGURE_DIR) -> list[Path]:
    """Null-model F1 as a function of how the benchmark is balanced.

    `points` is the measured (pos, neg, f1) table; the curve behind it is the closed
    form F1 = 2p/(1+p) for a constant-positive predictor, drawn to show the measured
    points are not five arbitrary observations but samples of a known function of the
    sampler's own configuration.
    """
    c = PALETTE[mode]
    fig, ax, c = _new_fig(mode, (11.4, 6.4))
    ax.set_xlim(0, 1.0)
    ax.set_ylim(0, 1.06)
    ax.set_xticks([0, 0.2, 0.4, 0.5, 0.6, 0.8, 1.0])
    ax.set_xticklabels(["0%", "20%", "40%", "50%", "60%", "80%", "100%"])
    ax.set_yticks([0, 0.25, 0.5, 0.75, 1.0])
    _grid(ax, c, "y")

    xs = [i / 400 for i in range(401)]
    ax.plot(xs, [2 * p / (1 + p) for p in xs], color=c["s1"], lw=LINE_PT, zorder=3)

    ax.axvline(sampler_pos_share, color=c["s2"], lw=LINE_PT, zorder=2)

    for pos, neg, f1 in points:
        share = pos / (pos + neg)
        at_sampler = abs(share - sampler_pos_share) < 1e-9
        col = c["s2"] if at_sampler else c["s1"]
        ax.plot([share], [f1], marker="o", ms=MARKER_PT + (3 if at_sampler else 0),
                color=col, markeredgecolor=c["surface"],
                markeredgewidth=SURFACE_GAP_PT, zorder=6)
        # Labels hang below-right of their dot, except left of the sampler rule, which
        # would otherwise be overprinted by the rule and its callout.
        left = share < sampler_pos_share
        ax.annotate(f"{pos}/{neg} → {f1:.3f}", xy=(share, f1),
                    xytext=(-11, -17) if left else (11, -17),
                    ha="right" if left else "left",
                    textcoords="offset points", fontsize=10.5,
                    fontweight="600" if at_sampler else "normal",
                    color=c["primary"] if at_sampler else c["secondary"])

    ax.annotate("upstream's sampler pins the benchmark here",
                xy=(sampler_pos_share, 1.02), xytext=(12, 0),
                textcoords="offset points", ha="left", va="center", fontsize=11.5,
                fontweight="600", color=c["s2"])
    ax.annotate("two-thirds of the F1 scale is handed out\nbefore any model reads any "
                "code",
                xy=(sampler_pos_share, 2 * sampler_pos_share / (1 + sampler_pos_share)),
                xytext=(0.615, 0.375), textcoords="data", ha="left", va="center",
                fontsize=11, color=c["secondary"], linespacing=1.5,
                arrowprops=dict(arrowstyle="-", color=c["axis"], lw=1.0,
                                connectionstyle="arc3,rad=-0.15"))

    ax.legend(handles=[
        Line2D([], [], color=c["s1"], lw=LINE_PT, marker="o", ms=MARKER_PT,
               markeredgecolor=c["surface"], markeredgewidth=SURFACE_GAP_PT,
               label="null-model F1 = 2p/(1+p); dots are measured"),
        Line2D([], [], color=c["s2"], lw=LINE_PT,
               label="balance the upstream sampler enforces"),
    ], loc="upper left", frameon=False, fontsize=10.5, labelcolor=c["secondary"],
        handletextpad=0.9, borderaxespad=0.6)

    _title(fig, c,
           "The benchmark's headline number is mostly a property of its sampling ratio",
           "A predictor that always answers “vulnerable” scores whatever the positive "
           "rate lets it score. Upstream forces 50/50,\nwhich sets the floor at 0.667 — "
           "close to the score the full system reports.")
    ax.set_xlabel("share of questions whose true answer is “vulnerable”",
                  fontsize=10.5, color=c["secondary"], labelpad=10)
    ax.set_ylabel("null-model F1", fontsize=10.5, color=c["secondary"], labelpad=10)
    _footnote(fig, c, "Source: runs/instrument/balance_sensitivity.csv.", y=0.03)
    fig.subplots_adjust(top=0.80, left=0.075, right=0.985, bottom=0.155)
    return save(fig, "fig4_balance_sensitivity", outdir, mode)


# ---------------------------------------------------------------- 5. coverage gap


def fig_coverage_gap(counts, covered, *, unreachable_share: float, n_detectors: int,
                     headline_share: float | None = None, headline_note: str = "",
                     source_note: str = "", n_findings: int | None = None,
                     mode: str = "light", outdir: Path = FIGURE_DIR) -> list[Path]:
    """Which tags any detector can even speak to, ordered by how often they occur.

    Split by color *and* by a labelled group, because the point is not that the
    uncovered tags are numerous -- it is that they include tags with hundreds of
    findings behind them, which only reads when frequency is the sort key.
    """
    c = PALETTE[mode]
    order = sorted(counts.items(), key=lambda kv: kv[1])
    fig, ax, c = _new_fig(mode, (12.0, 13.0))
    y = list(range(len(order)))
    vmax = max(counts.values())

    ax.set_xlim(0, vmax * 1.16)
    ax.set_ylim(-1.0, len(order) - 0.2)
    ax.set_yticks(y)
    ax.set_yticklabels([t for t, _ in order], fontsize=9.5, color=c["secondary"])
    _grid(ax, c, "x")

    th = _thickness(ax, len(order), len(order))
    for yi, (tag, n) in zip(y, order):
        has = tag in covered
        _round_end_bar(ax, 0, n, yi, th, c["s1"] if has else c["s2"], zorder=3)
        ax.annotate(f"{n}", xy=(n, yi), xytext=(6, 0), textcoords="offset points",
                    va="center", fontsize=9, color=c["secondary"])

    n_cov, n_tot = len(covered), len(order)
    share = headline_share if headline_share is not None else unreachable_share
    ax.annotate(
        f"{n_detectors} upstream detectors reach {n_cov} of {n_tot} tags.\n"
        f"{share:.1%} of positive (repository, tag) pairs have no detector at all —\n"
        "unreachable by construction, for any model, at any cost."
        + (f"\n{headline_note}" if headline_note else ""),
        xy=(vmax * 0.30, 6.5), fontsize=12.5, color=c["primary"], va="center",
        linespacing=1.55)

    ax.legend(handles=[
        Line2D([], [], color=c["s1"], lw=9, solid_capstyle="butt",
               label="at least one detector exists"),
        Line2D([], [], color=c["s2"], lw=9, solid_capstyle="butt",
               label="no detector — cannot be found"),
    ], loc="lower right", frameon=False, fontsize=11, labelcolor=c["secondary"],
        handletextpad=0.9, borderaxespad=1.4)

    _title(fig, c,
           "Two thirds of the tag vocabulary has no detector behind it",
           "Every tag in the training ground truth, ordered by how many findings carry "
           "it. Colour marks whether upstream ships\nany detector for that tag — the "
           "orange bars are score that is unavailable, not score that was missed.",
           y=0.988)
    ax.set_xlabel("findings carrying this tag"
                  + (f" (ground truth, {n_findings} rows)" if n_findings else ""),
                  fontsize=10.5, color=c["secondary"], labelpad=10)
    _footnote(fig, c, source_note or "Sources: detectors/index.json, "
                                     "runs/routing_recall/summary.json.", y=0.008)
    fig.subplots_adjust(top=0.915, left=0.145, right=0.985, bottom=0.055)
    return save(fig, "fig5_coverage_gap", outdir, mode)


# ----------------------------------------------------------------- 6. cost ladder


def fig_cost_ladder(stages, *, latency_s: float, concurrency: int,
                    recall_loss: float = 0.0, mode: str = "light",
                    outdir: Path = FIGURE_DIR) -> list[Path]:
    """Calls and input tokens at each stage of the plan, as two small multiples.

    Two measures on two panels rather than two y-scales on one plot: the counts differ
    by four orders of magnitude between the panels and any shared or twinned axis would
    manufacture a relationship between them.
    """
    c = PALETTE[mode]
    fig, axes, c = _new_fig(mode, (13.0, 6.4), 1, 2)
    labels = [s[0] for s in stages]
    panels = [
        ("LLM calls", [s[1] for s in stages], lambda v: f"{v:,.0f}"),
        ("input tokens", [s[2] for s in stages], lambda v: f"{v / 1e6:,.1f}M"),
    ]

    for ax, (name, vals, fmt) in zip(axes, panels):
        ax.set_xlim(0, max(vals) * 1.30)
        # Stage 1 reads at the top, so row i plots stage -(i+1); the tick labels are
        # reversed with it. (Plotting reversed values against forward labels silently
        # mislabels every rung, which is exactly the bug this ordering removes.)
        ax.set_ylim(-0.55, len(vals) - 0.05)
        ax.set_yticks(range(len(vals)))
        ax.set_yticklabels(list(reversed(labels)) if ax is axes[0] else [""] * len(vals),
                           fontsize=10.5, color=c["secondary"])
        ax.set_xticks([])
        th = _thickness(ax, len(vals), len(vals), cap_pt=26.0)
        for i, v in enumerate(reversed(vals)):
            _round_end_bar(ax, 0, v, i, th, c["s1"], zorder=3)
            ax.annotate(fmt(v), xy=(v, i), xytext=(9, 0), textcoords="offset points",
                        va="center", fontsize=12, fontweight="600",
                        color=c["primary"])
        drop = 1 - vals[-1] / vals[0]
        ax.annotate(f"−{drop:.1%}", xy=(max(vals) * 0.60, 0.55),
                    fontsize=22, fontweight="600", color=c["s1"], ha="left",
                    va="center")
        ax.set_xlabel(name, fontsize=11.5, color=c["secondary"], labelpad=8)

    hours = stages[0][1] * latency_s / 3600.0
    hours_routed = stages[-1][1] * latency_s / 3600.0
    fig.text(0.012, 0.085,
             f"Routing costs {recall_loss:.1%} recall: every (repository, tag) pair "
             "that had a detector still reaches one.",
             fontsize=12, fontweight="600", color=c["good"])
    fig.text(0.012, 0.030,
             f"At {latency_s:g} s per call, the unrouted plan is ≈{hours:,.0f} h "
             f"sequential ({hours / (24):.1f} days) — upstream cannot finish its own "
             f"test set. Routed: ≈{hours_routed:,.0f} h, or ≈"
             f"{hours_routed / concurrency:.1f} h at {concurrency}-way concurrency.",
             fontsize=10.5, color=c["secondary"])

    _title(fig, c,
           "Filtering and routing remove 87.5% of the calls and 88.6% of the tokens",
           "Same 56 detectors, same corpus (the 53 held-out repositories), same "
           "downstream pipeline — only the call plan changes.")
    _footnote(fig, c,
              "Stage 1 is the project's published upstream baseline; stages 2–3 are "
              "measured with routing.broadcast_cost / routing.cost at 4 chars per "
              "token.", y=0.002)
    fig.subplots_adjust(top=0.80, left=0.20, right=0.975, bottom=0.235, wspace=0.10)
    return save(fig, "fig6_cost_ladder", outdir, mode)


# ------------------------------------------------------------------------- driver


def build_all(outdir: Path = FIGURE_DIR) -> list[Path]:
    runs = REPO_ROOT / "runs"
    data = REPO_ROOT.parent / "data"

    perfect = load_perfect_predictor(runs / "e6" / "e6_perfect_predictor.csv")
    macro = json.loads((runs / "e6" / "e6_summary.json").read_text())
    audit = load_instrument_audit(runs / "instrument" / "instrument_audit.csv",
                                  "README (github, current)")
    balance = load_balance_sensitivity(runs / "instrument" / "balance_sensitivity.csv")
    # data/train.csv disappeared from the shared workspace mid-session; upstream's
    # dataset/dataset.csv carries the identical 497 rows plus two extra columns, so it
    # is an exact fallback rather than a substitute. Neither file is written here.
    ground_truth = next(p for p in (
        data / "train.csv",
        REPO_ROOT.parent / "upstream-bastet" / "dataset" / "dataset.csv",
    ) if p.exists())
    coverage = load_coverage(ground_truth, REPO_ROOT / "detectors" / "index.json")
    routing = load_routing_summary(runs / "routing_recall" / "summary.json")

    pub, null = audit["published"], audit["constant yes"]
    metrics = [
        ("F1", null["f1"], pub["f1"], ""),
        ("accuracy", null["accuracy"], pub["accuracy"], ""),
        ("balanced accuracy", null["balanced_accuracy"], pub["balanced_accuracy"], ""),
        # MCC is undefined for a constant predictor (zero variance); 0.0 is the
        # conventional substitution and is stated on the chart rather than silently used.
        ("MCC", 0.0, pub["mcc"], "MCC undefined for a constant\npredictor; shown as 0"),
    ]

    # Measured with bastet_cc.routing over data/ex/test (53 repositories, 56 detectors).
    stages = [
        ("upstream: every .sol file\n× every detector", 344_008, 535_000_000),
        ("+ vendor/test exclusion\nand scope.txt", 112_616, 246_039_484),
        ("+ hint routing\n(function slices)", 42_866, 60_731_740),
    ]

    written: list[Path] = []
    for mode in MODES:
        written += fig_measurement_audit(
            perfect, macro_f1=macro["upstream_macro_f1_perfect_predictor"],
            n_seeds=len(macro["seeds"]), mode=mode, outdir=outdir)
        written += fig_floor(
            published=pub["f1"], reruns=[0.5556, 0.72, 0.6667, 0.72],
            null_f1=null["f1"], mode=mode, outdir=outdir)
        written += fig_metric_flip(metrics, mode=mode, outdir=outdir)
        written += fig_balance_sensitivity(balance, mode=mode, outdir=outdir)
        written += fig_coverage_gap(
            coverage["counts"], coverage["covered"],
            unreachable_share=coverage["unreachable_share"],
            n_detectors=coverage["n_detectors"],
            headline_share=1 - routing["coverage_ceiling"],
            headline_note=f"(routed split, {routing['positives']} positives; "
                          f"{coverage['unreachable_share']:.1%} over all "
                          f"{coverage['n_pairs']} pairs in the full ground truth)",
            n_findings=coverage["n_findings"],
            source_note=f"Sources: {coverage['source'].name}, detectors/index.json, "
                        "runs/routing_recall/summary.json.",
            mode=mode, outdir=outdir)
        written += fig_cost_ladder(
            stages, latency_s=1.7, concurrency=32,
            recall_loss=1.0 - routing["routing_ceiling_given_detector"],
            mode=mode, outdir=outdir)
    return written


def main() -> None:
    for p in build_all():
        print(p)


if __name__ == "__main__":
    main()
