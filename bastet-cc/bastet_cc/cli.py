"""Command line entry points for Bastet-CC.

The pipeline is deliberately splittable. A scan of the TEST split costs real wall-clock
and, under the freeze protocol, may only run once -- so indexing, planning, execution,
verification and scoring are separate commands with artefacts on disk between them.
That way a scoring mistake costs a re-score, not a re-scan.

`scan --arm broadcast` is not a debugging option. It is the control condition: the same
detectors, the same model, the same parser and the same scorer, with only `plan()`
switched to upstream's every-file-to-every-detector behaviour. Anything that touches one
arm and not the other belongs in `plan.py` or it does not belong at all.
"""

from __future__ import annotations

import json
import os
import sys
from pathlib import Path

import typer

from .llm import DEFAULT_RPM

app = typer.Typer(add_completion=False, help="Bastet-CC: routed smart-contract vulnerability detection")

PKG = Path(__file__).resolve().parent
ROOT = PKG.parent
DATA = ROOT.parent / "data"
RUNS = ROOT / "runs"

DEFAULT_MODEL = "ais3/nemotron-3-ultra-550b"
DEFAULT_BASE_URL = "https://llm-api.zoolab.org/v1"
PROMPT_VERSION = "v1"


def _api_key() -> str:
    key = os.environ.get("AIS3_API_KEY")
    if not key:
        typer.secho(
            "set AIS3_API_KEY (the AIS3 gateway token); it is deliberately not in the repo",
            fg=typer.colors.RED, err=True,
        )
        raise typer.Exit(2)
    return key


GROUND_TRUTH = DATA / "train.csv"


def _ground_truth():
    """Load the labelled findings, or explain how to get them and stop.

    Every scoring path needs this file and it is deliberately not redistributed
    (see .gitignore). Reaching pandas with a missing path produces a forty-line
    traceback that tells a first-time reader nothing, so the check is explicit
    and names the command that fixes it.
    """
    import pandas as pd

    if not GROUND_TRUTH.exists():
        typer.secho(f"missing ground truth: {GROUND_TRUTH}", fg=typer.colors.RED, err=True)
        typer.secho(
            "  train.csv is the Kaggle competition's labelled findings and is not\n"
            "  redistributed here. Fetch it from the `onesavie-bastet` Data tab into\n"
            "  data/train.csv (see README, 'Install').\n"
            "\n"
            "  Commands that need no labels: index, route, structural, power, figures.",
            fg=typer.colors.YELLOW, err=True,
        )
        raise typer.Exit(2)
    return pd.read_csv(GROUND_TRUTH)


def _detector_dirs(include_synth: bool) -> list[Path]:
    dirs = [ROOT / "detectors"]
    synth = ROOT / "detectors_synth"
    if include_synth and (synth / "index.json").exists():
        dirs.append(synth)
    return dirs


def _load_detectors(include_synth: bool):
    from .routing import load_detectors
    out = []
    for d in _detector_dirs(include_synth):
        out.extend(load_detectors(d))
    return out


def _split_repos(split: str) -> list[str]:
    payload = json.loads((DATA / "splits.json").read_text())
    if split not in ("train_syn", "dev", "test"):
        raise typer.BadParameter(f"unknown split {split!r}")
    return payload[split]


def _repo_dir(repo: str) -> Path:
    for base in (DATA / "ex" / "train", DATA / "ex" / "test"):
        p = base / repo
        if p.is_dir():
            return p
    raise typer.BadParameter(f"repository {repo} not extracted under {DATA / 'ex'}")


@app.command()
def index(repo: str = typer.Argument(..., help="repo hash or path")) -> None:
    """Parse a repository into a function-level index."""
    from .solidity import index_repo

    path = Path(repo) if Path(repo).is_dir() else _repo_dir(repo)
    ix = index_repo(path)
    errs = sum(f["parse_errors"] for f in ix["files"])
    typer.echo(
        f"{ix['repo']}: {ix['n_files']} files, {ix['n_functions']} functions, "
        f"{ix['n_bytes'] / 1e6:.2f} MB, {errs} parse errors"
    )
    typer.echo(f"  scope.txt present: {ix['scope_file']}   skipped: {ix['skipped']}")


@app.command()
def route(
    repo: str = typer.Argument(...),
    synth: bool = typer.Option(True, help="include synthesised detectors"),
) -> None:
    """Show what routing costs against what broadcasting would cost."""
    from .routing import broadcast_cost, cost, fit
    from .plan import plan
    from .solidity import index_repo

    path = Path(repo) if Path(repo).is_dir() else _repo_dir(repo)
    dets = _load_detectors(synth)
    ix = index_repo(path)
    fit(dets, [ix])

    routed = cost(plan("routed", dets, path, repo_index=ix))
    bcast = broadcast_cost(dets, ix)
    typer.echo(f"{ix['repo']}  {len(dets)} detectors, {ix['n_functions']} functions")
    typer.echo(f"{'':<16}{'calls':>10}{'input tokens':>15}")
    typer.echo(f"{'broadcast':<16}{bcast['calls']:>10,}{bcast['input_tokens']:>15,}")
    typer.echo(f"{'routed':<16}{routed['calls']:>10,}{routed['input_tokens']:>15,}")
    if bcast["calls"]:
        typer.echo(
            f"{'saved':<16}{100 * (1 - routed['calls'] / bcast['calls']):>9.1f}%"
            f"{100 * (1 - routed['input_tokens'] / bcast['input_tokens']):>14.1f}%"
        )


@app.command()
def scan(
    target: str = typer.Argument(..., help="repo hash, path, or a split name"),
    run: str = typer.Option(..., "--run", help="run id; artefacts land in runs/<id>/"),
    arm: str = typer.Option("routed", help="routed | broadcast"),
    model: str = typer.Option(DEFAULT_MODEL),
    concurrency: int = typer.Option(16),
    rpm: int = typer.Option(
        DEFAULT_RPM, help="request/minute cap; the gateway enforces 120. 0 disables"),
    synth: bool = typer.Option(True, help="include synthesised detectors"),
    verify: bool = typer.Option(True, help="run the refutation pass"),
    closure: bool = typer.Option(
        False, help="routed only: append one-hop callees to each slice"),
) -> None:
    """Scan repositories and record findings.

    Resumable: task ids fold in the model and prompt version, so a rerun skips work
    already on disk and redoes anything whose inputs changed.
    """
    import asyncio

    from .llm import LLMClient
    from .plan import plan
    from .routing import fit
    from .runstore import RunStore
    from .solidity import index_repo

    if arm not in ("routed", "broadcast"):
        raise typer.BadParameter("arm must be 'routed' or 'broadcast'")
    if closure and arm != "routed":
        raise typer.BadParameter(
            "closure is a routed-arm treatment; enabling it on the broadcast "
            "control would void the comparison")

    repos = _split_repos(target) if target in ("train_syn", "dev", "test") else [target]
    paths = [Path(r) if Path(r).is_dir() else _repo_dir(r) for r in repos]

    dets = _load_detectors(synth)
    indexes = [index_repo(p) for p in paths]
    fit(dets, indexes)

    tasks = []
    closure_stats: list[dict] = []
    for p, ix in zip(paths, indexes):
        tasks.extend(plan(arm, dets, p, repo_index=ix, closure=closure))
        if closure:
            from .plan import last_closure_stats
            closure_stats.append({"repo": ix["repo"], **last_closure_stats()})

    store = RunStore(RUNS / run)
    store.write_manifest({
        "arm": arm, "model": model, "prompt_version": PROMPT_VERSION,
        "target": target, "repos": repos, "concurrency": concurrency,
        "rpm": rpm or None,
        "detectors": len(dets), "detector_dirs": [str(d) for d in _detector_dirs(synth)],
        "verify": verify, "closure": closure,
        "closure_stats": closure_stats or None,
        "splits_sha256": json.loads((DATA / "splits.json").read_text()).get("splits_sha256"),
    })
    store.write_tasks(tasks, model, PROMPT_VERSION)

    done = store.done_ids()
    typer.echo(f"{arm}: {len(tasks)} tasks over {len(repos)} repos, {len(done)} already done")

    # The gateway caps requests per minute, not concurrency, so wall-clock is
    # governed by the cap once the plan is larger than a minute's worth. Saying
    # so up front stops a 6-hour run from being started as if it were a 1-hour one.
    remaining = len(tasks) - len(done)
    if rpm and remaining:
        hours = remaining / rpm / 60
        typer.echo(f"  at {rpm} rpm this is ~{hours:.1f} h of wall clock"
                   f" ({remaining:,} calls); concurrency={concurrency} bounds memory,"
                   f" not rate")
    if closure and closure_stats:
        added = sum(c.get("added_tokens_est", 0) for c in closure_stats)
        exp = sum(c.get("slices_expanded", 0) for c in closure_stats)
        typer.echo(f"  closure: {exp:,} slices expanded, +{added:,} input tokens est")

    async def _go() -> None:
        from .executor import run_tasks
        client = LLMClient(
            base_url=DEFAULT_BASE_URL, api_key=_api_key(),
            model=model, max_concurrency=concurrency,
            rpm=rpm or None,
            log_path=RUNS / run / "llm_log.jsonl",
        )
        try:
            await run_tasks(tasks, client, store)
            if verify:
                from .verify import verify_findings
                findings = store.load_findings()
                by_repo = {ix["repo"]: ix for ix in indexes}
                for repo_name, ix in by_repo.items():
                    subset = [f for f in findings if getattr(f, "repo", None) == repo_name]
                    if subset:
                        await verify_findings(subset, ix, client, store)
        finally:
            if client.limiter is not None:
                st = client.limiter.stats()
                if st["n_waits"]:
                    print(f"[rate] throttled {st['n_waits']:,} times, "
                          f"{st['waited_s']:.0f}s total wait at {st['rpm']} rpm",
                          flush=True)
            await client.aclose()

    asyncio.run(_go())
    out = store.export_findings()
    typer.echo(f"wrote {out}")


@app.command()
def evaluate(
    run: str = typer.Option(..., "--run"),
    split: str = typer.Option("dev"),
    scorer: str = typer.Option("both", help="both | upstream | fixed"),
    calibration: Path = typer.Option(None, help="calibration json; omit to fit on this split"),
) -> None:
    """Score a run under the corrected scorer, upstream's, or both."""
    import pandas as pd

    from .aggregate import (aggregate, confusion_by_tag, fit_calibration, macro_f1,
                            scoreable_tags, truth_map, upstream_calibration,
                            upstream_predictions)
    from .runstore import RunStore

    store = RunStore(RUNS / run)
    findings = store.load_findings()
    repos = _split_repos(split)
    truth_df = _ground_truth()
    truth = truth_map(truth_df, repos)
    tags = scoreable_tags(truth, repos)

    if calibration:
        from .aggregate import Calibration
        calib = Calibration(**json.loads(Path(calibration).read_text()))
    else:
        # Fitting on the split being scored inflates it. Acceptable on DEV, which is
        # what calibration is for; on TEST, pass a calibration frozen beforehand.
        if split == "test":
            typer.secho(
                "refusing to fit calibration on TEST -- pass --calibration from DEV",
                fg=typer.colors.RED, err=True,
            )
            raise typer.Exit(2)
        calib = fit_calibration(findings, truth_df, repos)

    typer.echo(f"run={run} split={split} repos={len(repos)} tags={len(tags)} "
               f"findings={len(findings)}")

    if scorer in ("fixed", "both"):
        cm = confusion_by_tag(aggregate(findings, calib, repos, tags), truth, repos, tags)
        typer.echo(f"\ncorrected scorer   macro-F1 {macro_f1(cm):.4f}")
        _print_tags(cm)

    if scorer in ("upstream", "both"):
        cm = confusion_by_tag(upstream_predictions(findings, repos), truth, repos, tags)
        typer.echo(f"\nupstream scorer    macro-F1 {macro_f1(cm):.4f}  "
                   f"(prior=1, tau->0: every finding counts)")
        _print_tags(cm)


def _print_tags(cm: dict) -> None:
    fmt = lambda v: "  n/a" if v is None else f"{v:5.3f}"  # noqa: E731
    typer.echo(f"  {'tag':<22}{'TP':>4}{'FP':>4}{'FN':>4}{'TN':>4}"
               f"{'prec':>8}{'rec':>8}{'f1':>8}")
    for tag, c in sorted(cm.items(), key=lambda kv: (-(kv[1].f1 or -1), kv[0])):
        if not c.n:
            continue
        typer.echo(f"  {tag:<22}{c.tp:>4}{c.fp:>4}{c.fn:>4}{c.tn:>4}"
                   f"{fmt(c.precision):>8}{fmt(c.recall):>8}{fmt(c.f1):>8}")


@app.command()
def calibrate(
    run: str = typer.Option(..., "--run", help="a DEV run to fit on"),
    split: str = typer.Option("dev"),
    out: Path = typer.Option(RUNS / "calibration.json"),
    sensitivity: bool = typer.Option(
        False, help="also run the wider grid and report the overfitting headroom"),
) -> None:
    """Fit the decision layer on DEV and freeze it for the TEST run."""
    import pandas as pd

    from .aggregate import fit_calibration, format_sweep, grid_search
    from .runstore import RunStore

    if split == "test":
        typer.secho("calibrating on TEST defeats the freeze protocol", fg=typer.colors.RED)
        raise typer.Exit(2)

    store = RunStore(RUNS / run)
    findings = store.load_findings()
    repos = _split_repos(split)
    truth_df = _ground_truth()

    # fit_calibration is what ships the number: it sweeps tau only, holding the
    # prior's smoothing fixed. grid_search additionally sweeps alpha/beta/clip,
    # which on 10 DEV repositories overfits harder -- aggregate.grid_search says
    # so in its own docstring ("the honest use is sensitivity analysis"). This
    # command used to write the grid_search result, so the calibration frozen for
    # TEST was the overfit one; and because grid_search records `grid_best`
    # rather than `tau_sweep`, format_sweep printed an empty table beside it.
    calib = fit_calibration(findings, truth_df, repos)
    typer.echo(format_sweep(calib))

    if sensitivity:
        best, grid = grid_search(findings, truth_df, repos)
        gap = (best.diagnostics["grid_best"]["macro_f1"]
               - (calib.diagnostics.get("best_macro_f1") or 0.0))
        typer.echo(f"\nsensitivity: {len(grid)} grid points, best macro-F1 "
                   f"{best.diagnostics['grid_best']['macro_f1']:.4f} at "
                   f"tau={best.tau} alpha={best.diagnostics['grid_best']['alpha']} "
                   f"beta={best.diagnostics['grid_best']['beta']}")
        typer.echo(f"             +{gap:.4f} over the shipped fit -- this is the "
                   f"overfitting headroom, not an improvement.")
        calib.diagnostics["sensitivity_grid_best"] = best.diagnostics["grid_best"]

    out.parent.mkdir(parents=True, exist_ok=True)
    out.write_text(json.dumps(calib.to_dict(), indent=2, default=list))
    typer.echo(f"\nwrote {out}  (tau={calib.tau}, "
               f"{len(calib.detector_prior)} detector priors)")


@app.command()
def figures(outdir: Path = typer.Option(None, help="override the figure directory")) -> None:
    """Render every figure from the measurement artefacts already on disk.

    `build_all` emits light and dark variants together, so there is no mode to
    choose; the flag this used to accept was silently ignored.
    """
    from .report import build_all, FIGURE_DIR

    paths = build_all(outdir or FIGURE_DIR)
    for p in paths:
        typer.echo(f"  {p}")
    typer.echo(f"{len(paths)} files")


def _structural(a: str, b: str, out: Path | None, quiet: bool) -> dict:
    """Shared body: `structural` is this alone, `compare` prints it as a preamble."""
    from .runstore import RunStore
    from .structural import compare_structural, format_structural, profile

    profiles, findings = {}, {}
    for name, run_id in (("a", a), ("b", b)):
        run_dir = RUNS / run_id
        if not run_dir.is_dir():
            typer.secho(f"no such run: {run_dir}", fg=typer.colors.RED, err=True)
            raise typer.Exit(2)
        findings[name] = RunStore(run_dir).load_findings()
        profiles[name] = profile(run_id, findings[name], run_dir)

    result = compare_structural(profiles["a"], profiles["b"], findings["a"], findings["b"])
    if not quiet:
        typer.echo(format_structural(result, a, b))
        if not result["comparable"]:
            typer.secho(
                "\nthese runs share no repository, so the site agreement above is empty; "
                "the per-arm columns are still valid.",
                fg=typer.colors.YELLOW)
    if out:
        out.parent.mkdir(parents=True, exist_ok=True)
        out.write_text(json.dumps(result, indent=2))
        typer.echo(f"\nwrote {out}")
    return result


@app.command()
def structural(
    a: str = typer.Option(..., "--a", help="run id for arm A (e.g. the routed arm)"),
    b: str = typer.Option(..., "--b", help="run id for arm B (e.g. broadcast)"),
    out: Path = typer.Option(None, help="write the result as JSON"),
) -> None:
    """Compare two arms without labels: where findings land, and what they cost.

    Runs from committed `findings.json` alone -- no API key, no train.csv, no
    6.8 GB corpus. That makes it the one head-to-head a reader who just cloned
    this repository can reproduce, and the only one available on TEST before the
    labels are spent. It does not rank detection quality; `compare` does that.
    """
    _structural(a, b, out=out, quiet=False)


@app.command()
def compare(
    a: str = typer.Option(..., "--a", help="run id for arm A (e.g. the routed arm)"),
    b: str = typer.Option(..., "--b", help="run id for arm B (e.g. broadcast)"),
    split: str = typer.Option("dev"),
    calibration: Path = typer.Option(None, help="frozen calibration; required for TEST"),
    out: Path = typer.Option(None, help="write the result as JSON"),
) -> None:
    """Paired comparison of two arms: McNemar, sign test, and power.

    Both arms scored the same repositories with the same model, so the
    comparison must be paired. A two-sample test would pay for
    between-repository variance, which dominates here -- repositories differ
    enormously in size and tag load -- and on a 12-repository TEST split that
    difference decides whether anything is resolvable at all.
    """
    from .aggregate import (Calibration, aggregate, fit_calibration, macro_f1,
                            confusion_by_tag, scoreable_tags, truth_map)
    from .runstore import RunStore
    from .stats import describe_paired, format_mcnemar, mcnemar

    repos = _split_repos(split)
    # The label-free half costs nothing and needs no corpus, so it runs first and
    # is printed either way: without it, a reader with no train.csv gets an error
    # and no comparison at all, which is the common case for anyone cloning this.
    _structural(a, b, out=None, quiet=False)
    typer.echo("")
    truth_df = _ground_truth()
    truth = truth_map(truth_df, repos)
    tags = scoreable_tags(truth, repos)

    if split == "test" and calibration is None:
        typer.secho("TEST requires --calibration frozen on DEV", fg=typer.colors.RED,
                    err=True)
        raise typer.Exit(2)

    arms: dict[str, list] = {}
    for name, run_id in (("a", a), ("b", b)):
        findings = RunStore(RUNS / run_id).load_findings()
        calib = (Calibration.from_dict(json.loads(calibration.read_text()))
                 if calibration else fit_calibration(findings, truth_df, repos))
        arms[name] = aggregate(findings, calib, repos, tags)

    # One decision per (repo, tag) cell, correct-or-not under each arm.
    pairs, per_repo_a, per_repo_b = [], [], []
    for repo in repos:
        cm_a = confusion_by_tag({t: {repo: arms["a"][t].get(repo, False)} for t in tags},
                                truth, [repo], tags)
        cm_b = confusion_by_tag({t: {repo: arms["b"][t].get(repo, False)} for t in tags},
                                truth, [repo], tags)
        per_repo_a.append(macro_f1(cm_a))
        per_repo_b.append(macro_f1(cm_b))
        for tag in tags:
            actual = tag in truth.get(repo, set())
            pairs.append((arms["a"][tag].get(repo, False) == actual,
                          arms["b"][tag].get(repo, False) == actual))

    m = mcnemar(pairs)
    typer.echo(f"arm A = {a}   arm B = {b}   split={split} "
               f"({len(repos)} repos x {len(tags)} tags)")
    typer.echo("")
    typer.echo(format_mcnemar(m, label_a=a, label_b=b))

    # Repository-level macro-F1, bootstrapped over repositories rather than
    # decisions: decisions inside one repo share a codebase and a model pass.
    typer.echo("\nper-repository macro-F1, paired:")
    paired = describe_paired(per_repo_a, per_repo_b, label_a=a, label_b=b)
    typer.echo(f"  mean difference : {paired['mean_difference']:+.4f}")
    typer.echo(f"  wins/losses/ties: {paired['wins']}/{paired['losses']}/{paired['ties']}")
    typer.echo(f"  sign test p     : {paired['sign_test_p']:.4f}")
    if paired["bootstrap"]:
        bs = paired["bootstrap"]
        typer.echo(f"  95% CI          : [{bs['lo']:+.4f}, {bs['hi']:+.4f}]"
                   f"  {'excludes' if bs['excludes_zero'] else 'includes'} zero")
    else:
        typer.echo(f"  bootstrap declined: {paired['bootstrap_declined'].splitlines()[0]}")
        typer.echo(f"  differences     : "
                   f"{[f'{d:+.3f}' for d in paired['differences']]}")

    if out:
        out.parent.mkdir(parents=True, exist_ok=True)
        out.write_text(json.dumps(
            {"arm_a": a, "arm_b": b, "split": split, "n_repos": len(repos),
             "n_tags": len(tags), "mcnemar": m.to_dict(), "paired_macro_f1": paired},
            indent=2))
        typer.echo(f"\nwrote {out}")


@app.command()
def power(
    decisions: int = typer.Option(240, help="paired decisions, i.e. repos x tags"),
    discordance: float = typer.Option(
        0.25, help="assumed fraction of decisions where the arms disagree"),
) -> None:
    """What effect size the design can resolve, before spending the TEST scan.

    Run this on D2, not D5. If the answer is "only a landslide registers", that
    is a fact about the experiment and it is cheaper to learn now -- the response
    is to widen the decision set (more tags scored) rather than to hope.
    """
    from .stats import mde

    n_disc = max(0, int(decisions * discordance))
    typer.echo(f"{decisions} paired decisions, {discordance:.0%} discordant "
               f"-> {n_disc} informative pairs\n")
    typer.echo(f"{'discordant':>12}{'MDE b/(b+c)':>14}   interpretation")
    for n in sorted({10, 25, 50, 100, n_disc, decisions}):
        v = mde(n)
        note = ("landslide only" if v > 0.85 else
                "large effects only" if v > 0.70 else "workable")
        mark = "  <-- your design" if n == n_disc else ""
        typer.echo(f"{n:>12}{v:>14.3f}   {note}{mark}")
    typer.echo("\nMDE is the share of *disagreements* the better arm must win at"
               "\n80% power, alpha 0.05. Concordant decisions carry no evidence.")


@app.command()
def report(
    run: str = typer.Option(..., "--run", help="run id under runs/"),
    fmt: str = typer.Option("md", "--format", help="sarif | md | json"),
    out: Path = typer.Option(None, help="output file; default runs/<run>/report.<ext>"),
    repo_url: str = typer.Option("", help="base URL for permalinks in markdown"),
    fail_on: str = typer.Option(
        "High", help="comma-separated severities that make the gate fail; '' never fails"),
    include_suppressed: bool = typer.Option(
        False, help="include findings the verifier rejected"),
) -> None:
    """Turn a run into a deliverable. SARIF feeds GitHub code scanning.

    Exit status is the gate: 1 when any finding at a `--fail-on` severity survived
    verification, 0 otherwise. Rejected verdicts never fail a build -- failing on a
    finding our own refutation pass argued away is how a security gate gets
    switched off.
    """
    from .emit import gate_summary, to_json, to_markdown, to_sarif
    from .runstore import RunStore

    store = RunStore(RUNS / run)
    findings = store.load_findings()
    if not findings:
        typer.secho(f"no findings in {RUNS / run}", fg=typer.colors.YELLOW, err=True)

    if fmt == "sarif":
        # The detector prompts become the SARIF rule descriptions, so an alert is
        # reviewable in the GitHub UI without cloning this repository.
        help_text = {}
        for d in _detector_dirs(True):
            for md in d.glob("*.md"):
                help_text[md.stem] = md.read_text(encoding="utf-8", errors="replace")[:4000]
        body = json.dumps(to_sarif(findings, detector_help=help_text,
                                   include_suppressed=include_suppressed,
                                   run_id=run), indent=2)
        ext = "sarif"
    elif fmt == "md":
        body = to_markdown(findings, title=f"Bastet-CC report — {run}",
                           repo_url=repo_url, include_suppressed=include_suppressed)
        ext = "md"
    elif fmt == "json":
        body = to_json(findings, include_suppressed=include_suppressed)
        ext = "json"
    else:
        raise typer.BadParameter("format must be sarif, md or json")

    target = out or (RUNS / run / f"report.{ext}")
    target.parent.mkdir(parents=True, exist_ok=True)
    target.write_text(body, encoding="utf-8")

    levels = tuple(s.strip() for s in fail_on.split(",") if s.strip())
    summary = gate_summary(findings, fail_on=levels)
    typer.echo(f"wrote {target}")
    loc = summary["localisation"]
    typer.echo(f"  {summary['total']} findings  {summary['counts'] or '{}'}"
               + (f"  suppressed {summary['suppressed']}" if summary["suppressed"] else ""))
    typer.echo(f"  localisation: {loc.get('parser', 0)} exact, "
               f"{loc.get('site', 0)} function-matched (line asserted by the model), "
               f"{loc.get('none', 0)} file-level only")
    if levels and not summary["passed"]:
        typer.secho(f"gate FAILED: {summary['blocking']} finding(s) at "
                    f"{'/'.join(levels)}", fg=typer.colors.RED)
        raise typer.Exit(1)
    typer.secho("gate passed", fg=typer.colors.GREEN)


@app.command("diff-scan")
def diff_scan(
    base: str = typer.Argument(..., help="git ref to diff against (e.g. origin/main)"),
    head: str = typer.Option("", help="second ref; omit to diff the working tree"),
    repo: Path = typer.Option(Path("."), help="repository to index and diff"),
    synth: bool = typer.Option(True, help="include synthesised detectors"),
    closure: bool = typer.Option(True, help="attach one-hop callees to each slice"),
    out: Path = typer.Option(None, help="write the scope and plan as JSON"),
) -> None:
    """Plan a scan of only the functions a diff touched — the PR gate.

    Prints the plan and its cost against what a whole-repository scan would cost,
    and does not call the model: the point of a gate is to know the bill before
    paying it. Feed the same scope to `scan` to execute it.

    Upstream's action scans the entire checkout on every pull request, so its cost
    is a property of the repository rather than of the change. This makes it a
    property of the change.
    """
    from .diffscan import git_diff, parse_diff, restrict_index, scope_from_diff
    from .plan import plan
    from .routing import broadcast_cost, cost, fit
    from .solidity import index_repo

    repo = repo.resolve()
    try:
        diff_text = git_diff(base, head, repo_root=repo)
    except RuntimeError as e:
        typer.secho(str(e), fg=typer.colors.RED, err=True)
        raise typer.Exit(2)

    changed = parse_diff(diff_text)
    if not changed:
        typer.secho(f"no added or modified files between {base} and "
                    f"{head or 'the working tree'}", fg=typer.colors.YELLOW)
        raise typer.Exit(0)

    ix = index_repo(repo)
    scope = scope_from_diff(changed, ix)

    typer.echo(f"{scope.changed_files} changed file(s), "
               f"{scope.changed_sol_files} Solidity, {scope.added_lines} added line(s)")
    typer.echo(f"touched {scope.n_functions} indexed function(s) in "
               f"{len(scope.touched)} file(s)")
    for path, fns in sorted(scope.touched.items()):
        typer.echo(f"  {path}: {', '.join(sorted(fns))}")

    if scope.unscanned_reasons:
        typer.echo("\nnot scanned:")
        for reason, items in sorted(scope.unscanned_reasons.items()):
            typer.echo(f"  {reason}")
            for item in sorted(items)[:8]:
                typer.echo(f"    {item}")
            if len(items) > 8:
                typer.echo(f"    ... and {len(items) - 8} more")

    if not scope.n_functions:
        typer.secho("\nnothing to scan. This is not the same as 'no vulnerabilities' — "
                    "see the reasons above.", fg=typer.colors.YELLOW)
        raise typer.Exit(0)

    dets = _load_detectors(synth)
    # Fit on the FULL index, not the restricted one. Document frequency is a
    # property of the codebase; measuring it over three changed functions would make
    # every identifier look rare and route every detector everywhere.
    fit(dets, [ix])
    scoped = restrict_index(ix, scope)

    tasks = plan("routed", dets, repo, repo_index=scoped, closure=closure)
    diff_cost = cost(tasks)
    full_tasks = plan("routed", dets, repo, repo_index=ix, closure=closure)
    full_cost = cost(full_tasks)
    bcast = broadcast_cost(dets, ix)

    typer.echo(f"\n{'plan':<28}{'calls':>10}{'input tokens':>15}")
    typer.echo(f"{'upstream (every file x det)':<28}{bcast['calls']:>10,}"
               f"{bcast['input_tokens']:>15,}")
    typer.echo(f"{'routed, whole repo':<28}{full_cost['calls']:>10,}"
               f"{full_cost['input_tokens']:>15,}")
    typer.echo(f"{'routed, diff only':<28}{diff_cost['calls']:>10,}"
               f"{diff_cost['input_tokens']:>15,}")
    if bcast["calls"]:
        typer.echo(f"\nvs upstream: {100 * (1 - diff_cost['calls'] / bcast['calls']):.2f}% "
                   f"fewer calls, "
                   f"{100 * (1 - diff_cost['input_tokens'] / bcast['input_tokens']):.2f}% "
                   f"fewer tokens")
    from .llm import DEFAULT_RPM
    typer.echo(f"at {DEFAULT_RPM} rpm: upstream "
               f"{bcast['calls'] / DEFAULT_RPM / 60:.1f} h, "
               f"diff-scoped {diff_cost['calls'] / DEFAULT_RPM * 60:.0f} s")

    if out:
        out.parent.mkdir(parents=True, exist_ok=True)
        out.write_text(json.dumps({
            "base": base, "head": head or None, "repo": str(repo),
            "scope": scope.to_dict(),
            "cost": {"diff": diff_cost, "routed_full": full_cost, "broadcast": bcast},
            "closure": closure, "detectors": len(dets),
        }, indent=2))
        typer.echo(f"\nwrote {out}")


@app.command()
def audit() -> None:
    """Run the leakage and instrument audits."""
    import subprocess
    for script in ("leakage_audit.py", "instrument_audit.py"):
        typer.echo(f"\n=== {script} ===")
        subprocess.run([sys.executable, str(ROOT / "scripts" / script)], check=False)


def main() -> None:
    app()


if __name__ == "__main__":
    main()
