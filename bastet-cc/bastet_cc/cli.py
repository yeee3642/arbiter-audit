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
    synth: bool = typer.Option(True, help="include synthesised detectors"),
    verify: bool = typer.Option(True, help="run the refutation pass"),
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

    repos = _split_repos(target) if target in ("train_syn", "dev", "test") else [target]
    paths = [Path(r) if Path(r).is_dir() else _repo_dir(r) for r in repos]

    dets = _load_detectors(synth)
    indexes = [index_repo(p) for p in paths]
    fit(dets, indexes)

    tasks = []
    for p, ix in zip(paths, indexes):
        tasks.extend(plan(arm, dets, p, repo_index=ix))

    store = RunStore(RUNS / run)
    store.write_manifest({
        "arm": arm, "model": model, "prompt_version": PROMPT_VERSION,
        "target": target, "repos": repos, "concurrency": concurrency,
        "detectors": len(dets), "detector_dirs": [str(d) for d in _detector_dirs(synth)],
        "verify": verify,
        "splits_sha256": json.loads((DATA / "splits.json").read_text()).get("splits_sha256"),
    })
    store.write_tasks(tasks, model, PROMPT_VERSION)

    done = store.done_ids()
    typer.echo(f"{arm}: {len(tasks)} tasks over {len(repos)} repos, {len(done)} already done")

    async def _go() -> None:
        from .executor import run_tasks
        client = LLMClient(
            base_url=DEFAULT_BASE_URL, api_key=_api_key(),
            model=model, max_concurrency=concurrency,
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
    truth_df = pd.read_csv(DATA / "train.csv")
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
) -> None:
    """Fit the decision layer on DEV and freeze it for the TEST run."""
    import pandas as pd
    from dataclasses import asdict

    from .aggregate import format_sweep, grid_search
    from .runstore import RunStore

    if split == "test":
        typer.secho("calibrating on TEST defeats the freeze protocol", fg=typer.colors.RED)
        raise typer.Exit(2)

    store = RunStore(RUNS / run)
    findings = store.load_findings()
    repos = _split_repos(split)
    truth_df = pd.read_csv(DATA / "train.csv")

    calib, sweep = grid_search(findings, truth_df, repos)
    typer.echo(format_sweep(calib))
    out.parent.mkdir(parents=True, exist_ok=True)
    out.write_text(json.dumps(asdict(calib), indent=2, default=list))
    typer.echo(f"\nwrote {out}  ({len(sweep)} grid points)")


@app.command()
def figures(mode: str = typer.Option("both", help="light | dark | both")) -> None:
    """Render every figure from the measurement artefacts already on disk."""
    from .report import build_all

    paths = build_all()
    for p in paths:
        typer.echo(f"  {p}")
    typer.echo(f"{len(paths)} files")


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
