"""The single point where the routed and broadcast arms diverge.

Everything downstream of `plan()` -- executor, prompts, parser, scorer, model -- is
shared between both arms (DESIGN 0.1). Any measured difference between the arms must
therefore be attributable to what happens in this file, so the two branches are kept
deliberately asymmetric in fidelity:

- routed: delegates to routing.route() over a tree-sitter index, then applies the
  required_hints all-of gate (DESIGN 1.2), then optionally one-hop call closure.
  This arm is ours; it may be smart.
- broadcast: replicates upstream Bastet's cli/commands/scan/scan.py: a recursive
  glob("**/*.sol") with NO vendor/test exclusion and NO scope.txt, the whole file as
  payload, one call per (file, detector). This arm must NOT be helped -- any filter
  smuggled in here silently voids the cost and accuracy comparison.

Known deliberate deviations of the broadcast arm from upstream, both logged:
- files above BROADCAST_TRUNCATE_CHARS are truncated (upstream just dies on a
  context overflow, which would abort the whole benchmark run);
- undecodable bytes are replaced rather than crashing open().read().
"""

from __future__ import annotations

import logging
from pathlib import Path
from typing import Literal

from . import routing
from .routing import Detector, Slice, Task

log = logging.getLogger(__name__)

# Upstream sends whole files with no size guard; a ~200K-char file at ~4 chars/token
# alone approaches the 262K-token window before the detector prompt is added. We cap
# instead of crashing so the broadcast arm can finish the benchmark upstream cannot.
BROADCAST_TRUNCATE_CHARS = 200_000


def _file_identifier_sets(repo_index: dict) -> dict[str, set[str]]:
    """Per-file union of function identifiers, the domain required_hints gate over."""
    out: dict[str, set[str]] = {}
    for f in repo_index["files"]:
        idents: set[str] = set()
        for fn in f["functions"]:
            idents.update(fn["identifiers"])
        out[f["path"]] = idents
    return out


def _apply_required_hints(tasks: list[Task], repo_index: dict) -> list[Task]:
    """Drop tasks whose file lacks ANY of the detector's required_hints.

    routing_hints keep their OR semantics inside route(); required_hints are an
    all-of precondition that kills category detectors (ERC777, ERC1155, ...) on
    files that cannot possibly host the vulnerability class, at zero LLM cost.
    getattr keeps this compatible with Detector instances predating the field
    (DESIGN appendix B item 1 belongs to the routing owner).
    """
    file_idents: dict[str, set[str]] | None = None
    kept: list[Task] = []
    for t in tasks:
        required = getattr(t.detector, "required_hints", None) or []
        if not required:
            kept.append(t)
            continue
        if file_idents is None:  # built lazily: no detector uses the gate yet
            file_idents = _file_identifier_sets(repo_index)
        if set(required) <= file_idents.get(t.path, set()):
            kept.append(t)
    if file_idents is not None and len(kept) < len(tasks):
        log.info("required_hints gate dropped %d/%d tasks", len(tasks) - len(kept), len(tasks))
    return kept


def _plan_routed(detectors: list[Detector], repo_index: dict,
                 closure: bool = False) -> list[Task]:
    unfitted = [d.id for d in detectors if d.signature is None]
    if unfitted:
        raise ValueError(
            f"routed plan requires routing.fit() to have run first; unfitted detectors: "
            f"{unfitted[:5]}{'...' if len(unfitted) > 5 else ''}")
    tasks = _apply_required_hints(routing.route(detectors, repo_index), repo_index)
    if closure:
        # Ablation arm R3 (DESIGN 3.2): same routing decision, larger payload. It
        # changes what each call *sees*, never which calls happen -- so a delta
        # between this and plain routed is attributable to context alone, and the
        # call-count comparison against broadcast is unaffected.
        from .callgraph import expand_tasks
        stats = expand_tasks(tasks, repo_index)
        log.info("call closure: %d/%d slices expanded, +%d tokens est",
                 stats["slices_expanded"], stats["slices"], stats["added_tokens_est"])
        _LAST_CLOSURE_STATS.clear()
        _LAST_CLOSURE_STATS.update(stats)
    return tasks


# Written by _plan_routed so the caller can record closure cost in the run
# manifest without plan() growing a second return value that every call site
# would have to unpack.
_LAST_CLOSURE_STATS: dict = {}


def last_closure_stats() -> dict:
    """Closure cost from the most recent routed plan; empty when closure was off."""
    return dict(_LAST_CLOSURE_STATS)


def _plan_broadcast(detectors: list[Detector], repo_root: Path) -> list[Task]:
    repo_root = Path(repo_root)
    repo = repo_root.name

    # Upstream: glob.glob(os.path.join(folder_path, "**/*.sol"), recursive=True) --
    # every .sol file, vendor and test code included, scope.txt ignored. Sorting only
    # fixes iteration order (upstream's is filesystem-dependent); the file SET is
    # identical, which is what fidelity means here.
    tasks: list[Task] = []
    n_truncated = 0
    for path in sorted(repo_root.rglob("*.sol")):
        rel = path.relative_to(repo_root).as_posix()
        try:
            source = path.read_text(errors="replace")
        except OSError as e:
            log.warning("broadcast: unreadable %s/%s (%s), skipped", repo, rel, e)
            continue
        if len(source) > BROADCAST_TRUNCATE_CHARS:
            n_truncated += 1
            log.warning(
                "broadcast: %s/%s truncated %d -> %d chars (upstream overflows context here)",
                repo, rel, len(source), BROADCAST_TRUNCATE_CHARS)
            source = source[:BROADCAST_TRUNCATE_CHARS]
        sl = Slice(
            repo=repo, path=rel, contract="", function="<file>",
            start_line=1, end_line=max(1, source.count("\n") + 1), source=source,
        )
        # Upstream iterates files outer, workflows inner; preserved for tasks.jsonl
        # readability (the executor re-sorts by task_id anyway).
        for d in detectors:
            tasks.append(Task(detector=d, path=rel, slices=[sl]))
    if n_truncated:
        log.warning("broadcast: %d file(s) truncated in %s", n_truncated, repo)
    return tasks


def plan(mode: Literal["routed", "broadcast"],
         detectors: list[Detector],
         repo_root: Path,
         repo_index: dict | None = None,
         signatures: dict | None = None,
         closure: bool = False) -> list[Task]:
    """Build the call plan for one repo. `signatures` is the stats dict returned by
    routing.fit() -- fit() itself mutates the detectors, so the dict is accepted only
    for manifest bookkeeping and is not consulted here.

    `closure` is routed-only and rejected on the broadcast arm rather than
    ignored: silently accepting a flag that helps the control condition is
    exactly the smuggling this module exists to prevent, and a caller that passes
    it has misunderstood the experiment.
    """
    if mode == "routed":
        if repo_index is None:
            raise ValueError("routed plan requires a repo_index from solidity.index_repo()")
        return _plan_routed(detectors, repo_index, closure=closure)
    if mode == "broadcast":
        if closure:
            raise ValueError(
                "closure is a routed-arm treatment; enabling it on the broadcast "
                "control would void the comparison (see module docstring)")
        return _plan_broadcast(detectors, repo_root)
    raise ValueError(f"unknown mode {mode!r}")
