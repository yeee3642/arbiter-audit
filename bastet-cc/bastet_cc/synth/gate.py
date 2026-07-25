"""S4 quality gate: leave-one-repo-out through the real scan pipeline.

A synthesized detector is only trusted once a variant induced *without* repo Ri's
findings still fires on Ri (recall evidence) and stays quiet on repos that are
negative for the tag (precision evidence). Variants go through the identical
route -> build_prompt -> complete -> parse_findings path the production scan uses;
the only shortcut is that a variant's routing signature is its S3-validated hint
set directly (those hints already passed a stricter df cut than routing.fit's).

Failing tags get one repair round: the missed ground-truth functions (or the
false-positive functions) are fed back into S2 as reviewer feedback -- but a fold's
variant never sees material originating from its own held-out repo. Tags that
still fail ship anyway with `gated: true`: coverage claims need 42/42, and gating
(verifier-confirmed findings only, capped prior) is the honest compromise.
"""

from __future__ import annotations

import asyncio
import json
from pathlib import Path

from ..routing import Detector, Slice, Task, route
from ..findings import parse_findings
from ..prompts import DETECTOR_DIRS, OUTPUT_SCHEMA, build_prompt, PROMPT_VERSION
from ..runstore import task_id as make_task_id
from .assemble import detector_id, render_body, slug
from .induce import induce_tag, load_induction, save_induction
from .hints import validate_hints, required_hints_for

# Full LORO for the ten highest-volume missing tags (DESIGN §2.3 S4); the long
# tail gets a single holdout for cost.
TOP10 = ["Accounting Error", "Governance", "Liquidation", "Cross-Chain", "MEV",
         "ERC1155", "DAO", "Upgradeable", "ERC777", "Pause"]

# Deviation from DESIGN (which caps nothing): Accounting Error alone has 16
# positive TRAIN-SYN repos, so unbounded LORO would triple the stage's call
# budget. Folds are capped at the first 5 positive repos (sorted, deterministic).
MAX_FOLDS = 5
N_NEG_REPOS = 2
MAX_TASKS_PER_REPO = 25     # cost cap per (variant, repo) scan, largest-match first
MAX_TASK_CODE_CHARS = 60_000
HIT_MEAN_MIN = 0.5
FP_MEAN_MAX = 0.5


def tag_positive_repos(records: list[dict], tag: str) -> list[str]:
    return sorted({r["repo"] for r in records if tag in r["tags"]})


def negative_repos(records: list[dict], tag: str, train_syn: list[str]) -> list[str]:
    pos = set(tag_positive_repos(records, tag))
    return [r for r in sorted(train_syn) if r not in pos][:N_NEG_REPOS]


def _localized(records: list[dict], tag: str, exclude_repo: str | None = None):
    return [r for r in records if r["localized"] and tag in r["tags"]
            and r["repo"] != (exclude_repo or "")]


def localized_ident_sets(records: list[dict], tag: str,
                         exclude_repo: str | None = None) -> list[set[str]]:
    return [set(r["identifiers"]) for r in _localized(records, tag, exclude_repo)]


def localized_repos(records: list[dict], tag: str,
                    exclude_repo: str | None = None) -> list[str]:
    """Repo of each entry in `localized_ident_sets`, same order -- S3 needs the
    attribution to tell class vocabulary from one repo's private vocabulary."""
    return [r["repo"] for r in _localized(records, tag, exclude_repo)]


def register_workdir(workdir: Path) -> None:
    """Make gate-variant markdown resolvable by prompts.detection_prompt without
    polluting detectors_synth/ (variants are run artifacts, not deliverables)."""
    workdir = Path(workdir)
    workdir.mkdir(parents=True, exist_ok=True)
    if workdir not in DETECTOR_DIRS:
        DETECTOR_DIRS.append(workdir)


def write_variant(variant_id: str, name: str, det_json: dict, hints: list[str],
                  workdir: Path) -> Detector:
    """Persist a variant md and return its routed Detector (signature = validated
    hints; synthesized detectors never broadcast)."""
    body = render_body(name, det_json)
    (Path(workdir) / f"{variant_id}.md").write_text(
        f"# {name}\n\n## Detection prompt\n\n{body}\n")
    det = Detector(id=variant_id, name=name, source_workflow="synthesized",
                   tags=[det_json.get("_tag") or name], routing_hints=hints,
                   prompt_chars=len(body))
    det.signature = set(hints)
    det.broadcast = False
    return det


def _file_ident_sets(repo_index: dict) -> dict[str, set[str]]:
    out: dict[str, set[str]] = {}
    for f in repo_index["files"]:
        s: set[str] = set()
        for fn in f["functions"]:
            s.update(fn.get("identifiers") or [])
        out[f["path"]] = s
    return out


async def scan_repo(det: Detector, tag: str, repo_index: dict,
                    required_hints: list[str], client) -> dict:
    """One (variant, repo) scan through the production path. Returns
    {repo, n_tasks, n_calls, findings: [Finding]}."""
    det.tags = [tag]
    tasks = route([det], repo_index)

    if required_hints:
        by_path = _file_ident_sets(repo_index)
        tasks = [t for t in tasks
                 if set(required_hints) <= by_path.get(t.path, set())]

    # Cost caps (deviation, documented): most-matched files first, oversized
    # payloads truncated at the slice boundary.
    tasks.sort(key=lambda t: (-len(t.slices), t.path))
    tasks = tasks[:MAX_TASKS_PER_REPO]
    for t in tasks:
        kept, used = [], 0
        for sl in t.slices:
            if kept and used + len(sl.source) > MAX_TASK_CODE_CHARS:
                continue
            kept.append(sl)
            used += len(sl.source)
        t.slices = kept

    calls = []
    for t in tasks:
        system, user = build_prompt(t, None)
        calls.append({"system": system, "user": user, "schema": OUTPUT_SCHEMA,
                      "task_id": make_task_id(t, client.model, PROMPT_VERSION)})
    results = await client.complete_many(calls) if calls else []

    found = []
    for t, res in zip(tasks, results):
        found.extend(parse_findings(t, res))
    return {"repo": repo_index["repo"], "n_tasks": len(tasks),
            "n_calls": len(calls), "findings": found}


async def probe_localized(det: Detector, tag: str, records: list[dict], repo: str,
                          client) -> dict:
    """Diagnostic: run the variant prompt directly on repo's known vulnerable
    functions, bypassing routing.

    A routed miss has two very different causes -- the hints never reached the file,
    or the prompt read the file and saw nothing -- and the repair loop and the
    write-up need to tell them apart. The probe answers the second question alone,
    so `hit` (DESIGN's pass criterion) stays a pure end-to-end routed measurement
    and this number is only ever reported alongside it.
    """
    slices = []
    for rec in records:
        if rec["repo"] != repo or tag not in rec["tags"]:
            continue
        for m in rec["matches"][:1]:
            slices.append(Slice(repo=repo, path=m["path"], contract=m["contract"],
                                function=m["function"], start_line=m["start_line"],
                                end_line=m["end_line"], source=m["source"]))
    if not slices:
        return {"n_slices": 0, "hit": None, "n_calls": 0}
    slices = slices[:8]
    task = Task(detector=det, path=slices[0].path, slices=slices)
    system, user = build_prompt(task, None)
    res = await client.complete(system, user, schema=OUTPUT_SCHEMA,
                                task_id=f"s4probe|{det.id}")
    return {"n_slices": len(slices), "hit": bool(parse_findings(task, res)),
            "n_calls": 1}


def _feedback_items(records: list[dict], tag: str, missed_repos: list[str],
                    fp_findings: list, repo_indexes: dict[str, dict]) -> list[dict]:
    """Repair material: real missed vulnerable functions and wrongly-flagged
    functions, each tagged with its origin repo so a fold can exclude its own."""
    items: list[dict] = []
    for repo in missed_repos:
        n = 0
        for rec in records:
            if rec["repo"] != repo or tag not in rec["tags"] or not rec["matches"]:
                continue
            for m in rec["matches"][:1]:
                src = "\n".join(m["source"].splitlines()[:60])
                items.append({"repo": repo, "text": (
                    "MISSED vulnerability. Your detector failed to fire on this "
                    f"real vulnerable function (fault: {m['fault_pattern'] or rec['description'][:200]}):\n"
                    f"```solidity\n{src}\n```\nRevise the checks so this is caught.")})
                n += 1
            if n >= 2:
                break
    seen = 0
    for f in fp_findings:
        if seen >= 2:
            break
        ix = repo_indexes.get(f.repo)
        if ix is None:
            continue
        for file in ix["files"]:
            if file["path"] != f.path:
                continue
            for fn in file["functions"]:
                if fn["name"] == f.function:
                    src = "\n".join((fn.get("source") or "").splitlines()[:60])
                    items.append({"repo": f.repo, "text": (
                        "FALSE POSITIVE. Your detector wrongly flagged this "
                        f"function (its claim: {f.description[:200]}):\n"
                        f"```solidity\n{src}\n```\nTighten the checks so safe "
                        "code like this is not reported.")})
                    seen += 1
                    break
            break
    return items


async def _run_folds(tag: str, tagdef: dict, records: list[dict],
                     fold_repos: list[str], neg_repos: list[str],
                     repo_indexes: dict[str, dict],
                     file_sets: dict[str, list[set[str]]],
                     req_hints: list[str], client, workdir: Path, s2_dir: Path,
                     suffix: str = "",
                     feedback: list[dict] | None = None) -> list[dict]:
    """Induce + scan every fold variant of one tag; returns fold result dicts."""
    async def one_fold(ri: str) -> dict:
        fb_texts = [i["text"] for i in (feedback or []) if i["repo"] != ri] or None
        cached = None if suffix else load_induction(tag, s2_dir, exclude_repo=ri)
        if cached is None:
            cached = await induce_tag(tag, tagdef, records, client,
                                      exclude_repo=ri, feedback=fb_texts,
                                      task_id=f"s4|{tag}|{ri}{suffix}")
            if not suffix:
                save_induction(cached, s2_dir)
        pos_minus = [r for r in tag_positive_repos(records, tag) if r != ri]
        hres = validate_hints(
            tag, cached["detector"]["routing_hint_candidates"], file_sets,
            pos_minus, localized_ident_sets(records, tag, exclude_repo=ri),
            localized_repos(records, tag, exclude_repo=ri))
        variant_id = f"{detector_id(tag)}__gate_{ri}{suffix}"
        det = write_variant(variant_id, cached["detector"]["name"] or tag,
                            cached["detector"], hres["kept"], workdir)
        pos_scan = await scan_repo(det, tag, repo_indexes[ri], req_hints, client)
        neg_scans = await asyncio.gather(*(
            scan_repo(det, tag, repo_indexes[nr], req_hints, client)
            for nr in neg_repos))
        probe = {"n_slices": 0, "hit": None, "n_calls": 0}
        if not pos_scan["findings"]:
            probe = await probe_localized(det, tag, records, ri, client)
        return {
            "repo": ri, "variant_id": variant_id, "mode": cached["mode"],
            "hints": hres["kept"],
            "hit": bool(pos_scan["findings"]),
            "n_pos_tasks": pos_scan["n_tasks"],
            "n_pos_findings": len(pos_scan["findings"]),
            "probe_hit": probe["hit"],
            "neg": {s["repo"]: bool(s["findings"]) for s in neg_scans},
            "n_calls": (pos_scan["n_calls"] + probe["n_calls"]
                        + sum(s["n_calls"] for s in neg_scans)),
            "fp_findings": [f for s in neg_scans for f in s["findings"]],
        }

    return list(await asyncio.gather(*(one_fold(r) for r in fold_repos)))


def _metrics(folds: list[dict]) -> tuple[float, float]:
    hit = sum(f["hit"] for f in folds) / len(folds)
    neg_flags = [v for f in folds for v in f["neg"].values()]
    fp = sum(neg_flags) / len(neg_flags) if neg_flags else 0.0
    return hit, fp


async def gate_tag(tag: str, tagdef: dict, records: list[dict],
                   repo_indexes: dict[str, dict],
                   file_sets: dict[str, list[set[str]]],
                   train_syn: list[str], client, workdir: Path,
                   s2_dir: Path) -> dict:
    """Full LORO (top-10 tags) or single holdout; one repair round on failure."""
    pos = tag_positive_repos(records, tag)
    req_hints = required_hints_for(tag, file_sets, pos)
    if not pos:
        return {"tag": tag, "folds": [], "hit_mean": None, "fp_mean": None,
                "passed": None, "repaired": False, "required_hints": req_hints,
                "reason": "no positive TRAIN-SYN repos; cannot gate"}

    loro = tag in TOP10 and len(pos) >= 2
    fold_repos = pos[:MAX_FOLDS] if loro else pos[:1]
    negs = negative_repos(records, tag, train_syn)

    folds = await _run_folds(tag, tagdef, records, fold_repos, negs,
                             repo_indexes, file_sets, req_hints, client,
                             workdir, s2_dir)
    hit, fp = _metrics(folds)
    passed = hit >= HIT_MEAN_MIN and fp <= FP_MEAN_MAX
    repaired = False
    feedback: list[dict] = []

    if not passed:
        missed = [f["repo"] for f in folds if not f["hit"]]
        fp_findings = [f for fold in folds for f in fold["fp_findings"]]
        feedback = _feedback_items(records, tag, missed, fp_findings, repo_indexes)
        if feedback:
            repaired = True
            folds = await _run_folds(tag, tagdef, records, fold_repos, negs,
                                     repo_indexes, file_sets, req_hints, client,
                                     workdir, s2_dir, suffix="_r1",
                                     feedback=feedback)
            hit, fp = _metrics(folds)
            passed = hit >= HIT_MEAN_MIN and fp <= FP_MEAN_MAX

    for f in folds:
        f.pop("fp_findings", None)
    probes = [f["probe_hit"] for f in folds if f["probe_hit"] is not None]
    return {"tag": tag, "loro": loro, "folds": folds,
            "hit_mean": round(hit, 3), "fp_mean": round(fp, 3),
            "routed_zero": sum(1 for f in folds if f["n_pos_tasks"] == 0),
            "probe_hit_mean": round(sum(probes) / len(probes), 3) if probes else None,
            "passed": passed, "repaired": repaired,
            "required_hints": req_hints,
            "feedback": [i["text"] for i in feedback],
            "n_calls": sum(f["n_calls"] for f in folds)}


async def run_s4(tags: list[str], tagdefs: dict, records: list[dict],
                 repo_indexes: dict[str, dict],
                 file_sets: dict[str, list[set[str]]], train_syn: list[str],
                 client, workdir: Path, s2_dir: Path,
                 out_path: Path) -> dict[str, dict]:
    """Gate every synthesized tag; cached per tag in out_path."""
    out_path = Path(out_path)
    results: dict[str, dict] = {}
    if out_path.exists():
        results = json.loads(out_path.read_text())

    register_workdir(workdir)
    pending = [t for t in tags if t not in results]
    if pending:
        gated = await asyncio.gather(*(
            gate_tag(t, tagdefs[t], records, repo_indexes, file_sets,
                     train_syn, client, workdir, s2_dir) for t in pending))
        for rec in gated:
            results[rec["tag"]] = rec
        out_path.write_text(json.dumps(results, indent=1))
    return results
