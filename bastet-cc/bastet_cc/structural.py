"""Label-free comparison of two arms: what differs before ground truth arrives.

`compare` answers "which arm is more often right", and it needs labels to do it.
That question is unavailable most of the time -- the corpus is 6.8 GB of other
people's source, `train.csv` is not redistributable, and on TEST the labels may
only be spent once. Yet two arms scanning the same repositories with the same
model differ in ways that are fully determined by the artefacts already on disk,
and those differences are worth measuring on their own terms rather than as a
proxy for accuracy.

Three of the metrics here are properties an auditor cares about directly:

- **Where the finding landed.** A report entry in `contracts/mocks/` is not a
  false positive in the labelling sense -- the mock may genuinely contain the
  pattern -- but nobody is paid to review it, and it costs a reviewer the same
  attention as a real one. `solidity.classify` decides this by path alone, which
  is exactly upstream Bastet's blind spot: it globs `**/*.sol` with no vendor or
  test exclusion.

- **Whether the finding is localisable.** `findings.parse_findings` binds a
  model-reported (contract, function) back to the slice it was asked about, and
  marks the evidence `[unmatched]` when it cannot. This is not a statement about
  the model's care: the broadcast arm sends whole files as a single slice named
  `<file>`, so *no* reported function name can ever match and the whole arm is
  unlocalisable by construction. That is the point. The measurement records a
  consequence of the payload shape, and the consequence is real -- an
  unlocalisable finding cannot be verified, deduplicated by site, or handed to a
  developer as a line range.

- **Redundancy.** Findings per distinct site. Both arms may report the same
  function several times through different detectors; the ratio says how much of
  a report is repetition, which is a reviewer-time cost neither precision nor
  recall charges for.

Nothing here can rank the arms on detection quality, and this module does not
try. It reports asymmetries and names which of them are architectural rather
than empirical, so a reader can tell the two apart.
"""

from __future__ import annotations

import json
from collections import Counter
from dataclasses import dataclass, field
from pathlib import Path

from .findings import Finding
from .solidity import classify

# Written into the evidence string by findings.parse_findings when a reported
# (contract, function) matched no slice in the task.
UNMATCHED = "[unmatched]"


def _site(f: Finding) -> tuple[str, str, str]:
    return (f.path, f.contract, f.function)


@dataclass
class ArmProfile:
    """Everything measurable about one arm's report without consulting labels."""

    run: str
    n_findings: int
    n_sites: int
    by_file_class: dict[str, int]
    n_unlocalisable: int
    n_detectors: int
    n_tags: int
    tags: list[str]
    repos: list[str]
    cost: dict[str, int] = field(default_factory=dict)

    @property
    def redundancy(self) -> float | None:
        """Findings per distinct site; None when the arm reported nothing."""
        return self.n_findings / self.n_sites if self.n_sites else None

    @property
    def offtarget_share(self) -> float | None:
        """Share of findings in vendored or non-production files."""
        if not self.n_findings:
            return None
        off = sum(n for k, n in self.by_file_class.items() if k != "core")
        return off / self.n_findings

    @property
    def localisable_share(self) -> float | None:
        if not self.n_findings:
            return None
        return 1.0 - self.n_unlocalisable / self.n_findings

    def to_dict(self) -> dict:
        return {
            "run": self.run,
            "n_findings": self.n_findings,
            "n_sites": self.n_sites,
            "by_file_class": dict(sorted(self.by_file_class.items())),
            "n_unlocalisable": self.n_unlocalisable,
            "localisable_share": self.localisable_share,
            "offtarget_share": self.offtarget_share,
            "redundancy": self.redundancy,
            "n_detectors": self.n_detectors,
            "n_tags": self.n_tags,
            "tags": self.tags,
            "repos": self.repos,
            "cost": self.cost,
        }


def read_cost(run_dir: Path) -> dict[str, int]:
    """Call and token cost for a run, from whichever artefact survived.

    `tasks.jsonl` is the plan and is gitignored; `llm_log.jsonl` holds real usage
    and is gitignored too. A committed run therefore usually has neither, and the
    honest answer is an empty dict rather than a zero -- a zero would render in a
    table as "this arm was free".
    """
    out: dict[str, int] = {}
    tasks = run_dir / "tasks.jsonl"
    if tasks.exists():
        calls = code_chars = 0
        for line in tasks.read_text(errors="ignore").splitlines():
            if not line.strip():
                continue
            try:
                rec = json.loads(line)
            except json.JSONDecodeError:
                continue
            calls += 1
            code_chars += int(rec.get("code_chars") or 0)
        out["planned_calls"] = calls
        out["code_chars"] = code_chars

    log = run_dir / "llm_log.jsonl"
    if log.exists():
        calls = in_tok = out_tok = 0
        for line in log.read_text(errors="ignore").splitlines():
            if not line.strip():
                continue
            try:
                rec = json.loads(line)
            except json.JSONDecodeError:
                continue
            calls += 1
            in_tok += int(rec.get("input_tokens") or 0)
            out_tok += int(rec.get("output_tokens") or 0)
        out["actual_calls"] = calls
        out["input_tokens"] = in_tok
        out["output_tokens"] = out_tok
    return out


def profile(run: str, findings: list[Finding], run_dir: Path | None = None) -> ArmProfile:
    return ArmProfile(
        run=run,
        n_findings=len(findings),
        n_sites=len({_site(f) for f in findings}),
        by_file_class=dict(Counter(classify(f.path) for f in findings)),
        n_unlocalisable=sum(1 for f in findings if UNMATCHED in f.evidence),
        n_detectors=len({f.detector_id for f in findings}),
        n_tags=len({f.tag for f in findings if f.tag}),
        tags=sorted({f.tag for f in findings if f.tag}),
        repos=sorted({f.repo for f in findings if f.repo}),
        cost=read_cost(run_dir) if run_dir else {},
    )


def compare_structural(a: ArmProfile, b: ArmProfile,
                       findings_a: list[Finding],
                       findings_b: list[Finding]) -> dict:
    """Asymmetries between two arms, with the shared repository set named.

    Site agreement is computed on the intersection of the two arms' repositories.
    Comparing reports over different repositories would count a repository only
    one arm scanned as disagreement, which is a scope difference and not a
    behavioural one.
    """
    shared = sorted(set(a.repos) & set(b.repos))
    only_a_repos = sorted(set(a.repos) - set(b.repos))
    only_b_repos = sorted(set(b.repos) - set(a.repos))

    sa = {_site(f) for f in findings_a if f.repo in shared}
    sb = {_site(f) for f in findings_b if f.repo in shared}

    ta = {f.tag for f in findings_a if f.repo in shared and f.tag}
    tb = {f.tag for f in findings_b if f.repo in shared and f.tag}

    return {
        "shared_repos": shared,
        "repos_only_in_a": only_a_repos,
        "repos_only_in_b": only_b_repos,
        "comparable": bool(shared),
        "sites": {
            "both": len(sa & sb),
            "only_a": len(sa - sb),
            "only_b": len(sb - sa),
            "jaccard": (len(sa & sb) / len(sa | sb)) if (sa | sb) else None,
        },
        "tags": {
            "both": sorted(ta & tb),
            "only_a": sorted(ta - tb),
            "only_b": sorted(tb - ta),
        },
        "arm_a": a.to_dict(),
        "arm_b": b.to_dict(),
    }


def format_structural(result: dict, label_a: str, label_b: str) -> str:
    """Render the comparison, flagging which rows are architectural.

    A row marked (arch) is determined by the arm's design rather than measured
    from its behaviour, so it cannot move with a better model and must not be
    read as a quality gap.
    """
    a, b = result["arm_a"], result["arm_b"]

    def num(v: object, spec: str = "") -> str:
        if v is None:
            return "n/a"
        if isinstance(v, float):
            return format(v, spec or ".3f")
        return format(v, spec) if spec else str(v)

    # +2 so a run id exactly as wide as the column still leaves a gap between
    # the two arms; run ids like `d1_broadcast_dev1` otherwise abut the header.
    w = max(len(label_a), len(label_b), 9) + 2
    lines = [
        f"{'metric':<34}{label_a:>{w}}{label_b:>{w}}",
        "-" * (34 + 2 * w),
        f"{'findings reported':<34}{num(a['n_findings']):>{w}}{num(b['n_findings']):>{w}}",
        f"{'distinct sites':<34}{num(a['n_sites']):>{w}}{num(b['n_sites']):>{w}}",
        f"{'findings per site':<34}{num(a['redundancy']):>{w}}{num(b['redundancy']):>{w}}",
        f"{'in vendor/non-production code':<34}"
        f"{num(a['offtarget_share'], '.1%'):>{w}}{num(b['offtarget_share'], '.1%'):>{w}}",
        f"{'localisable to a function (arch)':<34}"
        f"{num(a['localisable_share'], '.1%'):>{w}}{num(b['localisable_share'], '.1%'):>{w}}",
        f"{'detectors that fired':<34}{num(a['n_detectors']):>{w}}{num(b['n_detectors']):>{w}}",
        f"{'tags covered':<34}{num(a['n_tags']):>{w}}{num(b['n_tags']):>{w}}",
    ]

    for key, title in (("planned_calls", "planned LLM calls"),
                       ("actual_calls", "actual LLM calls"),
                       ("input_tokens", "input tokens")):
        if key in a["cost"] or key in b["cost"]:
            lines.append(
                f"{title:<34}{num(a['cost'].get(key)):>{w}}{num(b['cost'].get(key)):>{w}}")

    s = result["sites"]
    lines += [
        "",
        f"shared repositories: {len(result['shared_repos'])}"
        + (f"   (only in {label_a}: {len(result['repos_only_in_a'])},"
           f" only in {label_b}: {len(result['repos_only_in_b'])})"
           if result["repos_only_in_a"] or result["repos_only_in_b"] else ""),
        f"site agreement     : both {s['both']}, only {label_a} {s['only_a']}, "
        f"only {label_b} {s['only_b']}"
        + (f", Jaccard {s['jaccard']:.3f}" if s["jaccard"] is not None else ""),
    ]
    if result["tags"]["only_a"] or result["tags"]["only_b"]:
        lines.append(f"tags only {label_a:<9}: {', '.join(result['tags']['only_a']) or '-'}")
        lines.append(f"tags only {label_b:<9}: {', '.join(result['tags']['only_b']) or '-'}")

    lines += [
        "",
        "(arch) = fixed by the arm's payload shape, not measured from its output.",
        "No row here ranks detection quality; that needs labels (`compare`).",
    ]
    return "\n".join(lines)
