"""Finding: the unit everything downstream consumes, plus the LLM-output parser.

The model only decides subtag/severity/description/confidence; the tag comes from the
detector that asked (DESIGN §1.3). That keeps a hallucinated tag from ever entering
scoring -- a detector can be wrong about a repo, but not about which class it detects.

Normalization lives here because the model's vocabulary is wider than the schema's:
probes showed severity `"Critical"` when left unpinned (MODEL_NOTES.md), and
contract/function names sometimes drift from the slice headers. Drifted locations are
kept but marked `[unmatched]` in evidence rather than dropped -- a real finding with a
sloppy address still counts at repo x tag granularity, and the verifier gets a chance
to check it.
"""

from __future__ import annotations

from dataclasses import asdict, dataclass, field, fields

from .routing import Task
from .llm import LLMResult
from .tags import canonical_tag


@dataclass
class Finding:
    repo: str
    detector_id: str
    tag: str            # canonical (tags.canonical_tag)
    subtag: str
    severity: str       # "High" | "Medium" | "Low"
    path: str
    contract: str
    function: str
    description: str
    evidence: str       # line refs, e.g. "L42-L47"
    confidence: float   # model self-estimate 0..1
    verdict: str = "unverified"   # unverified | confirmed | rejected | uncertain
    task_id: str = ""


_FIELD_NAMES = {f.name for f in fields(Finding)}

# The schema allows High/Medium/Low only, but unpinned models emit Critical/Info
# variants; fold them onto the nearest schema value instead of losing the finding.
_SEVERITY = {
    "high": "High", "critical": "High",
    "medium": "Medium", "med": "Medium", "moderate": "Medium",
    "low": "Low", "info": "Low", "informational": "Low",
}


def normalize_severity(raw: object) -> str:
    s = str(raw or "").strip()
    return _SEVERITY.get(s.lower(), s.title() if s else "Medium")


def _clamp_confidence(raw: object) -> float:
    # Missing confidence means the model gave no signal either way -> 0.5 (DESIGN §1.3).
    try:
        v = float(raw)  # type: ignore[arg-type]
    except (TypeError, ValueError):
        return 0.5
    return min(1.0, max(0.0, v))


def parse_findings(task: Task, result: LLMResult) -> list[Finding]:
    """LLM output -> normalized Findings for one task. Never raises: garbage in,
    empty list out, and the error is already recorded on the LLMResult."""
    if result.parsed is None or not isinstance(result.parsed, dict):
        return []
    items = result.parsed.get("findings")
    if not isinstance(items, list):
        return []

    # Deferred import: runstore imports Finding from here, so the reverse edge must
    # not exist at module load time.
    from .prompts import PROMPT_VERSION
    from .runstore import task_id as make_task_id
    tid = make_task_id(task, result.model, PROMPT_VERSION)

    repo = task.slices[0].repo if task.slices else ""
    tag = canonical_tag(task.detector.tags[0]) if task.detector.tags else ""
    by_pair = {(sl.contract, sl.function): sl for sl in task.slices}
    by_function = {sl.function: sl for sl in task.slices}

    out: list[Finding] = []
    for item in items:
        if not isinstance(item, dict):
            continue
        # Absent `vulnerable` still counts: the model reported it as a finding.
        if item.get("vulnerable") is False:
            continue
        contract = str(item.get("contract") or "").strip()
        function = str(item.get("function") or "").strip()
        evidence = str(item.get("evidence") or "").strip()

        sl = by_pair.get((contract, function)) or by_function.get(function)
        if sl is not None:
            path, contract = sl.path, sl.contract
        else:
            path = task.path
            evidence = (evidence + " [unmatched]").strip()

        out.append(Finding(
            repo=repo,
            detector_id=task.detector.id,
            tag=tag,
            subtag=str(item.get("subtag") or "").strip(),
            severity=normalize_severity(item.get("severity")),
            path=path,
            contract=contract,
            function=function,
            description=str(item.get("description") or "").strip(),
            evidence=evidence,
            confidence=_clamp_confidence(item.get("confidence")),
            verdict="unverified",
            task_id=tid,
        ))
    return out


def to_dict(finding: Finding) -> dict:
    return asdict(finding)


def from_dict(d: dict) -> Finding:
    """Tolerant inverse of to_dict: unknown keys dropped, missing keys defaulted, so
    results.jsonl written by older code versions still loads."""
    known = {k: v for k, v in d.items() if k in _FIELD_NAMES}
    known.setdefault("repo", "")
    known.setdefault("detector_id", "")
    known.setdefault("tag", "")
    known.setdefault("subtag", "")
    known.setdefault("severity", "Medium")
    known.setdefault("path", "")
    known.setdefault("contract", "")
    known.setdefault("function", "")
    known.setdefault("description", "")
    known.setdefault("evidence", "")
    known.setdefault("confidence", 0.5)
    return Finding(**known)


def to_upstream_row(finding: Finding, property_id: str = "") -> dict:
    """One row in the upstream/Kaggle ground-truth column layout, for the demo
    submission csv and any comparison against train.csv."""
    return {
        "Property": property_id,
        "repo_path": finding.repo,
        "severity": finding.severity,
        "tag": finding.tag,
        "subtag": finding.subtag,
        "description": finding.description,
    }
