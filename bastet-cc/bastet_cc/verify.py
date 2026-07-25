"""Adversarial verification: one round, one call per finding, refutation-first.

DESIGN §2.5. The detector's job is to be suspicious; this pass's job is to be hostile
to the result. The system prompt (prompts.VERIFY_SYSTEM) forbids `confirmed` without a
line-cited attack scenario, and a model that confirms anyway is downgraded here in
code -- self-report is not evidence, the scenario is.

Scope is deliberately narrow. No multi-round debate: the second round mostly relitigates
the first at double the cost, and single-round refutation already removes the bulk of
false positives that a detector prompt produces on innocent code. The verdict does not
delete anything either -- it becomes a multiplier in `aggregate` (confirmed 1.0 /
unverified 0.7 / uncertain 0.4 / rejected 0.0), so a wrong rejection costs a finding its
weight, not its existence.

Context comes from the repository index, never from re-reading files: the indexer
already holds every function's source and line span, and re-reading would let the
verifier see code the detector never got. Because the index stores functions rather
than raw files, "+-30 lines" is reconstructed as the neighbouring functions whose spans
overlap the padded window. A finding whose location cannot be resolved in the index
gets no verdict at all (it stays `unverified`) -- verifying against the wrong code is
worse than not verifying.

The enablement matrix is a parameter, not a constant: DEV decides it (DESIGN §2.5(4))
and `VerifyPolicy` is what DEV's answer is written into.
"""

from __future__ import annotations

import asyncio
import hashlib
import json
import os
import re
import time
from dataclasses import dataclass, field, replace
from functools import lru_cache
from pathlib import Path
from typing import Any, Iterable

# Same error taxonomy as the detect pass: a transient failure must not be frozen into
# the resume log, a permanent one must not be retried forever (executor.py).
from .executor import TRANSIENT_ERRORS
from .findings import Finding, finding_key
from .hermes import EvidencePacket, HermesConfig, build_packet
from .llm import LLMClient
from .prompts import (
    DETECTOR_DIRS,
    TWINCOURT_SCHEMA,
    VERIFY_SCHEMA,
    build_twincourt_prompt,
    build_verify_prompt,
    detection_prompt,
)
from .runstore import RunStore
from .twincourt import (
    OVERLAY_SCHEMA_VERSION,
    TWINCOURT_PROMPT_VERSION,
    TWINCOURT_SCHEMA_VERSION,
    TWINCOURT_TREATMENT,
    TWINCOURT_VERSION,
    adjudication_id,
    normalize_decision,
)

# Bump on any change to VERIFY_SYSTEM, the context builder or the verdict rules:
# it is part of the cache key, so a bump re-runs verification instead of serving
# verdicts formed under different instructions.
VERIFY_PROMPT_VERSION = "v2"

# DESIGN §2.5(1). Enough to see the guard clause a caller placed above the function
# and the modifier defined below it, small enough that a 40-function file does not
# collapse into one prompt.
CONTEXT_PAD_LINES = 30

# A verifier prompt that outgrows this is verifying a file, not a finding; the
# neighbour list is truncated (nearest-first) rather than the target function.
MAX_CONTEXT_CHARS = 24_000

VALID_VERDICTS = ("confirmed", "rejected", "uncertain")

TAG_DEFINITIONS_MD = Path(__file__).resolve().parents[2] / "Tag Definitions.md"


# -- enablement matrix ----------------------------------------------------------


@dataclass
class VerifyPolicy:
    """Which findings get verified (DESIGN §2.5(4)).

    Defaults encode the design's decision: synthesized detectors ON because their
    precision is the open question, gated ones forced ON because they only exist at
    all under supervision, hand-written ones OFF because they are upstream's own
    prompts and paying a second call for each is what routing just saved. A
    hand-written detector opens individually once DEV shows it firing wrongly more
    than half the time -- `force_on` is where `fit_calibration`'s enablement table
    gets applied.
    """
    synthesized: bool = True
    gated: bool = True
    handwritten: bool = False
    force_on: set[str] = field(default_factory=set)     # detector ids
    force_off: set[str] = field(default_factory=set)    # detector ids
    off_tags: set[str] = field(default_factory=set)     # verifier hurts recall here

    @classmethod
    def all_on(cls) -> "VerifyPolicy":
        return cls(synthesized=True, gated=True, handwritten=True)

    @classmethod
    def all_off(cls) -> "VerifyPolicy":
        return cls(synthesized=False, gated=False, handwritten=False)

    @classmethod
    def from_enablement_table(cls, rows: Iterable[dict], **kw) -> "VerifyPolicy":
        """Build from `aggregate.verify_enablement_table` output."""
        force_on = {r["detector_id"] for r in rows if r.get("verify")}
        force_off = {r["detector_id"] for r in rows if not r.get("verify")}
        return cls(force_on=force_on, force_off=force_off, **kw)

    def enabled(self, finding: Finding, meta: dict | None = None) -> bool:
        meta = meta or {}
        if finding.tag in self.off_tags:
            return False
        if finding.detector_id in self.force_on:
            return True
        if finding.detector_id in self.force_off:
            return False
        if meta.get("gated"):
            return self.gated
        if meta.get("synthesized") or meta.get("source_workflow") == "synthesized":
            return self.synthesized
        return self.handwritten


@lru_cache(maxsize=1)
def load_detector_meta(dirs: tuple[Path, ...] | None = None) -> dict[str, dict]:
    """{detector_id: {source_workflow, synthesized, gated}} from the index files.

    Read from index.json rather than the `Detector` dataclass because the synthesized
    fields (`gated`, `synthesized`) are an appendix-B addition to that dataclass that
    routing.py has not taken yet; the index already carries them, and a detector
    missing from every index is treated as hand-written.
    """
    out: dict[str, dict] = {}
    for d in (dirs or tuple(DETECTOR_DIRS)):
        path = Path(d) / "index.json"
        if not path.exists():
            continue
        for entry in json.loads(path.read_text(encoding="utf-8")):
            out[entry["id"]] = {
                "source_workflow": entry.get("source_workflow", ""),
                "synthesized": bool(entry.get("synthesized")),
                "gated": bool(entry.get("gated")),
            }
    return out


# -- prompt material ------------------------------------------------------------


_TABLE_ROW = re.compile(r"^\|(?P<cells>.+)\|\s*$")


@lru_cache(maxsize=1)
def _tag_definitions(path: str = "") -> dict[str, str]:
    """Tag -> official description, parsed from the Tag Definitions markdown table."""
    md = Path(path) if path else TAG_DEFINITIONS_MD
    if not md.exists():
        return {}
    out: dict[str, str] = {}
    for line in md.read_text(encoding="utf-8", errors="replace").splitlines():
        m = _TABLE_ROW.match(line.strip())
        if not m:
            continue
        cells = [c.strip() for c in m.group("cells").split("|")]
        if len(cells) < 2 or not cells[0] or set(cells[0]) <= {"-", ":"}:
            continue
        if cells[0] in ("Title", "Tag"):
            continue
        # First table in the file is the tag table; the subtag table reuses the same
        # column layout, so a later duplicate title must not clobber an earlier one.
        out.setdefault(cells[0], cells[1].replace("<br>", " ").strip())
    return out


def tag_definition(tag: str) -> str:
    """The official definition text for a tag, or a neutral fallback.

    The verifier needs the taxonomy's own wording: half of a false positive is a
    finding that is real but belongs to a different tag, and only the definition
    lets the model say so.
    """
    defs = _tag_definitions()
    from .tags import canonical_tag
    return defs.get(tag) or defs.get(canonical_tag(tag)) or (
        f"(no official definition available for tag {tag!r})")


_CHECK_LINE = re.compile(r"^\s*(?:\d+[.)]|[-*])\s+(?P<text>\S.*)$")


@lru_cache(maxsize=512)
def detector_checks(detector_id: str, max_checks: int = 8) -> tuple[str, ...]:
    """The detector's own rules, so the verifier argues against the same criteria.

    Synthesized detectors carry an explicit `### Detection Checks` section; upstream's
    hand-written prompts have no such section, so their numbered/bulleted steps are
    used instead. Either way this is the detector's stated basis, which is what a
    refuting reviewer has to engage with.

    39 of the 56 upstream detectors state no steps at all -- they are a knowledge
    paragraph plus a worked example. For those the `### Vulnerability Knowledge` prose
    stands in as the single criterion, because handing the verifier an empty checklist
    would leave it refuting the finding against nothing but the tag definition.
    """
    try:
        body = detection_prompt(detector_id)
    except (FileNotFoundError, ValueError):
        return ()

    m = re.search(r"^###\s*Detection Checks\s*$", body, re.MULTILINE)
    section = body[m.end():] if m else body
    if m:
        nxt = re.search(r"^###\s", section, re.MULTILINE)
        if nxt:
            section = section[:nxt.start()]

    checks: list[str] = []
    in_fence = False
    for line in section.splitlines():
        if line.strip().startswith("```"):
            in_fence = not in_fence
            continue
        if in_fence:
            continue
        cm = _CHECK_LINE.match(line)
        if cm:
            checks.append(cm.group("text").strip())
        if len(checks) >= max_checks:
            break
    if checks:
        return tuple(checks)
    return _knowledge_fallback(body)


def _knowledge_fallback(body: str, max_chars: int = 700) -> tuple[str, ...]:
    """The detector's knowledge prose, as one criterion, for list-free prompts."""
    m = re.search(r"^###\s*Vulnerability Knowledge\s*$", body, re.MULTILINE)
    section = body[m.end():] if m else body
    nxt = re.search(r"^###\s", section, re.MULTILINE)
    if nxt:
        section = section[:nxt.start()]
    text = " ".join(line.strip() for line in section.splitlines()
                    if line.strip() and not line.strip().startswith(("```", "**")))
    text = text.strip()
    return (text[:max_chars],) if text else ()


# -- context ---------------------------------------------------------------------


def _index_for(repo_index: dict, repo: str) -> dict | None:
    """Accept either one repo's index or a {repo: index} mapping.

    A single index is used as given even if its `repo` field disagrees: the caller
    chose it, and a hash-named directory does not always match the repo string the
    findings carry.
    """
    if "files" in repo_index:
        return repo_index
    got = repo_index.get(repo)
    return got if isinstance(got, dict) and "files" in got else None


def _evidence_lines(evidence: str) -> tuple[int, int] | None:
    nums = [int(n) for n in re.findall(r"L?(\d{1,6})", evidence or "")][:2]
    if not nums:
        return None
    return (nums[0], nums[-1])


def function_context(repo_index: dict, finding: Finding,
                     pad: int = CONTEXT_PAD_LINES,
                     max_chars: int = MAX_CONTEXT_CHARS) -> str:
    """The finding's function plus everything within +-`pad` lines, from the index.

    Resolution order is (contract, function), then function name alone, then the line
    range in `evidence` -- the same tolerance `findings.parse_findings` applies, since
    a model that drifted on the contract name usually still pointed at real code.
    Returns "" when nothing resolves, which the caller reads as "do not verify".
    """
    ix = _index_for(repo_index, finding.repo)
    if ix is None:
        return ""
    files = [f for f in ix["files"] if f["path"] == finding.path] or \
            [f for f in ix["files"] if f["path"].endswith(finding.path)]
    if not files:
        return ""
    fobj = files[0]
    fns = fobj["functions"]
    if not fns:
        return ""

    target = None
    for fn in fns:
        if fn["contract"] == finding.contract and fn["name"] == finding.function:
            target = fn
            break
    if target is None:
        named = [fn for fn in fns if fn["name"] == finding.function]
        target = named[0] if named else None
    if target is None:
        span = _evidence_lines(finding.evidence)
        if span:
            overlapping = [fn for fn in fns
                           if fn["start_line"] <= span[1] and fn["end_line"] >= span[0]]
            target = overlapping[0] if overlapping else None
    if target is None:
        return ""

    lo, hi = target["start_line"] - pad, target["end_line"] + pad
    neighbours = [fn for fn in fns
                  if fn is not target
                  and fn["start_line"] <= hi and fn["end_line"] >= lo]
    # Nearest first, so truncation drops the least relevant context.
    neighbours.sort(key=lambda fn: abs(fn["start_line"] - target["start_line"]))

    def block(fn: dict, label: str) -> str:
        return (f"// {label} {fobj['path']} | CONTRACT {fn['contract']} "
                f"| FUNCTION {fn['name']} | L{fn['start_line']}-L{fn['end_line']}\n"
                f"{fn['source']}")

    parts = [f"// FILE {fobj['path']} | CONTRACTS {', '.join(fobj['contracts']) or '-'}",
             block(target, "REPORTED IN")]
    used = sum(len(p) for p in parts)
    for fn in neighbours:
        b = block(fn, "NEARBY")
        if used + len(b) > max_chars:
            break
        parts.append(b)
        used += len(b)
    return "\n\n".join(parts)


# -- verification ----------------------------------------------------------------


def verify_id(finding: Finding, model: str,
              prompt_version: str = VERIFY_PROMPT_VERSION) -> str:
    """Stable id for one verification, so resume skips completed work.

    Keyed on the complete immutable finding identity plus model and prompt version.
    This keeps sibling claims, severity changes, and parser-span changes isolated
    across restart/resume.
    """
    parts = [finding_key(finding), model, prompt_version]
    return hashlib.sha256("|".join(parts).encode()).hexdigest()[:16]


def _normalize_verdict(parsed: dict | None) -> tuple[str, str]:
    """(verdict, reason). DESIGN §2.5(3): `confirmed` without a scenario is not a
    confirmation -- it is an assertion, and it degrades to `uncertain`."""
    if not isinstance(parsed, dict):
        return "unverified", ""
    v = str(parsed.get("verdict") or "").strip().lower()
    if v not in VALID_VERDICTS:
        return "unverified", ""
    scenario = str(parsed.get("attack_scenario") or "").strip()
    reason = str(parsed.get("reject_reason") or "").strip()
    if v == "confirmed" and not scenario:
        return "uncertain", "confirmed without an attack scenario"
    return v, scenario if v == "confirmed" else reason


class VerifyStore:
    """verify.jsonl beside results.jsonl: append-only, one line per verification.

    Separate from RunStore's results.jsonl on purpose -- that file is keyed by
    task_id and owned by the executor; verification is a second pass over its output
    and must be resumable and inspectable on its own.
    """

    def __init__(self, store: RunStore):
        self.path = Path(store.run_dir) / "verify.jsonl"

    def done(self) -> dict[tuple[str, str], dict]:
        out: dict[tuple[str, str], dict] = {}
        if not self.path.exists():
            return out
        with self.path.open() as fh:
            for line in fh:
                try:
                    rec = json.loads(line)
                except json.JSONDecodeError:
                    continue  # torn tail from a hard kill; that finding re-verifies
                if (
                    not isinstance(rec, dict)
                    or rec.get("verdict")
                    not in (*VALID_VERDICTS, "unverified")
                ):
                    continue
                work_id = rec.get("adjudication_id") or rec.get("verify_id")
                if not isinstance(work_id, str) or not work_id:
                    continue
                if "finding_key" in rec:
                    key = rec.get("finding_key")
                    if not isinstance(key, str) or not key:
                        continue
                else:
                    key = ""
                # The log is append-only and later adjudications supersede earlier
                # ones for the same exact work/finding identity. This matches the
                # overlay reader and keeps resume/export views consistent.
                out[(work_id, key)] = rec
        return out

    def append(self, rec: dict) -> None:
        with self.path.open("a") as fh:
            fh.write(json.dumps(rec) + "\n")
            fh.flush()
            os.fsync(fh.fileno())


def _cached_finding(finding: Finding, rec: dict) -> Finding:
    """Apply the compact durable view of one cached adjudication."""
    return replace(
        finding,
        verdict=str(rec.get("verdict") or finding.verdict),
        adjudication_id=str(
            rec.get("adjudication_id") or rec.get("verify_id") or ""),
        adjudication_reason=str(
            rec.get("reason_code") or rec.get("reason")
            or rec.get("reject_reason") or ""),
        adjudication_version=str(
            rec.get("adjudication_version") or rec.get("schema_version")
            or rec.get("prompt_version") or "legacy-v1"),
    )


async def verify_findings(findings: list[Finding], repo_index: dict,
                          client: LLMClient, store: RunStore,
                          policy: VerifyPolicy | None = None,
                          detector_meta: dict[str, dict] | None = None,
                          pad: int = CONTEXT_PAD_LINES,
                          treatment: str = "none",
                          context_chars: int = MAX_CONTEXT_CHARS,
                          provider_fingerprint: str = "") -> list[Finding]:
    """One refutation call per enabled finding; returns findings with verdicts filled.

    Inputs are not mutated -- a copy carries the verdict, so a caller can score the
    verified and unverified views of the same run side by side (that comparison is
    `aggregate.verify_impact`).

    `repo_index` is either one repository's index or a {repo: index} mapping, since a
    findings list may span repositories.
    """
    treatment = treatment.strip().lower()
    if treatment not in ("none", TWINCOURT_TREATMENT):
        raise ValueError(
            f"treatment must be 'none' or {TWINCOURT_TREATMENT!r}")
    if context_chars <= 0:
        raise ValueError("context_chars must be positive")

    policy = policy or VerifyPolicy()
    meta = detector_meta if detector_meta is not None else load_detector_meta()
    vstore = VerifyStore(store)
    cached = vstore.done()

    # (finding index, cache/work id, legacy context or HERMES packet)
    plan: list[tuple[int, str, str | EvidencePacket]] = []
    skipped = {"policy": 0, "no_context": 0, "cached": 0}
    out = [replace(f) for f in findings]
    hermes_config = HermesConfig(max_chars=context_chars)

    for i, f in enumerate(out):
        if not policy.enabled(f, meta.get(f.detector_id)):
            skipped["policy"] += 1
            continue
        if treatment == TWINCOURT_TREATMENT:
            packet = build_packet(f, repo_index, hermes_config)
            if packet is None:
                skipped["no_context"] += 1
                continue
            work_id = adjudication_id(
                f,
                model=client.model,
                provider_fingerprint=provider_fingerprint,
                packet_id=packet.id,
                hermes_version=packet.version,
                hermes_config=packet.config.payload(),
            )
            payload: str | EvidencePacket = packet
        else:
            work_id = verify_id(f, client.model)
            context = function_context(
                repo_index, f, pad=pad, max_chars=context_chars)
            if not context:
                skipped["no_context"] += 1
                continue
            payload = context
        cache_record = cached.get((work_id, finding_key(f)))
        if cache_record is None:
            cache_record = cached.get((work_id, ""))
        if cache_record is not None:
            out[i] = _cached_finding(f, cache_record)
            skipped["cached"] += 1
            continue
        plan.append((i, work_id, payload))

    print(f"[verify] {len(findings)} findings, {len(plan)} to verify "
          f"(skipped: {skipped})", flush=True)
    if not plan:
        return out

    verdicts: dict[str, int] = {}
    t0 = time.monotonic()

    async def one(
        i: int, work_id: str, payload: str | EvidencePacket
    ) -> None:
        f = out[i]
        checks = list(detector_checks(f.detector_id))
        if treatment == TWINCOURT_TREATMENT:
            packet = payload
            if not isinstance(packet, EvidencePacket):
                raise TypeError("TwinCourt requires an EvidencePacket")
            system, user = build_twincourt_prompt(
                f, packet, tag_definition(f.tag), checks)
            result = await client.complete(
                system,
                user,
                schema=TWINCOURT_SCHEMA,
                task_id=work_id,
                stage="verify",
            )
            decision = normalize_decision(
                result.parsed, (fragment.id for fragment in packet.fragments))
            verdict, reason = decision.verdict, decision.reason_code
        else:
            context = payload
            if not isinstance(context, str):
                raise TypeError("legacy verification requires string context")
            system, user = build_verify_prompt(
                f, context, tag_definition(f.tag), checks)
            result = await client.complete(
                system,
                user,
                schema=VERIFY_SCHEMA,
                task_id=work_id,
                stage="verify",
            )
            verdict, reason = _normalize_verdict(result.parsed)
        if result.error in TRANSIENT_ERRORS:
            verdicts["transient_error"] = verdicts.get("transient_error", 0) + 1
            return  # not persisted: the next resume gets a fresh attempt
        adjudication_version = (
            TWINCOURT_VERSION
            if treatment == TWINCOURT_TREATMENT
            else f"legacy-{VERIFY_PROMPT_VERSION}"
        )
        out[i] = replace(
            f,
            verdict=verdict,
            adjudication_id=work_id,
            adjudication_reason=reason,
            adjudication_version=adjudication_version,
        )
        verdicts[verdict] = verdicts.get(verdict, 0) + 1
        record: dict[str, Any] = {
            "finding_key": finding_key(f),
            "adjudication_id": work_id,
            "adjudication_version": adjudication_version,
            "task_id": f.task_id, "repo": f.repo,
            "detector_id": f.detector_id, "tag": f.tag, "path": f.path,
            "contract": f.contract, "function": f.function,
            "verdict": verdict, "reason": reason, "error": result.error,
            "usage": {"model": result.model,
                      "input_tokens": result.input_tokens,
                      "output_tokens": result.output_tokens,
                      "latency_s": round(result.latency_s, 3),
                      "attempts": result.attempts},
        }
        if treatment == TWINCOURT_TREATMENT:
            packet = payload
            assert isinstance(packet, EvidencePacket)
            record.update({
                "schema_version": OVERLAY_SCHEMA_VERSION,
                "treatment": TWINCOURT_TREATMENT,
                "prompt_version": TWINCOURT_PROMPT_VERSION,
                "decision_schema_version": TWINCOURT_SCHEMA_VERSION,
                "hermes_version": packet.version,
                "provider_fingerprint": provider_fingerprint,
                "packet": packet.stats(),
                "reason_code": reason,
                "decision": decision.to_dict(),
            })
        else:
            record.update({
                "verify_id": work_id,
                "schema_version": "verify-overlay-v1",
                "prompt_version": VERIFY_PROMPT_VERSION,
            })
        vstore.append(record)

    await asyncio.gather(
        *(one(i, work_id, payload) for i, work_id, payload in plan))
    print(f"[verify] done in {time.monotonic() - t0:.0f}s: {verdicts}", flush=True)
    return out


def verdict_counts(findings: Iterable[Finding]) -> dict[str, int]:
    counts: dict[str, int] = {}
    for f in findings:
        counts[f.verdict] = counts.get(f.verdict, 0) + 1
    return counts
