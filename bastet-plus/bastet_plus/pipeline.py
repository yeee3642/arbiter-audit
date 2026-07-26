"""The two pipelines under comparison.

``run_legacy``  -- a faithful Python replica of the original n8n path:
                   whole file in, one call per detector, no verification,
                   no dedup, legacy severity coercion.
``run_enhanced`` -- slice -> k-sample detect -> vote -> ground -> refute -> merge.

Both take the same detectors, the same model and the same endpoint, so the
delta between them is attributable to the harness.

A note on fairness: the legacy replica gets the *improved* JSON extraction
(``llm.extract_json``) even though n8n's structured output parser is stricter.
That deliberately hands the baseline an advantage, so the accuracy numbers
cannot be dismissed as "your parser is just better". The size of that advantage
is measured separately and reported as ``strict_parse_failures``.
"""

from __future__ import annotations

import json
import time
from concurrent.futures import ThreadPoolExecutor
from dataclasses import dataclass, field

from .config import SEVERITY_ORDER, LLMConfig, PipelineConfig
from .dedupe import merge_across_detectors, vote
from .detectors import Detector
from .grounding import apply_grounding
from .llm import LLMClient, LLMError, extract_json
from .schema import FINDING_SCHEMA, Finding, coerce_findings
from .slicing import Slice, read_source, slice_solidity
from .verify import verify_one


@dataclass
class ScanResult:
    findings: list[Finding] = field(default_factory=list)
    dropped: list[Finding] = field(default_factory=list)
    stats: dict = field(default_factory=dict)

    def positives(self) -> list[Finding]:
        return self.findings


# --------------------------------------------------------------------------
# legacy replica
# --------------------------------------------------------------------------


def _legacy_coerce_severity(items: list) -> tuple[list, int]:
    """Reproduce ``cli/models/audit_report.py``: unknown severity becomes "high".

    Returns the items plus a count of how many were silently rewritten. That
    count is the bug: the prompts never ask for severity, so it fires on
    essentially every finding, and every legacy report is 100% "high".
    """
    n = 0
    for it in items:
        if not isinstance(it, dict):
            continue
        sev = str(it.get("severity", "")).lower()
        if sev not in ("high", "medium", "low"):
            it["severity"] = "high"
            n += 1
    return items, n


def run_legacy(path: str, detectors: list[Detector], client: LLMClient,
               llm_cfg: LLMConfig) -> ScanResult:
    src = read_source(path)
    findings: list[Finding] = []
    strict_fail = 0
    severity_coerced = 0
    detector_errors = 0
    truncation_risk = 0

    def one(det: Detector):
        nonlocal strict_fail, severity_coerced, detector_errors, truncation_risk
        try:
            # n8n's chainLlm: system message = the prompt, user message = the
            # raw contract, whole file, every time.
            raw = client.complete(
                [{"role": "system", "content": det.legacy_prompt()},
                 {"role": "user", "content": src}],
                temperature=llm_cfg.temperature,
            )
        except LLMError:
            detector_errors += 1
            return []

        # What n8n's Structured Output Parser would have accepted: bare JSON.
        try:
            json.loads(raw.strip())
        except Exception:
            strict_fail += 1

        parsed = extract_json(raw)
        items = parsed if isinstance(parsed, list) else (
            parsed.get("output") or parsed.get("findings") or []
        ) if isinstance(parsed, dict) else []
        if not isinstance(items, list):
            items = []
        items, n = _legacy_coerce_severity(items)
        severity_coerced += n
        return coerce_findings(items, detector=det.name, file=path, slice_name="<whole file>")

    # ~4 chars/token: flag inputs that the model will silently truncate.
    if len(src) / 4 > 100_000:
        truncation_risk = 1

    t0 = time.time()
    with ThreadPoolExecutor(max_workers=max(1, llm_cfg.concurrency)) as pool:
        for chunk in pool.map(one, detectors):
            findings.extend(chunk)

    return ScanResult(
        findings=findings,
        stats={
            "pipeline": "legacy",
            "file": path,
            "source_chars": len(src),
            "llm_requests": len(detectors),
            "slices": 1,
            "raw_findings": len(findings),
            "reported": len(findings),
            "strict_parse_failures": strict_fail,
            "severity_silently_coerced": severity_coerced,
            "detector_errors": detector_errors,
            "whole_file_truncation_risk": truncation_risk,
            "wall_seconds": round(time.time() - t0, 2),
        },
    )


# --------------------------------------------------------------------------
# enhanced
# --------------------------------------------------------------------------


def _detect_task(client: LLMClient, det: Detector, sl: Slice, path: str,
                 sample_idx: int, temperature: float, seed: int | None) -> list[Finding]:
    user = (
        f"File: {path}\nRegion: {sl.name} (source lines {sl.start_line}-{sl.end_line})\n\n"
        "```solidity\n" + sl.text + "\n```"
    )
    parsed = client.complete_json(
        [{"role": "system", "content": det.enhanced_prompt()},
         {"role": "user", "content": user}],
        FINDING_SCHEMA, temperature=temperature, seed=seed, schema_name="findings",
    )
    out = coerce_findings(parsed, detector=det.name, file=path, slice_name=sl.name)
    for f in out:
        f.sample_idx = sample_idx
    return out


def run_enhanced(path: str, detectors: list[Detector], client: LLMClient,
                 llm_cfg: LLMConfig, cfg: PipelineConfig) -> ScanResult:
    src = read_source(path)
    slices = (slice_solidity(src, max_chars=cfg.max_slice_chars,
                             context_chars=cfg.context_header_chars, file_label=path)
              if cfg.slice_code else
              [Slice(name="<file>", text=src, start_line=1, end_line=src.count("\n") + 1, kind="file")])

    tasks = [
        (det, sl, k)
        for det in detectors
        for sl in slices
        for k in range(max(1, cfg.samples))
    ]

    t0 = time.time()
    raw: list[Finding] = []
    errors = 0

    def run(t):
        det, sl, k = t
        temp = llm_cfg.temperature if cfg.samples <= 1 else cfg.vote_temperature
        seed = llm_cfg.seed if cfg.samples <= 1 else (
            None if llm_cfg.seed is None else llm_cfg.seed + 977 * k
        )
        try:
            return _detect_task(client, det, sl, path, k, temp, seed)
        except LLMError:
            return None

    with ThreadPoolExecutor(max_workers=max(1, llm_cfg.concurrency)) as pool:
        for res in pool.map(run, tasks):
            if res is None:
                errors += 1
            else:
                raw.extend(res)

    n_raw = len(raw)

    # 1. self-consistency: within each (detector, slice), require agreement
    voted: list[Finding] = []
    vote_rejected: list[Finding] = []
    by_scope: dict[tuple[str, str], list[Finding]] = {}
    for f in raw:
        by_scope.setdefault((f.detector, f.slice_name), []).append(f)
    for group in by_scope.values():
        k, r = vote(group, max(1, cfg.samples), cfg.vote_threshold)
        voted.extend(k)
        vote_rejected.extend(r)
    n_after_vote = len(voted)

    # 2. evidence grounding (free)
    grounded, ungrounded = apply_grounding(voted, src, drop_ungrounded=cfg.drop_ungrounded)
    n_after_ground = len(grounded)

    # 3. adversarial verification
    verify_rejected: list[Finding] = []
    if cfg.verify and grounded:
        slice_by_name = {sl.name: sl for sl in slices}

        def check(f: Finding):
            sl = slice_by_name.get(f.slice_name)
            text = sl.text if sl else src
            start = sl.start_line if sl else 1
            try:
                return verify_one(client, f, text, start, cfg.verify_votes,
                                  model=llm_cfg.verifier_model or None)
            except LLMError:
                return True, f  # never lose a finding to an infrastructure blip

        survivors = []
        with ThreadPoolExecutor(max_workers=max(1, llm_cfg.concurrency)) as pool:
            for ok, f in pool.map(check, grounded):
                (survivors if ok else verify_rejected).append(f)
        grounded = survivors
    n_after_verify = len(grounded)

    # 4. one line per bug, across all detectors
    merged = merge_across_detectors(grounded)

    floor = SEVERITY_ORDER.get(cfg.min_severity, 0)
    final = [f for f in merged if SEVERITY_ORDER.get(f.severity, 1) >= floor]
    final.sort(key=lambda f: (-SEVERITY_ORDER.get(f.severity, 1), -f.confidence, f.file, f.line or 0))

    return ScanResult(
        findings=final,
        dropped=vote_rejected + ungrounded + verify_rejected,
        stats={
            "pipeline": "enhanced",
            "file": path,
            "source_chars": len(src),
            "slices": len(slices),
            "llm_requests": len(tasks),
            "detector_errors": errors,
            "raw_findings": n_raw,
            "after_vote": n_after_vote,
            "dropped_by_vote": len(vote_rejected),
            "after_grounding": n_after_ground,
            "dropped_ungrounded": len(ungrounded),
            "after_verify": n_after_verify,
            "dropped_by_verifier": len(verify_rejected),
            "merged_duplicates": n_after_verify - len(merged),
            "reported": len(final),
            "wall_seconds": round(time.time() - t0, 2),
        },
    )
