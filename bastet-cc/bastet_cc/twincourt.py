"""Structured same-model falsification with deterministic evidence gates."""

from __future__ import annotations

import hashlib
import json
from dataclasses import asdict, dataclass
from typing import Any, Iterable, Literal

from .findings import Finding, finding_key


TWINCOURT_TREATMENT = "hermes_twincourt"
TWINCOURT_VERSION = "twincourt-v1"
TWINCOURT_PROMPT_VERSION = "twincourt-prompt-v1"
TWINCOURT_SCHEMA_VERSION = "twincourt-schema-v1"
OVERLAY_SCHEMA_VERSION = "verify-overlay-v2"

_VERDICTS = frozenset({"confirmed", "rejected", "uncertain"})
_REASON_CODES = frozenset({
    "exploit_path_proven",
    "guarded",
    "unreachable",
    "missing_precondition",
    "wrong_location",
    "insufficient_context",
    "invalid_claim",
})


@dataclass(frozen=True)
class CourtDecision:
    verdict: Literal["confirmed", "rejected", "uncertain"]
    reason_code: str
    preconditions: tuple[str, ...]
    causal_steps: tuple[str, ...]
    counter_evidence: tuple[str, ...]
    cited_fragment_ids: tuple[str, ...]
    summary: str
    raw_verdict: str
    gate_reason: str = ""

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


def adjudication_id(
    finding: Finding,
    *,
    model: str,
    provider_fingerprint: str,
    packet_id: str,
    hermes_version: str,
    hermes_config: dict[str, Any],
) -> str:
    """Cache identity over every input that can change a court decision."""
    payload = {
        "finding_key": finding_key(finding),
        "model": model,
        "provider_fingerprint": provider_fingerprint,
        "treatment": TWINCOURT_TREATMENT,
        "twincourt_version": TWINCOURT_VERSION,
        "prompt_version": TWINCOURT_PROMPT_VERSION,
        "schema_version": TWINCOURT_SCHEMA_VERSION,
        "hermes_version": hermes_version,
        "hermes_config": hermes_config,
        "packet_id": packet_id,
    }
    canonical = json.dumps(
        payload, ensure_ascii=False, sort_keys=True, separators=(",", ":"))
    return "court-" + hashlib.sha256(canonical.encode()).hexdigest()[:20]


def _bounded_strings(
    value: object, *, max_items: int = 12, max_chars: int = 600
) -> tuple[str, ...]:
    if not isinstance(value, list):
        return ()
    out: list[str] = []
    for item in value[:max_items]:
        if not isinstance(item, str):
            continue
        text = " ".join(item.split()).strip()
        if text:
            out.append(text[:max_chars])
    return tuple(out)


def normalize_decision(
    parsed: object,
    valid_fragment_ids: Iterable[str],
) -> CourtDecision:
    """Normalize the model response and enforce citation/causality invariants."""
    valid_ids = frozenset(str(value) for value in valid_fragment_ids)
    if not isinstance(parsed, dict):
        return CourtDecision(
            verdict="uncertain",
            reason_code="invalid_claim",
            preconditions=(),
            causal_steps=(),
            counter_evidence=(),
            cited_fragment_ids=(),
            summary="TwinCourt response was not a JSON object.",
            raw_verdict="",
            gate_reason="malformed_response",
        )

    raw_verdict = str(parsed.get("verdict") or "").strip().lower()
    verdict = raw_verdict if raw_verdict in _VERDICTS else "uncertain"
    reason = str(parsed.get("reason_code") or "").strip().lower()
    if reason not in _REASON_CODES:
        reason = "invalid_claim"
    preconditions = _bounded_strings(parsed.get("preconditions"))
    causal_steps = _bounded_strings(parsed.get("causal_steps"))
    counter_evidence = _bounded_strings(parsed.get("counter_evidence"))
    cited = tuple(
        fragment_id for fragment_id in _bounded_strings(
            parsed.get("cited_fragment_ids"), max_chars=128)
        if fragment_id in valid_ids
    )
    summary = " ".join(str(parsed.get("summary") or "").split()).strip()[:1200]

    gate_reason = ""
    if verdict == "confirmed":
        valid_confirmation = (
            reason == "exploit_path_proven"
            and bool(preconditions)
            and len(causal_steps) >= 2
            and bool(cited)
        )
        if not valid_confirmation:
            verdict = "uncertain"
            reason = "insufficient_context"
            gate_reason = "confirmation_missing_causal_evidence"
    elif verdict == "rejected":
        valid_rejection = reason in {
            "guarded", "unreachable", "missing_precondition",
            "wrong_location", "invalid_claim",
        } and bool(counter_evidence) and bool(cited)
        if not valid_rejection:
            verdict = "uncertain"
            reason = "insufficient_context"
            gate_reason = "rejection_missing_counter_evidence"

    if raw_verdict not in _VERDICTS:
        gate_reason = gate_reason or "invalid_verdict"
    if not summary:
        summary = "No bounded adjudication summary was supplied."

    return CourtDecision(
        verdict=verdict,
        reason_code=reason,
        preconditions=preconditions,
        causal_steps=causal_steps,
        counter_evidence=counter_evidence,
        cited_fragment_ids=cited,
        summary=summary,
        raw_verdict=raw_verdict,
        gate_reason=gate_reason,
    )
