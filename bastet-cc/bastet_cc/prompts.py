"""Prompt assembly: detector text as instructions, code slices as content.

Upstream gives every chainLlm node its own output schema; both of our arms instead
share `OUTPUT_SCHEMA` so one parser serves routed and broadcast alike. That is the
single deliberate deviation from broadcast fidelity (DESIGN §1.2) and both arms carry
it, so the comparison holds.

Slices are prefixed with a `// FILE ... | CONTRACT ... | FUNCTION ... | L{a}-L{b}`
header. The model is told to echo those fields verbatim; findings.py then matches its
reports back to slices by (contract, function), which is what turns free text into a
locatable Finding.

`PROMPT_VERSION` participates in every task_id -- bump it on any wording change and
the run cache invalidates itself.
"""

from __future__ import annotations

import json
import re
from functools import lru_cache
from pathlib import Path

from .routing import Task

PROMPT_VERSION = "v1"

# Directories searched for detector markdown, in order. Synthesized detectors land in
# detectors_synth/ with identical structure (DESIGN appendix A).
DETECTOR_DIRS: list[Path] = [
    Path(__file__).resolve().parent.parent / "detectors",
    Path(__file__).resolve().parent.parent / "detectors_synth",
]

# The one output schema shared by every detector in both arms (DESIGN §1.2). Passed to
# LLMClient.complete(schema=...) to request JSON mode; also rendered into the system
# prompt because json_object mode alone does not pin field names (MODEL_NOTES.md).
OUTPUT_SCHEMA: dict = {
    "type": "object",
    "properties": {
        "findings": {
            "type": "array",
            "items": {
                "type": "object",
                "properties": {
                    "contract": {"type": "string"},
                    "function": {"type": "string"},
                    "vulnerable": {"type": "boolean"},
                    "subtag": {"type": "string"},
                    "severity": {"type": "string", "enum": ["High", "Medium", "Low"]},
                    "description": {"type": "string"},
                    "evidence": {"type": "string"},
                    "confidence": {"type": "number"},
                },
                "required": ["contract", "function", "vulnerable", "severity"],
            },
        },
    },
    "required": ["findings"],
}

VERIFY_SCHEMA: dict = {
    "type": "object",
    "properties": {
        "verdict": {"type": "string", "enum": ["confirmed", "rejected", "uncertain"]},
        "attack_scenario": {"type": ["string", "null"]},
        "reject_reason": {"type": ["string", "null"]},
    },
    "required": ["verdict"],
}

_SCHEMA_EXAMPLE = (
    '{"findings": [{"contract": "string", "function": "string", "vulnerable": true, '
    '"subtag": "string", "severity": "High|Medium|Low", "description": "string", '
    '"evidence": "line refs like L42-L47", "confidence": 0.0}]}'
)

DETECT_SYSTEM = (
    "You are an expert smart contract security auditor reviewing Solidity code.\n"
    "Apply the detection instructions you are given to the code under review, and "
    "report only concrete, exploitable issues of that specific vulnerability class.\n\n"
    "Output requirements (these override any output format mentioned in the "
    "instructions below):\n"
    "- Respond with ONLY a single JSON object, no markdown fences, no prose.\n"
    f"- Shape: {_SCHEMA_EXAMPLE}\n"
    "- Copy `contract` and `function` EXACTLY from the `// FILE ... | CONTRACT ... | "
    "FUNCTION ...` header of the code section the issue is in.\n"
    "- `evidence` cites the absolute line numbers shown in the headers (e.g. "
    '"L42-L47").\n'
    "- `confidence` is your 0..1 estimate that a senior auditor would confirm the "
    "issue.\n"
    '- If nothing is vulnerable, respond with {"findings": []}.'
)

VERIFY_SYSTEM = (
    "You are a senior security auditor whose job is to REFUTE the vulnerability "
    "report below. Only answer `confirmed` if you can write a concrete attack "
    "scenario citing specific line numbers from the provided context. If the claimed "
    "pattern is already guarded against in the context, you MUST answer `rejected` "
    "and say which lines guard it. If the context is insufficient to decide either "
    "way, answer `uncertain`.\n\n"
    "Respond with ONLY a single JSON object, no markdown fences:\n"
    '{"verdict": "confirmed|rejected|uncertain", "attack_scenario": "string or null", '
    '"reject_reason": "string or null"}'
)


@lru_cache(maxsize=512)
def detection_prompt(detector_id: str) -> str:
    """The '## Detection prompt' section of a detector's markdown, verbatim.

    Detector dataclasses carry only metadata (routing hints, prompt_chars); the prompt
    body stays in the md file so synthesized detectors are reviewable artifacts.
    """
    for d in DETECTOR_DIRS:
        path = d / f"{detector_id}.md"
        if path.exists():
            text = path.read_text()
            m = re.search(r"^## Detection prompt\s*$", text, re.MULTILINE)
            if m is None:
                raise ValueError(f"{path} has no '## Detection prompt' section")
            return text[m.end():].strip()
    raise FileNotFoundError(f"no markdown found for detector {detector_id!r} in {DETECTOR_DIRS}")


def slice_header(sl) -> str:
    return (f"// FILE {sl.path} | CONTRACT {sl.contract} | FUNCTION {sl.function} "
            f"| L{sl.start_line}-L{sl.end_line}")


def _render_exemplars(exemplars: list[dict]) -> str:
    lines = ["### Similar audited findings (from real audits of other projects)"]
    for i, ex in enumerate(exemplars, 1):
        tag = ex.get("tag", "")
        subtag = ex.get("subtag", "")
        fault = ex.get("fault_pattern") or ex.get("description", "")
        lines.append(f"{i}. [{tag} / {subtag}] fault: {fault}")
        snippet = (ex.get("snippet") or "").strip()
        if snippet:
            capped = "\n".join(snippet.splitlines()[:10])
            lines.append(f"   code:\n```solidity\n{capped}\n```")
    return "\n".join(lines)


def build_prompt(task: Task, exemplars: list[dict] | None = None) -> tuple[str, str]:
    """(system, user) for one detection call. Broadcast tasks arrive here with a
    single whole-file slice and exemplars=None -- same path, no branch."""
    parts = [detection_prompt(task.detector.id)]
    if exemplars:
        parts.append(_render_exemplars(exemplars))
    code = "\n\n".join(f"{slice_header(sl)}\n{sl.source}" for sl in task.slices)
    parts.append("### Code under review\n\n" + code)
    return DETECT_SYSTEM, "\n\n".join(parts)


def build_verify_prompt(finding, context_source: str,
                        tag_definition: str, checks: list[str]) -> tuple[str, str]:
    """(system, user) for one adversarial verification call (DESIGN §2.5)."""
    check_lines = "\n".join(f"- {c}" for c in checks) if checks else "- (none provided)"
    user = "\n\n".join([
        "### Vulnerability report under review\n"
        f"- tag: {finding.tag}\n"
        f"- subtag: {finding.subtag}\n"
        f"- severity: {finding.severity}\n"
        f"- location: {finding.path} | {finding.contract}.{finding.function}\n"
        f"- evidence: {finding.evidence}\n"
        f"- description: {finding.description}",
        "### Official tag definition\n" + tag_definition,
        "### Detector checks\n" + check_lines,
        "### Code context\n\n" + context_source,
    ])
    return VERIFY_SYSTEM, user


def schema_json() -> str:
    """OUTPUT_SCHEMA as compact JSON, for prompt-embedded fallback or manifests."""
    return json.dumps(OUTPUT_SCHEMA, separators=(",", ":"))
