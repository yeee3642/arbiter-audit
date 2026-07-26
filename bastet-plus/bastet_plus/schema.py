"""Single source of truth for the finding format.

The original harness kept three *divergent* copies of this contract:

  1. the free-text "Report Format" block inside every one of the 56 n8n prompts,
     which asks for ``Summary`` / ``Vulnerability Details`` / ``File Name`` /
     ``Code Snippet`` and never mentions severity at all;
  2. the JSON Schema pasted into each workflow's Structured Output Parser node,
     which requires ``summary`` / ``severity`` / ``vulnerability_details`` /
     ``code_snippet`` / ``recommendation``;
  3. ``cli/models/audit_report.py``, whose ``__init__`` rewrites any missing or
     unrecognised severity to ``"high"``.

(1) and (2) disagree on every field name, and (3) hides the disagreement -- so
every finding the legacy pipeline emits is stamped "high" regardless of what the
model thought. Here the schema is defined once and both the prompt text and the
``response_format`` are *derived* from it, so they cannot drift.
"""

from __future__ import annotations

import re
from dataclasses import asdict, dataclass, field

SEVERITIES = ("high", "medium", "low")

FINDING_SCHEMA = {
    "type": "object",
    "properties": {
        "findings": {
            "type": "array",
            "description": "All confirmed vulnerabilities. Empty array if none.",
            "items": {
                "type": "object",
                "properties": {
                    "summary": {"type": "string", "description": "One-line summary of the vulnerability"},
                    "severity": {"type": "string", "enum": list(SEVERITIES),
                                 "description": "high | medium | low"},
                    "function_name": {"type": "string",
                                      "description": "Exact name of the function containing the vulnerability"},
                    "description": {"type": "string", "description": "Why this is exploitable, concretely"},
                    "code_snippet": {"type": "array", "items": {"type": "string"},
                                     "description": "Lines copied VERBATIM from the supplied source. Do not paraphrase."},
                    "recommendation": {"type": "string", "description": "How to fix it"},
                    "confidence": {"type": "number",
                                   "description": "0.0-1.0, how sure you are this is a real exploitable bug"},
                },
                "required": ["summary", "severity", "function_name", "description",
                             "code_snippet", "recommendation", "confidence"],
                "additionalProperties": False,
            },
        }
    },
    "required": ["findings"],
    "additionalProperties": False,
}

VERDICT_SCHEMA = {
    "type": "object",
    "properties": {
        "is_real": {"type": "boolean", "description": "true only if this is a genuine exploitable vulnerability"},
        "severity": {"type": "string", "enum": list(SEVERITIES)},
        "confidence": {"type": "number", "description": "0.0-1.0"},
        "reason": {"type": "string", "description": "One or two sentences justifying the verdict"},
    },
    "required": ["is_real", "severity", "confidence", "reason"],
    "additionalProperties": False,
}


def prompt_format_block() -> str:
    """The output-contract text injected into every detector prompt.

    Derived from FINDING_SCHEMA above, so it can never disagree with the
    ``response_format`` sent on the wire.
    """
    props = FINDING_SCHEMA["properties"]["findings"]["items"]["properties"]
    lines = [f'  - "{name}": {spec.get("description", "")}' for name, spec in props.items()]
    return (
        "## Output contract\n\n"
        "Reply with a single JSON object, nothing else. It has exactly one key, `findings`,\n"
        "whose value is an array. If you find nothing, return `{\"findings\": []}`.\n"
        "If the input is not a smart contract, return `{\"findings\": []}`.\n\n"
        "Each array element has exactly these keys:\n" + "\n".join(lines) + "\n\n"
        "`code_snippet` must contain lines copied character-for-character from the source you\n"
        "were given. A snippet that does not appear in the source will be discarded.\n"
    )


# --------------------------------------------------------------------------


@dataclass
class Finding:
    summary: str = ""
    severity: str = "medium"
    function_name: str = ""
    description: str = ""
    code_snippet: list[str] = field(default_factory=list)
    recommendation: str = ""
    confidence: float = 0.5

    # -- harness-populated metadata (never asked of the model) -------------
    detector: str = ""
    file: str = ""
    slice_name: str = ""
    line: int | None = None
    grounded: bool = False
    sample_idx: int = 0
    votes: int = 1
    samples: int = 1
    verdict_reason: str = ""
    # True when the model omitted/garbled a field and the harness had to
    # substitute a default. The legacy code did this silently.
    coerced_fields: list[str] = field(default_factory=list)

    def as_dict(self) -> dict:
        return asdict(self)

    def key(self) -> tuple:
        """Identity used for dedup and for self-consistency vote counting."""
        return (self.file, _norm_name(self.function_name), _sig(self.summary))


def _norm_name(s: str) -> str:
    s = (s or "").strip()
    s = re.sub(r"\(.*$", "", s)          # drop argument list
    s = re.sub(r"^.*[.:]", "", s)        # drop Contract. prefix
    return s.strip().lower()


_STOP = {"the", "a", "an", "of", "to", "in", "is", "are", "and", "or", "for", "no", "not",
         "this", "that", "it", "be", "can", "may", "will", "with", "on", "by", "function",
         "contract", "vulnerability", "issue", "allows", "due", "which", "there"}


def _sig(text: str, n: int = 6) -> frozenset:
    """Coarse topical signature of a summary, used for near-duplicate matching."""
    words = [w for w in re.findall(r"[a-z0-9_]+", (text or "").lower()) if w not in _STOP and len(w) > 2]
    return frozenset(sorted(words, key=lambda w: (-len(w), w))[:n])


# --------------------------------------------------------------------------
# tolerant coercion
# --------------------------------------------------------------------------

_ALIASES = {
    "summary": ["summary", "Summary", "title"],
    "severity": ["severity", "Severity", "risk", "impact"],
    "function_name": ["function_name", "functionName", "Function Name", "function"],
    "description": ["description", "Description", "details", "detail"],
    "code_snippet": ["code_snippet", "codeSnippet", "Code Snippet", "snippet", "code"],
    "recommendation": ["recommendation", "Recommendation", "mitigation", "fix"],
    "confidence": ["confidence", "Confidence", "certainty"],
}


def _pick(obj: dict, field_name: str):
    for alias in _ALIASES[field_name]:
        if alias in obj:
            return obj[alias]
    # legacy prompts nest under "Vulnerability Details" / "vulnerability_details"
    for nest_key in ("vulnerability_details", "Vulnerability Details", "vulnerabilityDetails"):
        nested = obj.get(nest_key)
        if isinstance(nested, dict):
            for alias in _ALIASES[field_name]:
                if alias in nested:
                    return nested[alias]
    return None


def coerce_findings(raw, *, detector: str = "", file: str = "", slice_name: str = "") -> list[Finding]:
    """Turn whatever the model returned into ``Finding`` objects.

    Accepts the modern ``{"findings": [...]}`` shape, a bare array (what the
    legacy prompts ask for), n8n's ``{"output": [...]}`` envelope, and a lone
    object. Records every substitution in ``coerced_fields`` instead of hiding
    it, which is how we can report the legacy severity bug as a number.
    """
    items = _unwrap(raw)
    out: list[Finding] = []
    for item in items:
        if not isinstance(item, dict):
            continue
        coerced: list[str] = []

        summary = _as_text(_pick(item, "summary"))
        description = _as_text(_pick(item, "description"))
        if not summary and not description:
            continue  # nothing usable
        if not summary:
            summary = description[:160]
            coerced.append("summary")

        sev_raw = _pick(item, "severity")
        sev = str(sev_raw).strip().lower() if sev_raw is not None else ""
        sev = {"critical": "high", "informational": "low", "info": "low", "warning": "medium",
               "moderate": "medium", "med": "medium"}.get(sev, sev)
        if sev not in SEVERITIES:
            sev = "medium"
            coerced.append("severity")

        fn = _as_text(_pick(item, "function_name"))
        if not fn:
            fn = "<unknown>"
            coerced.append("function_name")

        snippet = _pick(item, "code_snippet")
        if isinstance(snippet, str):
            snippet = [snippet]
        elif not isinstance(snippet, list):
            snippet = []
            coerced.append("code_snippet")
        snippet = [_as_text(s) for s in snippet if _as_text(s)]

        conf = _pick(item, "confidence")
        try:
            conf = float(conf)
            conf = min(1.0, max(0.0, conf if conf <= 1.0 else conf / 100.0))
        except (TypeError, ValueError):
            conf = 0.5
            coerced.append("confidence")

        out.append(Finding(
            summary=summary.strip(),
            severity=sev,
            function_name=fn.strip(),
            description=(description or summary).strip(),
            code_snippet=snippet,
            recommendation=_as_text(_pick(item, "recommendation")).strip(),
            confidence=conf,
            detector=detector,
            file=file,
            slice_name=slice_name,
            coerced_fields=coerced,
        ))
    return out


def _unwrap(raw) -> list:
    if raw is None:
        return []
    if isinstance(raw, list):
        # n8n hands back [{"output": [...]}, ...]
        flat = []
        for e in raw:
            if isinstance(e, dict) and isinstance(e.get("output"), list):
                flat.extend(e["output"])
            else:
                flat.append(e)
        return flat
    if isinstance(raw, dict):
        for key in ("findings", "output", "vulnerabilities", "results", "issues"):
            v = raw.get(key)
            if isinstance(v, list):
                return v
            if isinstance(v, dict):
                return [v]
        if any(k in raw for aliases in _ALIASES.values() for k in aliases):
            return [raw]
    return []


def _as_text(v) -> str:
    if v is None:
        return ""
    if isinstance(v, str):
        return v
    if isinstance(v, (int, float, bool)):
        return str(v)
    if isinstance(v, list):
        return "\n".join(_as_text(x) for x in v)
    if isinstance(v, dict):
        return " ".join(f"{k}: {_as_text(x)}" for k, x in v.items())
    return str(v)
