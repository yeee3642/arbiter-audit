"""Strip credentials out of anything that is about to touch disk.

The gateway echoes the caller's key identifier back inside 429 bodies --
`Rate limit exceeded for api_key: <64 hex>` -- and probe scripts store error
strings verbatim. That put a key identifier into a public repository 107 times
in one artefact, past a .gitignore that only ever guarded `.env`. Ignoring files
is the wrong layer: a secret reaches disk through a *value*, not a filename, so
the guard belongs where the value is serialised.

**Why this is anchored on context rather than on shape.** The obvious
implementation -- mask anything with the entropy of a key -- is actively harmful
on this corpus, and measurably so. A shape-only first cut flagged three real
research artefacts:

  - `e18a34eb0e04b04f7a0ac29a6e80748dca96319b42c54d679cb821dca90c6303`
    is the UniswapV2 pair init-code hash, quoted inside a detector's example.
  - `address token = considerationFulfillments[i].token;` matched a
    `token\\s+<16+ chars>` credential rule.
  - `splits_sha256` and `source_sha256` are 64 hex and are published on purpose;
    masking them breaks the freeze check in `leakage_audit.py`.

In an EVM corpus, 64-hex constants and the identifier `token` are domain
vocabulary. Generic secret scanners are built for application source where those
are rare, and their false-positive rate here is high enough that a blanket sweep
silently corrupts the evidence the project rests on. So the rules below all
require a credential *keyword adjacent to* the value, and the bare high-entropy
sweep is available only to `scan()` for advisory pre-commit warnings -- never to
`redact()`, which rewrites files.

`scripts/scrub_artifacts.py` applies this to what is already committed;
`.githooks/pre-commit` applies it to what is about to be.
"""

from __future__ import annotations

import re

_LABEL = "[REDACTED:{}]"

# Keywords that make an adjacent high-entropy value a credential rather than
# data. `token` is deliberately absent -- it is a Solidity noun, and requiring
# `api_token`/`auth_token` keeps the ERC-20 vocabulary out of scope.
_CRED_KEY = r"(?:api[_-]?key|apikey|api[_-]?token|auth[_-]?token|access[_-]?token|" \
            r"secret[_-]?key|client[_-]?secret|private[_-]?key|password|passwd|" \
            r"authorization|bearer[_-]?token)"

# Rules that rewrite files. Each requires a credential keyword next to the value.
_REDACT_RULES: tuple[tuple[str, re.Pattern[str]], ...] = (
    # `api_key: <value>` / `"api_key"="<value>"` -- the gateway 429 shape.
    ("api_key", re.compile(
        rf"(?i)(\b{_CRED_KEY}\b['\"]?\s*[:=]\s*['\"]?)([A-Za-z0-9_\-]{{16,}})")),
    # `api_key <value>` with only whitespace between, as in prose error text.
    ("api_key", re.compile(
        rf"(?i)(\b{_CRED_KEY}\b\s+)([A-Za-z0-9]{{32,}})\b")),
    # Provider-prefixed tokens: the prefix *is* the context, no keyword needed.
    ("token", re.compile(
        r"\b(?:sk|pk|rk|ghp|gho|ghs|ghu|xox[baprs])[-_][A-Za-z0-9_\-]{16,}\b")),
    ("bearer", re.compile(r"(?i)\bBearer\s+[A-Za-z0-9_\-.=]{20,}")),
)

# Advisory only: shape without context. Used by scan() so the pre-commit hook can
# say "look at this" without any code rewriting a file on the strength of it.
_ADVISORY_RULES: tuple[tuple[str, re.Pattern[str]], ...] = (
    ("hex64", re.compile(r"\b[0-9a-f]{64}\b")),
)


def redact(text: str) -> str:
    """Replace credential-shaped substrings with a labelled placeholder.

    Only context-anchored rules run here. A value that merely *looks* like a key
    is left alone: on this corpus that is usually an init-code hash or a
    TYPEHASH, and destroying it costs more than the hypothetical leak it
    prevents.
    """
    if not text:
        return text
    out = text
    for name, pat in _REDACT_RULES:
        if name == "api_key":
            out = pat.sub(lambda m: m.group(1) + _LABEL.format("api_key"), out)
        else:
            out = pat.sub(_LABEL.format(name), out)
    return out


def redact_error(text: str | None) -> str | None:
    """Redactor for LLM/HTTP error strings, applied at the point of capture."""
    return None if text is None else redact(text)


def scan(text: str, advisory: bool = True) -> list[tuple[str, str, bool]]:
    """Credential-shaped substrings, for the pre-commit guard.

    Returns `(label, sample, blocking)`. `blocking=True` entries are
    context-anchored and should fail a commit; advisory entries are shape-only
    and should print a warning the operator can wave through, because on this
    corpus most of them are Solidity constants.
    """
    hits: list[tuple[str, str, bool]] = []
    for name, pat in _REDACT_RULES:
        for m in pat.finditer(text):
            value = m.group(2) if name == "api_key" and m.lastindex and m.lastindex >= 2 \
                else m.group(0)
            hits.append((name, value[:24] + ("..." if len(value) > 24 else ""), True))
    if advisory:
        for name, pat in _ADVISORY_RULES:
            for m in pat.finditer(text):
                hits.append((name, m.group(0)[:24] + "...", False))
    return hits
