"""Solidity-aware source slicing.

The original harness POSTed the whole ``.sol`` file as one blob for every one of
the 56 detectors. Two things go wrong with that:

  * **Context dilution.** A 3 000-line file gives the model 3 000 lines of
    haystack for a needle-shaped question, and recall drops with position in
    the prompt. Files bigger than the context window are silently truncated by
    the server -- the original never checks.
  * **No localisation.** Because the model sees no structure, its
    ``function_name`` is frequently a guess, and there is no line number at all,
    so the report cannot be diffed against a ground truth.

This module cuts a file into *self-contained* slices: every slice carries the
pragma/import header plus contract-level declarations (state variables,
modifiers, events, structs) so a function is never judged without the storage
it touches. Byte and line offsets are retained for mapping findings back.

It is a brace-matching scanner, not a full parser -- deliberately: it must never
raise on the malformed, half-Yul, multi-version files that show up in real
audits.
"""

from __future__ import annotations

import re
from dataclasses import dataclass


@dataclass
class Slice:
    name: str          # e.g. "Vault.withdraw"
    text: str          # what actually goes in the prompt
    start_line: int    # 1-based line of the body within the original file
    end_line: int
    kind: str = "function"


def read_source(path: str) -> str:
    """Read a source file without exploding on encoding.

    The original ``scan.py`` calls ``open(path, "r")`` with no encoding, which
    picks up the platform default (cp1252 on Windows) and raises on any
    contract containing a non-ASCII character -- common in NatSpec.
    """
    data = open(path, "rb").read()
    for enc in ("utf-8-sig", "utf-8", "utf-16", "cp1252", "latin-1"):
        try:
            return data.decode(enc)
        except (UnicodeDecodeError, UnicodeError):
            continue
    return data.decode("utf-8", "replace")


# --------------------------------------------------------------------------
# masking: blank out comments and string literals so brace matching is sane
# --------------------------------------------------------------------------


def _mask(src: str) -> str:
    out = list(src)
    i, n = 0, len(src)
    while i < n:
        c = src[i]
        nxt = src[i + 1] if i + 1 < n else ""
        if c == "/" and nxt == "/":
            while i < n and src[i] != "\n":
                out[i] = " "
                i += 1
        elif c == "/" and nxt == "*":
            while i < n and not (src[i] == "*" and i + 1 < n and src[i + 1] == "/"):
                if src[i] != "\n":
                    out[i] = " "
                i += 1
            for _ in range(2):
                if i < n:
                    out[i] = " "
                    i += 1
        elif c in "\"'":
            quote = c
            out[i] = " "
            i += 1
            while i < n and src[i] != quote:
                if src[i] == "\\":
                    out[i] = " "
                    i += 1
                    if i < n:
                        out[i] = " "
                        i += 1
                    continue
                if src[i] != "\n":
                    out[i] = " "
                i += 1
            if i < n:
                out[i] = " "
                i += 1
        else:
            i += 1
    return "".join(out)


def _match_brace(masked: str, open_idx: int) -> int:
    """Index just past the ``}`` closing the ``{`` at ``open_idx``, or -1."""
    depth = 0
    for i in range(open_idx, len(masked)):
        if masked[i] == "{":
            depth += 1
        elif masked[i] == "}":
            depth -= 1
            if depth == 0:
                return i + 1
    return -1


_CONTRACT_RE = re.compile(r"\b(contract|library|interface|abstract\s+contract)\s+(\w+)")
_FUNC_RE = re.compile(r"\b(function\s+(\w+)|constructor|receive\s*\(|fallback\s*\()")


def _line_of(src: str, idx: int) -> int:
    return src.count("\n", 0, idx) + 1


# --------------------------------------------------------------------------


def file_header(src: str, masked: str, limit: int = 2500) -> str:
    """pragma + import lines, so every slice knows its language version and deps."""
    first = len(src)
    m = _CONTRACT_RE.search(masked)
    if m:
        first = m.start()
    head_lines = []
    for line in src[:first].splitlines():
        s = line.strip()
        if s.startswith(("pragma", "import", "// SPDX")):
            head_lines.append(line)
    head = "\n".join(head_lines)
    return head[:limit]


def _contract_context(src: str, masked: str, body_start: int, body_end: int, limit: int) -> str:
    """Contract-level declarations: everything that is not a function body.

    Without this the model sees ``balances[msg.sender] -= amt`` and has no idea
    whether ``balances`` is a mapping, whether there is a ``nonReentrant``
    modifier, or what the storage layout is.
    """
    keep: list[str] = []
    i = body_start
    while i < body_end:
        fm = _FUNC_RE.search(masked, i, body_end)
        if not fm:
            keep.append(src[i:body_end])
            break
        keep.append(src[i:fm.start()])
        brace = masked.find("{", fm.start(), body_end)
        semi = masked.find(";", fm.start(), body_end)
        if brace == -1 or (semi != -1 and semi < brace):
            # interface / abstract declaration -- keep the signature, it's context
            end = (semi + 1) if semi != -1 else fm.end()
            keep.append(src[fm.start():end])
            i = end
            continue
        end = _match_brace(masked, brace)
        if end == -1:
            break
        # replace the body with a stub so the signature survives as context
        keep.append(src[fm.start():brace] + "{ ... }")
        i = end

    text = "".join(keep)
    # squeeze runs of blank lines
    text = re.sub(r"\n\s*\n\s*\n+", "\n\n", text).strip()
    if len(text) > limit:
        text = text[:limit] + "\n// ... (context truncated)"
    return text


def slice_solidity(src: str, *, max_chars: int = 12_000, context_chars: int = 2_500,
                   file_label: str = "") -> list[Slice]:
    """Cut ``src`` into self-contained, prompt-sized slices.

    Small files come back as a single whole-file slice -- slicing a 200 line
    contract buys nothing and costs the model cross-function visibility.
    """
    masked = _mask(src)
    header = file_header(src, masked, context_chars)

    if len(src) <= max_chars:
        return [Slice(name=file_label or "<file>", text=src, start_line=1,
                      end_line=src.count("\n") + 1, kind="file")]

    slices: list[Slice] = []
    for cm in _CONTRACT_RE.finditer(masked):
        cname = cm.group(2)
        brace = masked.find("{", cm.end())
        if brace == -1:
            continue
        cend = _match_brace(masked, brace)
        if cend == -1:
            cend = len(src)
        body_start, body_end = brace + 1, cend - 1
        ctx = _contract_context(src, masked, body_start, body_end, context_chars)
        preamble = f"{header}\n\n// ==== contract-level context for `{cname}` ====\n{ctx}\n\n// ==== function(s) under review ====\n"
        budget = max(1500, max_chars - len(preamble))

        # collect function bodies
        funcs: list[tuple[str, int, int]] = []
        i = body_start
        while i < body_end:
            fm = _FUNC_RE.search(masked, i, body_end)
            if not fm:
                break
            fbrace = masked.find("{", fm.start(), body_end)
            semi = masked.find(";", fm.start(), body_end)
            if fbrace == -1 or (semi != -1 and semi < fbrace):
                i = (semi + 1) if semi != -1 else fm.end()
                continue
            fend = _match_brace(masked, fbrace)
            if fend == -1:
                break
            fname = fm.group(2) or fm.group(1).split("(")[0].strip()
            funcs.append((fname, fm.start(), fend))
            i = fend

        if not funcs:
            slices.append(Slice(name=f"{cname}", text=preamble + src[body_start:body_end][:budget],
                                start_line=_line_of(src, body_start), end_line=_line_of(src, body_end),
                                kind="contract"))
            continue

        # greedily pack whole functions into slices
        batch: list[tuple[str, int, int]] = []
        size = 0
        for f in funcs:
            flen = f[2] - f[1]
            if batch and size + flen > budget:
                slices.append(_emit(src, cname, preamble, batch))
                batch, size = [], 0
            if flen > budget:  # single monster function -- give it its own slice, truncated
                slices.append(_emit(src, cname, preamble, [f], budget))
                continue
            batch.append(f)
            size += flen
        if batch:
            slices.append(_emit(src, cname, preamble, batch))

    if not slices:  # no recognisable contract -- fall back to fixed windows
        return _window(src, max_chars, file_label)
    return slices


def _emit(src: str, cname: str, preamble: str, batch: list[tuple[str, int, int]],
          budget: int | None = None) -> Slice:
    body = "\n\n".join(src[s:e] for _, s, e in batch)
    if budget is not None and len(body) > budget:
        body = body[:budget] + "\n// ... (function truncated)"
    names = ",".join(n for n, _, _ in batch[:3]) + ("..." if len(batch) > 3 else "")
    return Slice(
        name=f"{cname}.{names}",
        text=preamble + body,
        start_line=_line_of(src, batch[0][1]),
        end_line=_line_of(src, batch[-1][2]),
    )


def _window(src: str, max_chars: int, label: str) -> list[Slice]:
    lines = src.splitlines(keepends=True)
    out, buf, start = [], [], 1
    for idx, line in enumerate(lines, 1):
        buf.append(line)
        if sum(len(x) for x in buf) >= max_chars:
            out.append(Slice(name=f"{label}#{start}-{idx}", text="".join(buf),
                             start_line=start, end_line=idx, kind="window"))
            buf, start = [], idx + 1
    if buf:
        out.append(Slice(name=f"{label}#{start}-{len(lines)}", text="".join(buf),
                         start_line=start, end_line=len(lines), kind="window"))
    return out
