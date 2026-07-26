"""Evidence grounding: does the quoted code actually exist in the source?

This is the cheapest false-positive filter in the harness -- it costs zero
tokens. A model that has invented a vulnerability almost always invents the
code that proves it, because it is reciting a pattern from training data rather
than reading the file in front of it. Checking that ``code_snippet`` really
occurs in the supplied source kills those outright, and as a side effect gives
every surviving finding a **line number**, which the original harness never
produced.

Matching is whitespace-insensitive (models re-indent) but token-exact
(``amountOutMin`` and ``amountOut`` are different bugs).
"""

from __future__ import annotations

import re

_WS = re.compile(r"\s+")


class SourceIndex:
    """Normalised view of a source file plus a map back to original offsets.

    Whitespace is removed entirely rather than merely collapsed. Models
    re-indent, re-wrap and re-space the code they quote -- ``swap(a, 0, path)``
    comes back as ``swap( a , 0 , path )`` often enough that collapsing runs is
    not sufficient. Erring toward permissive matching is the right direction
    here: this filter *drops* findings, so a miss costs recall.
    """

    def __init__(self, src: str):
        self.src = src
        norm_chars: list[str] = []
        self.back: list[int] = []  # normalised index -> original index
        for i, ch in enumerate(src):
            if ch.isspace():
                continue
            norm_chars.append(ch)
            self.back.append(i)
        self.norm = "".join(norm_chars)
        self._line_starts = [0] + [m.end() for m in re.finditer(r"\n", src)]

    def line_of(self, orig_idx: int) -> int:
        lo, hi = 0, len(self._line_starts) - 1
        while lo < hi:
            mid = (lo + hi + 1) // 2
            if self._line_starts[mid] <= orig_idx:
                lo = mid
            else:
                hi = mid - 1
        return lo + 1

    def find(self, fragment: str) -> int | None:
        """Return the 1-based line where ``fragment`` occurs, else None."""
        frag = _WS.sub("", fragment)
        # Below ~8 significant characters a "match" is noise: `}`, `return;`,
        # `_;` occur everywhere and prove nothing.
        if len(frag) < 8:
            return None
        pos = self.norm.find(frag)
        if pos == -1:
            return None
        return self.line_of(self.back[pos])


def _significant_lines(snippet: list[str]) -> list[str]:
    """Snippet lines worth checking: drop braces, ellipses, comments, noise."""
    out = []
    for block in snippet:
        for line in str(block).splitlines():
            s = line.strip()
            if not s or s in {"{", "}", "(", ")", "...", "// ...", "```"}:
                continue
            if s.startswith("//") or s.startswith("*") or s.startswith("/*"):
                continue
            if len(s) < 6:
                continue
            out.append(s)
    return out


def ground(finding, index: SourceIndex, slice_start_line: int = 1) -> tuple[bool, float, int | None]:
    """Check a finding's evidence against the real source.

    Returns ``(grounded, match_ratio, line)``.

    ``grounded`` requires the *majority* of significant snippet lines to be
    present verbatim. A single incidental match (``require(msg.sender ==
    owner);`` appears in half the corpus) is not enough.
    """
    lines = _significant_lines(finding.code_snippet)
    if not lines:
        # No evidence offered. Fall back to the function name, which at least
        # has to exist -- but this never counts as grounded.
        fn = (finding.function_name or "").strip()
        if fn and fn != "<unknown>":
            hit = index.find(f"function {fn}") or index.find(fn + "(")
            return False, 0.0, hit
        return False, 0.0, None

    hits, first_line = 0, None
    for line in lines:
        ln = index.find(line)
        if ln is not None:
            hits += 1
            if first_line is None or ln < first_line:
                first_line = ln
    ratio = hits / len(lines)
    # A whole multi-line block matching contiguously is the strongest signal.
    if not first_line:
        joined = " ".join(lines)
        first_line = index.find(joined)
        if first_line:
            ratio = 1.0
            hits = len(lines)
    return (ratio >= 0.5 and hits >= 1), ratio, first_line


def apply_grounding(findings, src: str, *, drop_ungrounded: bool = True):
    """Annotate findings with ``grounded``/``line``; optionally drop the ghosts.

    Returns ``(kept, dropped)``.
    """
    index = SourceIndex(src)
    kept, dropped = [], []
    for f in findings:
        ok, ratio, line = ground(f, index)
        f.grounded = ok
        f.line = line
        if ok:
            # Grounded evidence is a genuine confidence signal; unmatched
            # evidence is a genuine warning sign.
            f.confidence = min(1.0, f.confidence + 0.1 * ratio)
        else:
            f.confidence = max(0.0, f.confidence - 0.25)
            if drop_ungrounded:
                f.verdict_reason = f"dropped: code_snippet not found in source (match ratio {ratio:.2f})"
                dropped.append(f)
                continue
        kept.append(f)
    return kept, dropped
