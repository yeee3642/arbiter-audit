"""Clustering, self-consistency voting, and cross-detector dedup.

The original harness ran 56 detectors over the same file and concatenated the
results, so a reentrancy bug reported by both ``owasp2025__4`` and
``access_control__1`` appeared twice in the report. It also ran each detector
exactly once, which on an open-weight model is a coin flip: a decoder that
misses a bug 40% of the time misses it 40% of the time, full stop.

Sampling the detector k times and requiring agreement converts that variance
into a usable signal -- findings the model produces consistently are far more
likely to be real than ones it produces once.
"""

from __future__ import annotations

from .schema import Finding, _norm_name, _sig


def _similar(a: Finding, b: Finding) -> bool:
    if a.file != b.file:
        return False
    fa, fb = _norm_name(a.function_name), _norm_name(b.function_name)
    if fa and fb and fa != fb and fa != "<unknown>" and fb != "<unknown>":
        return False
    # The signature must describe *what kind of bug*, not *where it is* -- the
    # location is already settled by the function-name gate above. Leaving the
    # function name in the signature makes "Reentrancy in withdraw" and
    # "Unchecked external call in withdraw" look half-identical on the strength
    # of the word "withdraw" alone, and two unrelated bugs get merged away.
    drop = {t for t in (fa, fb) if t}

    # Compare on the summary alone as well as on summary+description, taking the
    # more generous reading: two detectors that found the same bug write
    # near-identical one-line summaries but wildly different rationales, and
    # folding the rationale in dilutes the signature until the pair slips past
    # the threshold and gets reported twice.
    overlap = max(
        _overlap(_sig(a.summary), _sig(b.summary), drop),
        _overlap(_sig(a.summary + " " + a.description), _sig(b.summary + " " + b.description), drop),
    )
    return overlap >= 0.5


def _overlap(sa, sb, drop: set[str]) -> float:
    sa, sb = sa - drop, sb - drop
    if not sa or not sb:
        # Nothing distinguishing left on one side; fall through to "unrelated"
        # rather than merging on no evidence.
        return 0.0
    return len(sa & sb) / min(len(sa), len(sb))


def cluster(findings: list[Finding]) -> list[list[Finding]]:
    """Greedy single-link clustering of near-duplicate findings."""
    clusters: list[list[Finding]] = []
    for f in findings:
        for c in clusters:
            if _similar(c[0], f):
                c.append(f)
                break
        else:
            clusters.append([f])
    return clusters


def _merge(group: list[Finding], samples: int) -> Finding:
    """Collapse a cluster into its single best representative."""
    best = max(group, key=lambda f: (f.grounded, f.confidence, len(f.code_snippet)))
    best.votes = len(group)
    best.samples = samples
    # Union the evidence -- different samples often quote different lines.
    seen, snippets = set(), []
    for f in group:
        for s in f.code_snippet:
            k = " ".join(s.split())
            if k and k not in seen:
                seen.add(k)
                snippets.append(s)
    best.code_snippet = snippets[:8]
    if best.line is None:
        for f in group:
            if f.line is not None:
                best.line = f.line
                break
    # Severity by majority, tie broken upward (a security tool should not
    # round risk down).
    order = {"low": 0, "medium": 1, "high": 2}
    counts: dict[str, int] = {}
    for f in group:
        counts[f.severity] = counts.get(f.severity, 0) + 1
    best.severity = max(counts, key=lambda s: (counts[s], order[s]))
    # Detector provenance, useful when triaging. Keep ALL of them: this string
    # is what attributes a finding to a vulnerability class downstream, so
    # truncating it silently reclassifies findings.
    dets: set[str] = set()
    for f in group:
        dets.update(d.strip() for d in f.detector.split(",") if d.strip())
    best.detector = ",".join(sorted(dets))
    return best


def vote(findings: list[Finding], samples: int, threshold: float) -> tuple[list[Finding], list[Finding]]:
    """Self-consistency filter.

    A cluster must appear in at least ``ceil(threshold * samples)`` of the k
    samples to survive. Returns ``(kept, rejected)``.
    """
    need = max(1, int(round(threshold * samples))) if samples > 1 else 1
    kept, rejected = [], []
    for group in cluster(findings):
        rep = _merge(group, samples)
        # Votes are counted per distinct sample, not per raw finding -- one
        # sample that reports the same bug twice must not out-vote two samples
        # that report it once each.
        rep.votes = len({f.sample_idx for f in group})
        if samples > 1 and rep.votes < need:
            rep.verdict_reason = f"dropped: only {rep.votes}/{samples} samples agreed (need {need})"
            rejected.append(rep)
        else:
            kept.append(rep)
    return kept, rejected


def merge_across_detectors(findings: list[Finding]) -> list[Finding]:
    """Final pass: one report line per real bug, no matter how many detectors saw it."""
    return [_merge(g, g[0].samples if g else 1) for g in cluster(findings)]
