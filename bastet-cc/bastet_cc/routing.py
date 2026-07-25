"""Match detectors to the code they actually care about, with no model in the loop.

Upstream Bastet sends every file to every detector. On the Kaggle test set that is
344,008 LLM calls carrying 535M input tokens -- the pipeline cannot finish its own
benchmark. Yet a slippage detector reading a file with no swap in it was never
going to return anything.

Routing closes that gap using the vocabulary each detector already declares. The
hard part is that a detector's prompt mentions both rare, decisive identifiers
(`swapExactTokensForTokens`) and ubiquitous ones (`address`, `transfer`). Matching
on the latter routes everything everywhere and saves nothing, so hints are weighted
by how rare they are in the corpus, exactly like IDF: a hint that appears in most
functions carries no information about which detector belongs there.

Recall is the thing being traded against, so routing stays deliberately generous --
a single surviving hint is enough to route, and detectors whose vocabulary is all
common words fall back to broadcast rather than silently going dark.
"""

from __future__ import annotations

import json
from dataclasses import dataclass, field
from pathlib import Path

# A hint occurring in more than this share of functions says nothing about which
# detector is relevant, so it is dropped from that detector's signature.
MAX_DOC_FREQ = 0.15

# Detectors left with fewer than this many discriminating hints cannot be routed
# safely; they broadcast instead. Losing recall costs more than spending tokens.
MIN_HINTS = 2


@dataclass
class Detector:
    id: str
    name: str
    source_workflow: str
    tags: list[str]
    routing_hints: list[str]
    prompt_chars: int
    signature: set[str] | None = None      # discriminating hints, set by fit()
    broadcast: bool = False                # too generic to route

    # Synthesised detectors carry three extra fields; the 56 extracted from upstream
    # do not, so all three default and `Detector(**row)` keeps working for both.
    #
    # required_hints is an AND gate applied before routing's OR: a detector for a
    # standard nobody implements here (ERC777, Gnosis Safe) matches stray identifiers
    # in almost any file, and firing it everywhere would spend the routing saving on
    # noise. routing_hints say "this function might be relevant"; required_hints say
    # "this file is not even the right kind of contract".
    required_hints: list[str] = field(default_factory=list)

    # Induced from a single repository, or failed leave-one-repo-out. Kept rather than
    # dropped so the coverage claim stays honest, but its findings need corroboration.
    gated: bool = False
    synthesized: bool = False


@dataclass
class Slice:
    """A unit of code handed to one detector: a function plus its location."""
    repo: str
    path: str
    contract: str
    function: str
    start_line: int
    end_line: int
    source: str

    @property
    def id(self) -> str:
        return f"{self.path}:{self.contract}.{self.function}:{self.start_line}"


def load_detectors(detectors_dir: str | Path) -> list[Detector]:
    index = json.loads((Path(detectors_dir) / "index.json").read_text())
    return [Detector(**d) for d in index]


def slices_from_index(repo_index: dict) -> list[Slice]:
    out: list[Slice] = []
    for f in repo_index["files"]:
        for fn in f["functions"]:
            out.append(Slice(
                repo=repo_index["repo"],
                path=f["path"],
                contract=fn["contract"],
                function=fn["name"],
                start_line=fn["start_line"],
                end_line=fn["end_line"],
                source=fn["source"],
            ))
    return out


def fit(detectors: list[Detector], repo_indexes: list[dict]) -> dict:
    """Learn which hints discriminate, from the corpus being scanned.

    Document frequency is measured over functions rather than files: detectors
    select functions, and a term common across files may still be rare per-function.
    """
    doc_freq: dict[str, int] = {}
    n_docs = 0

    for ix in repo_indexes:
        for f in ix["files"]:
            for fn in f["functions"]:
                n_docs += 1
                for ident in set(fn["identifiers"]):
                    doc_freq[ident] = doc_freq.get(ident, 0) + 1

    if n_docs == 0:
        for d in detectors:
            d.signature, d.broadcast = set(), True
        return {"n_functions": 0, "vocab": 0}

    stats = []
    for d in detectors:
        keep = {
            h for h in d.routing_hints
            if doc_freq.get(h, 0) / n_docs <= MAX_DOC_FREQ
        }
        # Hints absent from the corpus entirely are kept: they are maximally
        # specific, they just happen not to occur here, which is the correct
        # signal to not route this detector at all.
        d.signature = keep
        d.broadcast = len(keep) < MIN_HINTS
        stats.append((d.id, len(d.routing_hints), len(keep), d.broadcast))

    return {
        "n_functions": n_docs,
        "vocab": len(doc_freq),
        "n_broadcast": sum(1 for d in detectors if d.broadcast),
        "detectors": stats,
    }


@dataclass
class Task:
    """One LLM call: a detector, a file, and only the functions that matched.

    Batching per file rather than per function is what makes routing pay. A
    per-function call count exceeds plain broadcast -- 16,518 functions against
    1,795 files -- so the win has to come from shrinking each call, not multiplying
    them. One call per (detector, file) pair caps the count at what broadcast
    already spends, while the payload carries matched functions instead of the
    whole file.
    """
    detector: Detector
    path: str
    slices: list[Slice]

    @property
    def code_chars(self) -> int:
        return sum(len(s.source) for s in self.slices)


def route(detectors: list[Detector], repo_index: dict) -> list[Task]:
    """Build the call plan: one task per (detector, file) pair that has a match."""
    per_file: list[tuple[str, list[tuple[Slice, set[str]]]]] = []

    for f in repo_index["files"]:
        entries: list[tuple[Slice, set[str]]] = []
        for fn in f["functions"]:
            sl = Slice(
                repo=repo_index["repo"], path=f["path"], contract=fn["contract"],
                function=fn["name"], start_line=fn["start_line"],
                end_line=fn["end_line"], source=fn["source"],
            )
            entries.append((sl, set(fn["identifiers"])))
        if entries:
            per_file.append((f["path"], entries))

    tasks: list[Task] = []
    for d in detectors:
        sig = d.signature or set()
        for path, entries in per_file:
            if d.broadcast:
                matched = [sl for sl, _ in entries]
            else:
                matched = [sl for sl, idents in entries if idents & sig]
            if matched:
                tasks.append(Task(detector=d, path=path, slices=matched))
    return tasks


def cost(tasks: list[Task]) -> dict:
    """Input-token cost of a routing plan, at the usual 4-chars-per-token estimate."""
    code = sum(t.code_chars for t in tasks)
    prompt = sum(t.detector.prompt_chars for t in tasks)
    return {
        "calls": len(tasks),
        "input_tokens": (code + prompt) // 4,
        "code_tokens": code // 4,
        "prompt_tokens": prompt // 4,
        "slices": sum(len(t.slices) for t in tasks),
    }


def broadcast_cost(detectors: list[Detector], repo_index: dict) -> dict:
    """What upstream Bastet would spend: every file, to every detector."""
    n_files = len(repo_index["files"])
    code = sum(f["n_bytes"] for f in repo_index["files"])
    calls = n_files * len(detectors)
    prompt = sum(d.prompt_chars for d in detectors) * n_files
    return {
        "calls": calls,
        "input_tokens": (code * len(detectors) + prompt) // 4,
        "code_tokens": code * len(detectors) // 4,
        "prompt_tokens": prompt // 4,
    }
