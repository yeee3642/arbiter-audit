"""Scan what a pull request changed, not what the repository contains.

Upstream Bastet's GitHub Action (`.example.github/actions/action.yml`) copies the
whole checkout into a container and runs `scan`, which globs `**/*.sol` and posts
every file to every active workflow, sequentially, polling the n8n execution API in
a `while True` with no sleep. On the Kaggle test set that plan is 344,008 calls. On
a pull request that touched one function it is still 344,008 calls, because nothing
in that pipeline knows which lines changed.

Routing already reduced the unit of work from a file to a function. A diff is
expressed in line ranges, and the tree-sitter index knows every function's span, so
intersecting the two gives the set of functions a commit actually touched -- and
then the existing routed plan runs over that set instead of the repository. A PR
gate stops being a batch job.

Two decisions worth stating, because both cost recall and both are deliberate:

- **A changed function is audited whole**, not just its changed lines. A bug is
  rarely confined to the edited line; the surrounding function is the smallest unit
  that can be judged. Combined with `--closure` the callees come too, so a change
  that breaks an invariant enforced elsewhere is still visible.

- **Deleting code is not scanned.** A diff hunk with no added lines removes a
  function or shrinks it, and there is no new code to audit. Recorded in the
  summary rather than silently dropped, because "this PR was clean" and "this PR
  had nothing to look at" are different statements.

What this cannot see is stated in `unscanned_reasons`: a change to a Solidity file
that the index skipped (vendored, non-production, or out of `scope.txt`), a change
outside any function body (a state variable, a constant, a pragma), and a change to
a non-Solidity file. The first two are real blind spots of a function-granular
gate; a constant is frequently exactly what a bug is.
"""

from __future__ import annotations

import re
import subprocess
from dataclasses import dataclass, field
from pathlib import Path

# `git diff --unified=0` hunk header: -old,count +new,count
_HUNK = re.compile(r"^@@ -(?:\d+)(?:,(?:\d+))? \+(\d+)(?:,(\d+))? @@")
_DIFF_FILE = re.compile(r"^\+\+\+ b/(.*)$")


@dataclass
class ChangedFile:
    path: str
    added_ranges: list[tuple[int, int]] = field(default_factory=list)

    @property
    def added_lines(self) -> int:
        return sum(e - s + 1 for s, e in self.added_ranges)


def parse_diff(diff_text: str) -> dict[str, ChangedFile]:
    """Added/modified line ranges per file, from `git diff --unified=0` output.

    Zero context is what makes this precise: with the default three lines of
    context a hunk header spans code the commit did not touch, and the gate would
    audit neighbouring functions on every edit.

    A hunk with `+0` lines is a pure deletion and contributes no range. The file
    still appears in the result with an empty range list, so a caller can tell
    "touched but nothing added" from "not touched".
    """
    files: dict[str, ChangedFile] = {}
    current: ChangedFile | None = None

    for line in diff_text.splitlines():
        m = _DIFF_FILE.match(line)
        if m:
            path = m.group(1)
            if path == "/dev/null":          # file deleted outright
                current = None
                continue
            current = files.setdefault(path, ChangedFile(path=path))
            continue
        if current is None:
            continue
        h = _HUNK.match(line)
        if h:
            start = int(h.group(1))
            count = 1 if h.group(2) is None else int(h.group(2))
            if count == 0:
                continue                     # deletion-only hunk
            current.added_ranges.append((start, start + count - 1))
    return files


def git_diff(base: str, head: str = "", repo_root: Path | None = None) -> str:
    """`git diff --unified=0` between two refs, or of the working tree.

    Passing `head=""` diffs the working tree against `base`, which is what a
    developer running the gate locally before pushing wants.
    """
    cmd = ["git", "diff", "--unified=0", "--no-color", "--no-ext-diff",
           "--diff-filter=ACMR", base]
    if head:
        cmd.append(head)
    proc = subprocess.run(cmd, capture_output=True, text=True,
                          cwd=str(repo_root) if repo_root else None)
    if proc.returncode != 0:
        raise RuntimeError(
            f"git diff failed ({proc.returncode}). Is {base!r} a valid ref, and is "
            f"the history deep enough? A shallow CI checkout needs "
            f"`fetch-depth: 0`.\n{proc.stderr.strip()}")
    return proc.stdout


def _overlaps(a: tuple[int, int], b: tuple[int, int]) -> bool:
    return a[0] <= b[1] and b[0] <= a[1]


@dataclass
class DiffScope:
    """Which indexed functions a diff touched, and what it could not reach."""
    touched: dict[str, set[str]] = field(default_factory=dict)   # path -> {fn names}
    changed_files: int = 0
    changed_sol_files: int = 0
    added_lines: int = 0
    unscanned_reasons: dict[str, list[str]] = field(default_factory=dict)

    @property
    def n_functions(self) -> int:
        return sum(len(v) for v in self.touched.values())

    def to_dict(self) -> dict:
        return {
            "changed_files": self.changed_files,
            "changed_sol_files": self.changed_sol_files,
            "added_lines": self.added_lines,
            "touched_functions": self.n_functions,
            "touched": {p: sorted(v) for p, v in sorted(self.touched.items())},
            "unscanned_reasons": {k: sorted(v)
                                  for k, v in sorted(self.unscanned_reasons.items())},
        }


def scope_from_diff(diff_files: dict[str, ChangedFile], repo_index: dict) -> DiffScope:
    """Intersect a diff's added ranges with the index's function spans.

    Paths are compared after POSIX normalisation on both sides: git always emits
    forward slashes, and the index does too since it uses `as_posix()`, but a caller
    may hand in either.
    """
    by_path = {f["path"].replace("\\", "/"): f for f in repo_index["files"]}
    scope = DiffScope(changed_files=len(diff_files))

    def note(reason: str, item: str) -> None:
        scope.unscanned_reasons.setdefault(reason, []).append(item)

    for raw_path, changed in diff_files.items():
        path = raw_path.replace("\\", "/")
        if not path.endswith(".sol"):
            note("not solidity", path)
            continue
        scope.changed_sol_files += 1
        scope.added_lines += changed.added_lines

        if not changed.added_ranges:
            note("deletion only, nothing added to audit", path)
            continue

        entry = by_path.get(path)
        if entry is None:
            # The file changed but the index does not hold it: vendored,
            # non-production, or excluded by scope.txt. A real blind spot of a
            # function-granular gate, so it is named rather than counted as clean.
            note("changed but not indexed (vendor / non-production / out of scope)",
                 path)
            continue

        hit: set[str] = set()
        for fn in entry["functions"]:
            span = (fn["start_line"], fn["end_line"])
            if any(_overlaps(span, r) for r in changed.added_ranges):
                hit.add(fn["name"])
        if hit:
            scope.touched[path] = hit
        else:
            note("changed outside any function body (state variable, constant, "
                 "pragma, import)", path)
    return scope


def restrict_index(repo_index: dict, scope: DiffScope) -> dict:
    """A copy of the index holding only the touched functions.

    Returning an index rather than a task list is what keeps this honest: the
    routed planner, the required-hints gate and the call closure all run unchanged
    on the result, so a diff scan is the same pipeline over a smaller input and not
    a second code path that could drift from the one the experiment measures.

    `n_bytes` is left at the original file size on purpose -- it is what
    `routing.broadcast_cost` charges upstream's plan, and rewriting it would make
    the diff scan look cheap by shrinking the thing it is compared against.
    """
    files = []
    for f in repo_index["files"]:
        path = f["path"].replace("\\", "/")
        keep = scope.touched.get(path)
        if not keep:
            continue
        fns = [fn for fn in f["functions"] if fn["name"] in keep]
        if fns:
            files.append({**f, "functions": fns})

    return {
        **repo_index,
        "n_files": len(files),
        "n_functions": sum(len(f["functions"]) for f in files),
        "files": files,
        "diff_scoped": True,
    }
