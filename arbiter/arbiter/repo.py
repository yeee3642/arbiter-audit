"""Reconstruct a compilable context for one contract inside a real repository.

The hermetic workspace -- one file, no dependencies -- compiled 24 of 24 samples in the
authored benchmark and 0 of 24 contracts drawn from OneSavie's own dataset. The failure
is not subtle: real audit repositories import. Measured across the 17 repositories that
dataset's evaluation drew from, 975 Solidity files carry 2,600 import statements, and
every one of them has to resolve before a single line of evidence can be produced.

Those imports fall into exactly two kinds, which is what makes this tractable:

  * repo-internal (`src/Kernel.sol`, `@protocol/core/...`, `modules/VOTES.sol`) --
    the file being imported is already in the repository, reachable under some prefix
    the project declared in a config this module does not need to parse.
  * external (`@openzeppelin/contracts/...`, `solmate/...`, `forge-std/...`) --
    a published library, absent from the checkout, of which 355 of the 500 external
    imports in that corpus are OpenZeppelin alone.

Both are resolved by the same mechanism: **suffix matching**. An import spec is a path
with a prefix the project chose and a tail that is a real path on disk. Strip prefixes
one segment at a time until the tail matches an indexed file, and the remapping that
would have made it resolve falls out of the match. No config parsing, no per-project
special case, and it fails loudly rather than silently producing a wrong file.

What this module deliberately does NOT do is make the repository build. It makes the
*import closure of one contract* build, which is a far smaller problem: forge compiles
what a test reaches, so a repository with 400 broken files still yields evidence for the
one contract under audit.
"""

from __future__ import annotations

import os
import re
from dataclasses import dataclass, field
from pathlib import Path

IMPORT_RE = re.compile(
    r'^\s*import\s+(?:[^"\';]*?\s+from\s+)?["\']([^"\']+)["\']', re.MULTILINE
)
PRAGMA_RE = re.compile(r"pragma\s+solidity\s+([^;]+);")

# Directories that never contain the source under audit and would bloat the mirror.
SKIP_DIRS = {
    ".git", "node_modules", "artifacts", "cache", "out", "typechain", "typechain-types",
    "coverage", "build", ".vscode", ".github", "docs", "broadcast",
}

# Where the vendored libraries live. Built by scripts/build_dep_cache.sh from the
# measured import census, not from a guess at what might be needed.
DEFAULT_DEP_CACHE = Path(os.path.expanduser("~/soldeps"))

# OpenZeppelin is version-sensitive in a way the others are not: a contract pinned to
# ^0.6.12 cannot compile against v5, and v5 removed names v4 code still uses. Ordered
# by preference for a given pragma, most-likely first.
OZ_BY_PRAGMA: dict[str, list[str]] = {
    "0.8": ["openzeppelin-v4", "openzeppelin-v5", "openzeppelin-v3"],
    "0.8.20+": ["openzeppelin-v5", "openzeppelin-v4"],
    "0.7": ["openzeppelin-v3", "openzeppelin-v4"],
    "0.6": ["openzeppelin-v3"],
    "0.5": ["openzeppelin-v3"],
}
OZ_UP_BY_PRAGMA: dict[str, list[str]] = {
    "0.8": ["openzeppelin-up-v4", "openzeppelin-up-v5", "openzeppelin-up-v3"],
    "0.8.20+": ["openzeppelin-up-v5", "openzeppelin-up-v4"],
    "0.7": ["openzeppelin-up-v3"],
    "0.6": ["openzeppelin-up-v3"],
    "0.5": ["openzeppelin-up-v3"],
}


def pragma_band(source: str) -> str:
    """Coarse solc band for a source file, used only to order dependency candidates."""
    m = PRAGMA_RE.search(source)
    if not m:
        return "0.8"
    spec = m.group(1)
    versions = re.findall(r"(\d+)\.(\d+)\.?(\d+)?", spec)
    if not versions:
        return "0.8"
    major, minor, patch = versions[0]
    if major != "0":
        return "0.8"
    if minor == "8":
        # v5 dropped support below 0.8.20, so a file that demands >=0.8.20 must not be
        # offered v4 first -- and one pinned below it must not be offered v5 at all.
        if patch and int(patch) >= 20 and not spec.strip().startswith("^"):
            return "0.8.20+"
        if ">=0.8.2" in spec or ">=0.8.3" in spec:
            return "0.8.20+"
        return "0.8"
    return f"0.{minor}" if minor in ("5", "6", "7") else "0.8"


def solc_floor(source: str) -> tuple[int, int, int]:
    """Lowest solc version this file will accept, as a tuple. Used to decide whether the
    harness may use post-0.8.4 syntax such as custom errors."""
    m = PRAGMA_RE.search(source)
    if not m:
        return (0, 8, 0)
    nums = re.findall(r"(\d+)\.(\d+)\.(\d+)", m.group(1))
    if not nums:
        nums = [(a, b, "0") for a, b, _ in re.findall(r"(\d+)\.(\d+)()", m.group(1))]
    if not nums:
        return (0, 8, 0)
    a, b, c = nums[0]
    return (int(a), int(b), int(c or 0))


@dataclass
class FileIndex:
    """Every .sol path under a root, searchable by path suffix."""

    root: Path
    paths: list[Path] = field(default_factory=list)

    @staticmethod
    def build(root: Path) -> "FileIndex":
        paths: list[Path] = []
        for dirpath, dirnames, filenames in os.walk(root):
            dirnames[:] = [d for d in dirnames if d not in SKIP_DIRS]
            for name in filenames:
                if name.endswith(".sol"):
                    paths.append(Path(dirpath) / name)
        return FileIndex(root=root, paths=paths)

    def ending_with(self, tail: str) -> list[Path]:
        needle = "/" + tail.strip("/")
        return [p for p in self.paths if p.as_posix().endswith(needle)]


def split_candidates(spec: str) -> list[tuple[str, str]]:
    """Every (prefix, tail) split of an import spec, longest prefix first.

    `@protocol/core/Foo.sol` yields ("@protocol/core", "Foo.sol") then
    ("@protocol", "core/Foo.sol"). Longest-prefix-first matters: it prefers the
    interpretation that leaves the most path on disk to actually match, which is the one
    least likely to collide with an unrelated file of the same basename.
    """
    segs = [s for s in spec.split("/") if s]
    out = []
    for k in range(len(segs) - 1, 0, -1):
        out.append(("/".join(segs[:k]), "/".join(segs[k:])))
    return out


@dataclass
class Resolution:
    remappings: dict[str, str] = field(default_factory=dict)
    unresolved: list[str] = field(default_factory=list)
    external_used: set[str] = field(default_factory=set)

    def as_lines(self) -> list[str]:
        return [f"{k}={v}" for k, v in sorted(self.remappings.items())]


class RepoContext:
    """One repository, indexed once and reused for every contract audited inside it."""

    def __init__(self, repo_root: Path, dep_cache: Path | None = None) -> None:
        self.root = Path(repo_root).resolve()
        self.dep_cache = Path(dep_cache or DEFAULT_DEP_CACHE)
        self.index = FileIndex.build(self.root)
        self._dep_index: dict[str, FileIndex] = {}

    # -- dependency cache ----------------------------------------------------

    def dep_index(self, name: str) -> FileIndex | None:
        if name in self._dep_index:
            return self._dep_index[name]
        path = self.dep_cache / name
        if not path.is_dir():
            return None
        self._dep_index[name] = FileIndex.build(path)
        return self._dep_index[name]

    def _dep_order(self, band: str) -> list[str]:
        """Which vendored packages to search, in order, for a file in this pragma band."""
        order: list[str] = []
        order += OZ_BY_PRAGMA.get(band, OZ_BY_PRAGMA["0.8"])
        order += OZ_UP_BY_PRAGMA.get(band, OZ_UP_BY_PRAGMA["0.8"])
        # hardhat-shim ahead of forge-std: both ship a `console.sol`, and a suffix match
        # on the basename alone would otherwise hand `hardhat/console.sol` to forge-std.
        order += [
            "hardhat-shim", "forge-std", "solmate", "uniswap-v2-core",
            "uniswap-v2-periphery", "uniswap-v3-core", "uniswap-v3-periphery",
            "chainlink",
        ]
        return order

    # -- closure -------------------------------------------------------------

    def imports_of(self, path: Path) -> list[str]:
        try:
            return IMPORT_RE.findall(path.read_text(encoding="utf-8", errors="ignore"))
        except OSError:
            return []

    def resolve(self, target: Path, max_depth: int = 40) -> Resolution:
        """Walk the target's import closure, emitting the remappings that make it build.

        Breadth-first over discovered files rather than over the whole repository: a
        contract that imports four files should not pay for a repository of four hundred,
        and a repository whose unrelated half is broken should still yield evidence.
        """
        target = Path(target).resolve()
        band = pragma_band(target.read_text(encoding="utf-8", errors="ignore"))
        res = Resolution()
        seen: set[Path] = set()
        queue: list[Path] = [target]
        depth = 0

        while queue and depth < max_depth:
            depth += 1
            nxt: list[Path] = []
            for path in queue:
                if path in seen:
                    continue
                seen.add(path)
                for spec in self.imports_of(path):
                    if spec.startswith("."):
                        # Relative imports resolve against the mirrored tree by
                        # construction, so nothing has to be remapped -- but the file
                        # they name still has to be walked for ITS imports.
                        resolved = (path.parent / spec).resolve()
                        if resolved.exists():
                            nxt.append(resolved)
                        else:
                            res.unresolved.append(f"{spec} (from {path.name})")
                        continue
                    hit = self._resolve_bare(spec, band, res)
                    if hit is not None:
                        nxt.append(hit)
                    elif spec not in res.unresolved:
                        res.unresolved.append(spec)
            queue = nxt
        return res

    def _resolve_bare(self, spec: str, band: str, res: Resolution) -> Path | None:
        """Find the file a bare import names, recording the remapping that reaches it."""
        # An already-emitted remapping may cover this spec; honour it so the closure walk
        # follows the same file forge will.
        for prefix, dest in res.remappings.items():
            if spec.startswith(prefix):
                cand = Path(dest) / spec[len(prefix):]
                if cand.exists():
                    return cand.resolve()

        for prefix, tail in split_candidates(spec):
            hits = self.index.ending_with(tail)
            if hits:
                best = self._pick(hits, tail, prefix)
                base = self._base_for(best, tail)
                if base is not None:
                    res.remappings[prefix + "/"] = str(base) + "/"
                    return best
        # Not in the repository: it is a published library.
        for pkg in self._dep_order(band):
            idx = self.dep_index(pkg)
            if idx is None:
                continue
            for prefix, tail in split_candidates(spec):
                hits = idx.ending_with(tail)
                if not hits:
                    continue
                best = self._pick(hits, tail, prefix)
                base = self._base_for(best, tail)
                if base is not None:
                    res.remappings[prefix + "/"] = str(base) + "/"
                    res.external_used.add(pkg)
                    return best
        return None

    @staticmethod
    def _base_for(hit: Path, tail: str) -> Path | None:
        posix = hit.as_posix()
        needle = "/" + tail.strip("/")
        if not posix.endswith(needle):
            return None
        return Path(posix[: -len(needle)])

    @staticmethod
    def _pick(hits: list[Path], tail: str, prefix: str) -> Path:
        """Choose among several files whose path ends the same way.

        Prefer the one whose directory actually ends with the prefix the project used --
        a project that writes `modules/VOTES.sol` usually does have a `modules/`
        directory -- then the shallowest path, which avoids reaching into a `test/` or
        `mocks/` copy of a contract when the real one is nearer the root.
        """
        last = prefix.split("/")[-1].lstrip("@")

        def score(p: Path) -> tuple[int, int, int]:
            base = RepoContext._base_for(p, tail)
            named = 0 if (base and base.name == last) else 1
            testish = 1 if re.search(r"/(test|tests|mock|mocks)/", p.as_posix()) else 0
            return (named, testish, len(p.as_posix()))

        return sorted(hits, key=score)[0]


# The workspace reaches the contract under audit through a remapping rather than a
# relative path, so nothing has to be copied and no import escapes the project root.
TARGET_PREFIX = "arbiter-target/"


@dataclass
class RepoPlan:
    """Everything a Workspace needs to build one contract in its repository's context.

    Nothing is copied. The repository is read where it lies and reached through
    remappings, because forge resolves the source graph itself and hands solc the files
    inline -- so a workspace costs a few hundred bytes rather than a mirror of the
    repository, and hundreds can run concurrently.
    """

    repo_root: Path
    target: Path
    target_import: str       # what the shim in src/Target.sol imports
    remappings: list[str]
    unresolved: list[str]
    external_used: list[str]
    band: str
    floor: tuple[int, int, int]
    # Which compilation set was found to work, so later workspaces for the same contract
    # skip straight to it instead of rediscovering it. "src" is the minimal set.
    chosen_src: str = "src"

    @property
    def resolved(self) -> bool:
        return not self.unresolved

    @property
    def test_pragma(self) -> str:
        """A pragma the harness can carry that still intersects the target's.

        forge groups files into compilation units by pragma compatibility, so a test
        declaring >=0.8.0 cannot be compiled together with a contract pinned to 0.6.12.
        The harness follows the contract down rather than forcing it up.
        """
        return ">=0.8.0" if self.floor >= (0, 8, 0) else ">=0.6.0"

    @property
    def custom_errors_ok(self) -> bool:
        """Custom errors arrived in 0.8.4; below that the harness reverts with strings."""
        return self.floor >= (0, 8, 4)

    @property
    def source_root(self) -> Path:
        """The directory the project itself treats as its source root.

        Needed because reaching a contract only through a test is not always enough.
        Solidity's plain `import "X";` re-exports transitively, and real projects lean on
        it: defiprotocol's IBasket.sol uses `IFactory` without importing it, relying on
        the cycle IBasket -> IAuction -> IFactory to carry the symbol in. Measured, that
        resolves when the project's files are compilation roots and fails when only a
        test reaches them -- so when the cheap context fails, the harness reproduces the
        project's own compilation set instead of guessing at more remappings.
        """
        cur = self.target.parent
        while cur != self.repo_root and cur.parent != cur:
            if cur.name in ("src", "contracts", "sources"):
                return cur
            cur = cur.parent
        return self.target.parent


def plan_for(
    target: Path, repo_root: Path | None = None, dep_cache: Path | None = None
) -> RepoPlan:
    target = Path(target).resolve()
    root = Path(repo_root).resolve() if repo_root else _guess_root(target)
    ctx = RepoContext(root, dep_cache)
    res = ctx.resolve(target)
    source = target.read_text(encoding="utf-8", errors="ignore")
    remappings = res.as_lines()
    remappings.append(f"{TARGET_PREFIX}={target.parent.as_posix()}/")
    return RepoPlan(
        repo_root=root,
        target=target,
        target_import=f"{TARGET_PREFIX}{target.name}",
        remappings=remappings,
        unresolved=res.unresolved,
        external_used=sorted(res.external_used),
        band=pragma_band(source),
        floor=solc_floor(source),
    )


NOT_FOUND_RE = re.compile(r'Source "([^"]+)" not found')


def repair(plan: RepoPlan, build_output: str, dep_cache: Path | None = None) -> int:
    """Add remappings for whatever the compiler says it could not find.

    The closure walk is a static approximation: it reads import statements with a regex,
    so it misses specs behind unusual formatting and it cannot see a file that only
    becomes reachable once an earlier remapping is applied. The compiler has no such
    blind spot -- it names the exact source it wanted. Feeding those names back is
    strictly more reliable than trying to make the static pass perfect, so the plan is
    repaired from the build output and the build retried.

    Returns the number of remappings added, so the caller can stop when a round adds
    nothing rather than loop on a genuinely missing dependency.
    """
    missing = [m for m in NOT_FOUND_RE.findall(build_output)]
    if not missing:
        return 0
    ctx = RepoContext(plan.repo_root, dep_cache)
    existing = {line.split("=", 1)[0] for line in plan.remappings}
    added = 0

    for spec in dict.fromkeys(missing):
        if spec.startswith(".") or any(spec.startswith(p) for p in existing):
            continue
        res = Resolution()
        if ctx._resolve_bare(spec, plan.band, res) is not None:
            for prefix, dest in res.remappings.items():
                if prefix not in existing:
                    plan.remappings.append(f"{prefix}={dest}")
                    existing.add(prefix)
                    added += 1
            continue
        # Last resort: match on basename alone. Weaker than suffix matching and it can
        # pick the wrong file when a repository has two `IERC20.sol`, so it is used only
        # after the precise attempt has already failed -- and a wrong pick shows up as a
        # compile error on the next round, not as a silent bad verdict.
        base = spec.rsplit("/", 1)[-1]
        hits = ctx.index.ending_with(base) or _dep_hits(ctx, plan.band, base)
        if not hits:
            continue
        best = RepoContext._pick(hits, base, spec.rsplit("/", 1)[0] or base)
        prefix_dir = spec.rsplit("/", 1)[0]
        if not prefix_dir:
            continue
        mapped = f"{prefix_dir}/={best.parent.as_posix()}/"
        if mapped.split("=", 1)[0] not in existing:
            plan.remappings.append(mapped)
            existing.add(mapped.split("=", 1)[0])
            added += 1
    return added


def _dep_hits(ctx: RepoContext, band: str, tail: str) -> list[Path]:
    for pkg in ctx._dep_order(band):
        idx = ctx.dep_index(pkg)
        if idx is None:
            continue
        hits = idx.ending_with(tail)
        if hits:
            return hits
    return []


def _guess_root(target: Path) -> Path:
    """Walk up to the nearest directory that looks like a project root."""
    markers = ("foundry.toml", "hardhat.config.js", "hardhat.config.ts", "package.json",
               "remappings.txt", ".git")
    cur = target.parent
    best = cur
    for _ in range(8):
        if any((cur / m).exists() for m in markers):
            best = cur
        if cur.parent == cur:
            break
        cur = cur.parent
    return best
