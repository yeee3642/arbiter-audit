"""Function-level Solidity indexing, without a compiler.

Audit-contest codebases rarely compile off the shelf -- dependencies are pinned to
paths that don't exist, pragmas span half a dozen incompatible versions, and the
interesting files are buried under vendored libraries. Anything that shells out to
`solc` gives up on most of the corpus, so this leans on tree-sitter, which parses
broken and version-mixed sources just fine and still yields real syntax nodes.

The index it produces is what routing keys on: a detector that only ever talks
about swaps has no reason to read a file with no swap in it.
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field, asdict
from pathlib import Path

import tree_sitter_solidity
from tree_sitter import Language, Parser


def _load_language() -> Language:
    """Bind the Solidity grammar across the tree-sitter ABI transition.

    tree-sitter-solidity 1.2.x returns a raw pointer as a Python int. tree-sitter
    0.25 accepts that but warns; 0.26 removed int support and raises
    OverflowError; 0.24 and older reject the grammar's ABI 15 outright. So the
    working range is exactly 0.25.x, which is what pyproject pins -- but the pin
    is a floor, not a guarantee, and the failure a reader hits otherwise is an
    OverflowError from a C binding with no hint about what to do.

    Newer grammar builds are expected to hand back a PyCapsule instead, which
    every version accepts. Try the value as-is, and if that fails say which pair
    of versions is installed and what to install instead.
    """
    raw = tree_sitter_solidity.language()
    try:
        return Language(raw)
    except (OverflowError, TypeError, ValueError) as exc:
        import importlib.metadata as md

        def version(pkg: str) -> str:
            try:
                return md.version(pkg)
            except md.PackageNotFoundError:      # pragma: no cover - env dependent
                return "not installed"

        raise RuntimeError(
            f"cannot bind the Solidity grammar: {type(exc).__name__}: {exc}\n"
            f"  tree-sitter          {version('tree-sitter')}\n"
            f"  tree-sitter-solidity {version('tree-sitter-solidity')}\n"
            "  This pair is incompatible. tree-sitter-solidity 1.2.x needs\n"
            "  tree-sitter >=0.25,<0.26 (0.26 dropped int grammar pointers, 0.24\n"
            "  and older reject its ABI). Fix with:\n"
            "      pip install 'tree-sitter>=0.25,<0.26'"
        ) from exc


_LANGUAGE = _load_language()

# Vendored dependencies and test scaffolding: real code, but nothing an auditor
# is being paid to look at. Upstream Bastet globs `**/*.sol` and scans all of it.
_VENDOR = re.compile(
    r"(^|/)(node_modules|lib|libs|dependencies|out|artifacts|cache|\.git|"
    r"forge-std|openzeppelin[\w-]*|solmate|solady|ds-test)(/|$)",
    re.I,
)
_NONPROD = re.compile(
    r"(^|/)(test|tests|mock|mocks|script|scripts|echidna|certora|fuzz)(/|$)"
    r"|\.t\.sol$|\.s\.sol$",
    re.I,
)


@dataclass
class Function:
    name: str
    kind: str                       # function | modifier | constructor | fallback | receive
    contract: str
    visibility: str
    modifiers: list[str]
    params: str
    start_line: int
    end_line: int
    source: str
    identifiers: set[str] = field(default_factory=set)

    def to_dict(self) -> dict:
        d = asdict(self)
        d["identifiers"] = sorted(self.identifiers)
        return d


@dataclass
class SolFile:
    path: str                       # repo-relative
    contracts: list[str]
    imports: list[str]
    functions: list[Function]
    n_bytes: int
    parse_errors: int

    def to_dict(self) -> dict:
        return {
            "path": self.path,
            "contracts": self.contracts,
            "imports": self.imports,
            "n_bytes": self.n_bytes,
            "parse_errors": self.parse_errors,
            "functions": [f.to_dict() for f in self.functions],
        }


def classify(rel_path: str) -> str:
    """vendor | nonprod | core -- what kind of file this is, by path alone.

    Both patterns anchor directory names on `/`, so a Windows-style path arrives
    as one long segment and matches nothing: `contracts\\mocks\\MockERC20.sol`
    classified as `core`. That failure is silent and it corrupts the experiment
    rather than crashing it -- the routed arm starts scanning vendored libraries
    and mocks, its cost advantage evaporates, and the "findings in
    non-production code" comparison reports zero for the wrong reason.
    Normalising here rather than at each call site means no caller can reintroduce
    it.
    """
    p = rel_path.replace("\\", "/")
    if _VENDOR.search(p):
        return "vendor"
    if _NONPROD.search(p):
        return "nonprod"
    return "core"


def _text(node, src: bytes) -> str:
    return src[node.start_byte:node.end_byte].decode("utf8", errors="replace")


def _collect_identifiers(node, src: bytes, out: set[str]) -> None:
    """Every identifier and member-access name reachable under `node`.

    Routing compares these against a detector's declared interests, so member
    accesses matter as much as bare calls: `block.timestamp` and `msg.sender`
    are the whole signal for several detectors.
    """
    if node.type in ("identifier", "type_identifier"):
        out.add(_text(node, src))
    elif node.type == "member_expression":
        prop = node.child_by_field_name("property")
        obj = node.child_by_field_name("object")
        if prop is not None and obj is not None:
            out.add(f"{_text(obj, src)}.{_text(prop, src)}")
        if prop is not None:
            out.add(_text(prop, src))
    for child in node.children:
        _collect_identifiers(child, src, out)


def _count_errors(node) -> int:
    n = 1 if node.type == "ERROR" or node.is_missing else 0
    for child in node.children:
        n += _count_errors(child)
    return n


_DEF_TYPES = {
    "function_definition": "function",
    "modifier_definition": "modifier",
    "constructor_definition": "constructor",
    "fallback_receive_definition": "fallback",
}
_VISIBILITIES = {"public", "private", "internal", "external"}


def parse_file(path: Path, repo_root: Path) -> SolFile:
    src = path.read_bytes()
    parser = Parser(_LANGUAGE)
    tree = parser.parse(src)
    root = tree.root_node

    rel = path.relative_to(repo_root).as_posix()
    contracts: list[str] = []
    imports: list[str] = []
    functions: list[Function] = []

    def walk(node, current_contract: str) -> None:
        ctype = node.type

        if ctype == "import_directive":
            imports.append(_text(node, src))

        elif ctype in ("contract_declaration", "interface_declaration", "library_declaration"):
            name_node = node.child_by_field_name("name")
            name = _text(name_node, src) if name_node else "<anonymous>"
            contracts.append(name)
            for child in node.children:
                walk(child, name)
            return

        elif ctype in _DEF_TYPES:
            name_node = node.child_by_field_name("name")
            kind = _DEF_TYPES[ctype]
            name = _text(name_node, src) if name_node else kind

            visibility, modifiers = "", []
            for child in node.children:
                if child.type == "visibility":
                    visibility = _text(child, src)
                elif child.type == "modifier_invocation":
                    modifiers.append(_text(child, src))
                elif child.type == "state_mutability":
                    modifiers.append(_text(child, src))
                elif child.type not in ("function_body", "block_statement"):
                    txt = _text(child, src).strip()
                    if txt in _VISIBILITIES and not visibility:
                        visibility = txt

            params_node = node.child_by_field_name("parameters")
            params = _text(params_node, src) if params_node else "()"

            idents: set[str] = set()
            _collect_identifiers(node, src, idents)

            functions.append(Function(
                name=name,
                kind=kind,
                contract=current_contract,
                visibility=visibility or "default",
                modifiers=modifiers,
                params=params,
                start_line=node.start_point[0] + 1,
                end_line=node.end_point[0] + 1,
                source=_text(node, src),
                identifiers=idents,
            ))
            return

        for child in node.children:
            walk(child, current_contract)

    walk(root, "<file>")

    return SolFile(
        path=rel,
        contracts=contracts,
        imports=imports,
        functions=functions,
        n_bytes=len(src),
        parse_errors=_count_errors(root),
    )


def read_scope(repo_root: Path) -> set[str] | None:
    """Code4rena ships `scope.txt` naming the files actually under audit.

    When present it is the ground truth for what to scan, and it is dramatically
    narrower than the file tree -- one test repo lists 4 in-scope files out of 752.
    """
    scope_file = repo_root / "scope.txt"
    if not scope_file.exists():
        return None
    out: set[str] = set()
    for line in scope_file.read_text(errors="ignore").splitlines():
        line = line.strip()
        if not line or line.startswith("#"):
            continue
        out.add(line.replace("\\", "/").lstrip("./"))
    return out or None


def index_repo(repo_root: Path, use_scope: bool = True) -> dict:
    """Index one repository, keeping only files worth auditing.

    A missing directory raises. `rglob` on a path that does not exist yields
    nothing, so without this the function returns a perfectly well-formed index
    of zero files -- and then routing plans zero tasks, the scan makes zero
    calls, and `evaluate` reports zero findings, all with exit status 0. A typo
    in a repository hash would look exactly like a model that found nothing.
    """
    repo_root = Path(repo_root)
    if not repo_root.is_dir():
        raise NotADirectoryError(
            f"cannot index {repo_root}: not a directory. Extract the corpus under "
            f"data/ex/ (see README, 'Install') or pass a path that exists.")
    scope = read_scope(repo_root) if use_scope else None

    files: list[SolFile] = []
    skipped = {"vendor": 0, "nonprod": 0, "out_of_scope": 0}

    for path in sorted(repo_root.rglob("*.sol")):
        rel = path.relative_to(repo_root).as_posix()

        if scope is not None:
            if rel not in scope:
                skipped["out_of_scope"] += 1
                continue
        else:
            kind = classify(rel)
            if kind != "core":
                skipped[kind] += 1
                continue

        try:
            files.append(parse_file(path, repo_root))
        except Exception:
            # A file we cannot parse is a file we cannot route; count it as
            # vendor-grade noise rather than failing the whole repository.
            skipped["vendor"] += 1

    return {
        "repo": repo_root.name,
        "scope_file": scope is not None,
        "n_files": len(files),
        "n_functions": sum(len(f.functions) for f in files),
        "n_bytes": sum(f.n_bytes for f in files),
        "skipped": skipped,
        "files": [f.to_dict() for f in files],
    }
