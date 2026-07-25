"""Path handling in the indexer, and the Windows separator bug it had.

`_VENDOR` and `_NONPROD` anchor directory names on `/`. `index_repo` built its
relative path with `str(Path.relative_to(...))`, which on Windows yields
backslashes, so every pattern missed and `classify` returned `core` for
`node_modules`, `lib/openzeppelin` and `contracts/mocks` alike.

The bug did not crash anything. It silently changed the experiment: the routed
arm began scanning vendored libraries and mocks, which inflates its call count
(destroying the cost claim) and puts findings in non-production files (destroying
the structural comparison against broadcast). `plan._plan_broadcast` already used
`as_posix()`, so only the routed arm was affected -- the two halves of a paired
A/B were reading different file sets, on one operating system only.

`scope.txt` had the mirror image: entries are written with forward slashes, so a
backslash path never matched and a repository shipping a scope file indexed zero
files.

These tests use string inputs rather than a real tree so they exercise the
Windows behaviour on every platform.
"""

from __future__ import annotations

from pathlib import Path

import pytest

from bastet_cc.solidity import classify, index_repo, read_scope


# -- classify -------------------------------------------------------------------


@pytest.mark.parametrize("rel", [
    "lib/openzeppelin/ERC20.sol",
    "node_modules/@oz/token/ERC20.sol",
    "dependencies/solmate/src/ERC20.sol",
    "out/Vault.sol",
])
def test_vendor_paths_are_vendor_either_separator(rel):
    assert classify(rel) == "vendor"
    assert classify(rel.replace("/", "\\")) == "vendor"


@pytest.mark.parametrize("rel", [
    "contracts/mocks/MockERC20.sol",
    "test/Vault.t.sol",
    "script/Deploy.s.sol",
    "certora/specs/Vault.sol",
])
def test_nonprod_paths_are_nonprod_either_separator(rel):
    assert classify(rel) == "nonprod"
    assert classify(rel.replace("/", "\\")) == "nonprod"


@pytest.mark.parametrize("rel", [
    "contracts/Vault.sol",
    "src/core/Lending.sol",
    "Vault.sol",
])
def test_production_paths_stay_core_either_separator(rel):
    assert classify(rel) == "core"
    assert classify(rel.replace("/", "\\")) == "core"


def test_substring_matches_do_not_trigger():
    """`liberty/` is not `lib/`, and `Testable.sol` is not a test."""
    assert classify("contracts/liberty/Token.sol") == "core"
    assert classify("contracts/Testable.sol") == "core"
    assert classify("contracts/scripting/Runner.sol") == "core"


# -- the indexer, end to end ----------------------------------------------------


def _write(root: Path, rel: str, body: str) -> None:
    p = root / rel
    p.parent.mkdir(parents=True, exist_ok=True)
    p.write_text(body, encoding="utf-8")


PRAGMA = "pragma solidity ^0.8.0;\n"


def test_index_repo_skips_vendor_and_nonprod(tmp_path):
    _write(tmp_path, "contracts/Vault.sol",
           PRAGMA + "contract Vault { function f() public {} }")
    _write(tmp_path, "contracts/mocks/MockERC20.sol",
           PRAGMA + "contract MockERC20 { function t() public {} }")
    _write(tmp_path, "test/Vault.t.sol",
           PRAGMA + "contract VaultTest { function testF() public {} }")
    _write(tmp_path, "lib/openzeppelin/ERC20.sol",
           PRAGMA + "contract ERC20 { function transfer() public {} }")

    ix = index_repo(tmp_path)
    assert ix["n_files"] == 1
    assert [f["path"] for f in ix["files"]] == ["contracts/Vault.sol"]
    assert ix["skipped"]["nonprod"] == 2
    assert ix["skipped"]["vendor"] == 1


def test_indexed_paths_are_posix(tmp_path):
    """Downstream keys on these strings -- routing, findings, classify, scope."""
    _write(tmp_path, "contracts/core/Vault.sol",
           PRAGMA + "contract Vault { function f() public {} }")
    ix = index_repo(tmp_path)
    path = ix["files"][0]["path"]
    assert "\\" not in path
    assert path == "contracts/core/Vault.sol"


def test_scope_file_restricts_the_index(tmp_path):
    _write(tmp_path, "contracts/InScope.sol",
           PRAGMA + "contract A { function f() public {} }")
    _write(tmp_path, "contracts/OutOfScope.sol",
           PRAGMA + "contract B { function g() public {} }")
    (tmp_path / "scope.txt").write_text("contracts/InScope.sol\n", encoding="utf-8")

    ix = index_repo(tmp_path)
    assert [f["path"] for f in ix["files"]] == ["contracts/InScope.sol"]
    assert ix["skipped"]["out_of_scope"] == 1
    assert ix["scope_file"] is True


def test_scope_file_written_with_backslashes_still_matches(tmp_path):
    """A scope.txt authored on Windows must not silently exclude everything."""
    _write(tmp_path, "contracts/InScope.sol",
           PRAGMA + "contract A { function f() public {} }")
    (tmp_path / "scope.txt").write_text("contracts\\InScope.sol\n", encoding="utf-8")

    assert read_scope(tmp_path) == {"contracts/InScope.sol"}
    assert index_repo(tmp_path)["n_files"] == 1


def test_scope_file_takes_precedence_over_vendor_filtering(tmp_path):
    """If the audit says a lib/ file is in scope, it is in scope."""
    _write(tmp_path, "lib/Custom.sol",
           PRAGMA + "contract C { function f() public {} }")
    (tmp_path / "scope.txt").write_text("lib/Custom.sol\n", encoding="utf-8")
    assert index_repo(tmp_path)["n_files"] == 1


def test_scope_comments_and_blanks_ignored(tmp_path):
    _write(tmp_path, "contracts/A.sol", PRAGMA + "contract A { function f() public {} }")
    (tmp_path / "scope.txt").write_text(
        "# in scope\n\n./contracts/A.sol\n", encoding="utf-8")
    assert read_scope(tmp_path) == {"contracts/A.sol"}
    assert index_repo(tmp_path)["n_files"] == 1


def test_missing_repository_raises_instead_of_indexing_nothing(tmp_path):
    """A typo'd repo hash must not look like "the model found nothing".

    rglob over a nonexistent path yields nothing, so index_repo used to return a
    valid index of zero files. Routing then plans zero tasks, the scan makes zero
    calls, evaluate reports zero findings, and every step exits 0.
    """
    with pytest.raises(NotADirectoryError) as exc:
        index_repo(tmp_path / "no-such-repo")
    assert "not a directory" in str(exc.value)


def test_repository_with_no_solidity_is_empty_but_not_an_error(tmp_path):
    """An existing directory that simply has no .sol is a legitimate empty index."""
    (tmp_path / "README.md").write_text("no contracts here", encoding="utf-8")
    ix = index_repo(tmp_path)
    assert ix["n_files"] == 0
    assert ix["n_functions"] == 0


def test_empty_scope_file_falls_back_to_path_filtering(tmp_path):
    """An empty scope.txt must not mean "scan nothing"."""
    _write(tmp_path, "contracts/A.sol", PRAGMA + "contract A { function f() public {} }")
    _write(tmp_path, "test/A.t.sol", PRAGMA + "contract T { function testA() public {} }")
    (tmp_path / "scope.txt").write_text("\n#only a comment\n", encoding="utf-8")

    ix = index_repo(tmp_path)
    assert read_scope(tmp_path) is None
    assert ix["scope_file"] is False
    assert ix["n_files"] == 1
    assert ix["skipped"]["nonprod"] == 1
