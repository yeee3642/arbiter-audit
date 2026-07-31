"""A disposable Foundry project per sample, so that a claim can be executed.

This is the part of ARBITER that Bastet has no counterpart for. Bastet's 56 detector
nodes are chat-completion calls; not one of them can run anything, so nothing it emits
is ever tested against an EVM. Here every sample gets a real forge project, and the
auditor is handed a compiler and a test runner as tools.

The design constraint that matters: audit repositories usually do not build. Missing
dependencies, pinned compilers and broken remappings defeat any approach that needs
`forge build` to succeed on the repository as shipped. ARBITER sidesteps that by never
building the repository -- it builds a *minimal self-contained workspace* around the
single unit under test. For the current evaluation set that is exact rather than
approximate, because all 14 samples are zero-import, self-contained contracts.
Where a sample does carry imports, they are vendored into the workspace and the
degradation is recorded rather than hidden: `Workspace.build_ok` is part of the run
record, and a sample whose harness never compiled is reported as unproven, not as safe.
"""

from __future__ import annotations

import re
import secrets
import shutil
import subprocess
from dataclasses import dataclass
from pathlib import Path
from typing import TYPE_CHECKING

if TYPE_CHECKING:  # pragma: no cover
    from .repo import RepoPlan

# Chosen because it satisfies every pragma in the evaluation set that is not an exact
# pin, and because forge fetches per-file compilers for the ones that are.
FALLBACK_SOLC = "0.8.24"

FOUNDRY_TOML = """[profile.default]
src = "{src}"
test = "test"
out = "out"
libs = []
{solc}
optimizer = false
via_ir = {via_ir}
# Deterministic: no fork, no network access during tests.
ffi = false
fs_permissions = []
"""


# The test contract invokes the attack directly, so tx.origin stays the deploying
# account. Pranking an attacker EOA here was tried and reverted: it broke the tx.origin
# sample it was meant to help. A contract that authorises on tx.origin is attacked by
# phishing -- the *victim* originates the transaction into the attacker's contract -- so
# forcing the origin to be the attacker makes that class unexploitable rather than
# exploitable. Agents that need to act as a plain account use mode='eoa'.
_CONTRACT_ATTACK = "        atk.attack();"

# The pranked block an EOA-mode attack runs inside; its body is the attack.
_EOA_PRANK_RE = re.compile(
    r"vm\.startPrank\(eoa, eoa\);(.*?)vm\.stopPrank\(\);", re.DOTALL
)


class BuildUnavailable(RuntimeError):
    """forge is not installed or not on PATH."""


@dataclass
class CommandResult:
    ok: bool
    stdout: str
    stderr: str
    exit_code: int

    @property
    def combined(self) -> str:
        return (self.stdout + "\n" + self.stderr).strip()


class Workspace:
    """One forge project holding one contract under test plus agent-written PoCs.

    Two modes, and which one is in force is recorded on the run rather than assumed:

      * **hermetic** -- the source is written to `src/Target.sol` and nothing else
        exists. Correct for self-contained contracts, and it guarantees a dependency
        download failure can never be mistaken for a safe verdict.
      * **in-repo** -- a `RepoPlan` supplies remappings that reach the contract where it
        actually lives, together with its import closure. Nothing is copied; forge
        resolves the graph and inlines the sources, so the workspace stays a few hundred
        bytes and hundreds run concurrently.

    The second mode exists because the first compiled 0 of 24 contracts drawn from
    OneSavie's own dataset. A harness that cannot compile the code under audit cannot
    produce evidence, and a tool that produces no evidence answers "safe" to everything,
    which is a degenerate predictor pointed the other way from a 53-detector OR.
    """

    def __init__(
        self,
        root: Path,
        sample_id: str,
        source: str,
        plan: "RepoPlan | None" = None,
    ) -> None:
        self.root = root / re.sub(r"[^A-Za-z0-9_.-]", "_", sample_id)
        self.sample_id = sample_id
        self.source = source
        self.plan = plan
        self.build_ok: bool | None = None
        self.pocs: dict[str, str] = {}
        # Names the last composition had to rename off the target's. Recorded rather than
        # silent: a rename is a rewrite of the agent's text, and a rewrite nobody can see
        # is the same class of thing as a harness that fails at a line the agent did not
        # write. Empty is the normal case.
        self.renamed: list[str] = []
        self._via_ir = False
        self._toml_args: tuple[str, str] = ("src", "")
        # Where a PoC reaches the contract under audit, and what syntax the harness may
        # use to talk about it. Both follow the contract rather than forcing it upward:
        # a target pinned to 0.6.12 cannot be compiled alongside a >=0.8.0 test, and
        # custom errors did not exist before 0.8.4.
        self.target_import = "../src/Target.sol" if plan is None else plan.target_import
        self.pragma = ">=0.8.0" if plan is None else plan.test_pragma
        self.custom_errors = True if plan is None else plan.custom_errors_ok
        self._scaffold()

    # -- setup ---------------------------------------------------------------

    def _scaffold(self) -> None:
        if self.root.exists():
            shutil.rmtree(self.root)
        (self.root / "src").mkdir(parents=True)
        (self.root / "test").mkdir(parents=True)
        self._write_toml(
            "src" if self.plan is None else self.plan.chosen_src,
            "" if self.plan is None else (
                self.plan.solc_version if self.plan.chosen_solc is None
                else self.plan.chosen_solc
            ),
        )
        if self.plan is None:
            (self.root / "src" / "Target.sol").write_text(self.source, encoding="utf-8")
        else:
            # src stays empty on purpose: forge compiles what the test reaches, so only
            # the target's import closure is built. A repository whose unrelated half
            # does not compile still yields evidence for the contract under audit.
            (self.root / "remappings.txt").write_text(
                "\n".join(self.plan.remappings) + "\n", encoding="utf-8"
            )
        # Cheatcodes are available in both modes with no dependency at all: they live at
        # a fixed address on the Foundry EVM, so a hand-written interface reaches them.
        (self.root / "test" / "Vm.sol").write_text(
            VM_SOL.replace("__PRAGMA__", self.pragma), encoding="utf-8"
        )

    # -- source access -------------------------------------------------------

    @property
    def lines(self) -> list[str]:
        return self.source.splitlines()

    def read(self, start: int = 1, end: int | None = None) -> str:
        lines = self.lines
        end = len(lines) if end is None else min(end, len(lines))
        start = max(1, start)
        if start > len(lines):
            return f"(file has only {len(lines)} lines)"
        width = len(str(end))
        return "\n".join(
            f"{i:>{width}}| {lines[i - 1]}" for i in range(start, end + 1)
        )

    def grep(self, pattern: str, max_hits: int = 40) -> str:
        try:
            rx = re.compile(pattern)
        except re.error as exc:
            return f"invalid regex: {exc}"
        hits = [
            f"{i}| {line}" for i, line in enumerate(self.lines, 1) if rx.search(line)
        ]
        if not hits:
            return f"no match for {pattern!r}"
        out = hits[:max_hits]
        if len(hits) > max_hits:
            out.append(f"... {len(hits) - max_hits} more matches suppressed")
        return "\n".join(out)

    # -- the rest of the repository ------------------------------------------
    #
    # An exploit against a real protocol is rarely written against one file. The vault
    # under audit is deployed by a factory, holds a token declared elsewhere, and takes a
    # constructor argument whose type lives in an interface directory. Without these the
    # agent can read the bug and still not be able to stand the contract up, which shows
    # up as a compile failure it has no way to fix -- indistinguishable, in the run
    # record, from a contract that is actually safe.

    @property
    def in_repo(self) -> bool:
        return self.plan is not None

    def repo_files(self, pattern: str = "") -> str:
        if self.plan is None:
            return "this contract was audited standalone; there is no repository to list"
        from .repo import SKIP_DIRS

        root = self.plan.repo_root
        try:
            rx = re.compile(pattern) if pattern else None
        except re.error as exc:
            return f"invalid regex: {exc}"
        out: list[str] = []
        for dirpath, dirnames, filenames in __import__("os").walk(root):
            dirnames[:] = [d for d in dirnames if d not in SKIP_DIRS]
            for name in sorted(filenames):
                if not name.endswith(".sol"):
                    continue
                rel = (Path(dirpath) / name).relative_to(root).as_posix()
                if rx is None or rx.search(rel):
                    out.append(rel)
        if not out:
            return f"no .sol file matches {pattern!r}"
        head = out[:200]
        text = "\n".join(head)
        if len(out) > len(head):
            text += f"\n... {len(out) - len(head)} more suppressed; narrow the pattern"
        return text

    def read_repo(self, rel: str, start: int = 1, end: int | None = None) -> str:
        path = self._repo_path(rel)
        if isinstance(path, str):
            return path
        lines = path.read_text(encoding="utf-8", errors="ignore").splitlines()
        end = len(lines) if end is None else min(end, len(lines))
        start = max(1, start)
        if start > len(lines):
            return f"({rel} has only {len(lines)} lines)"
        width = len(str(end))
        return "\n".join(f"{i:>{width}}| {lines[i - 1]}" for i in range(start, end + 1))

    def grep_repo(self, pattern: str, max_hits: int = 60) -> str:
        if self.plan is None:
            return "this contract was audited standalone; there is no repository to search"
        from .repo import SKIP_DIRS

        try:
            rx = re.compile(pattern)
        except re.error as exc:
            return f"invalid regex: {exc}"
        root = self.plan.repo_root
        hits: list[str] = []
        for dirpath, dirnames, filenames in __import__("os").walk(root):
            dirnames[:] = [d for d in dirnames if d not in SKIP_DIRS]
            for name in sorted(filenames):
                if not name.endswith(".sol"):
                    continue
                path = Path(dirpath) / name
                rel = path.relative_to(root).as_posix()
                try:
                    text = path.read_text(encoding="utf-8", errors="ignore")
                except OSError:
                    continue
                for i, line in enumerate(text.splitlines(), 1):
                    if rx.search(line):
                        hits.append(f"{rel}:{i}| {line.strip()[:160]}")
                        if len(hits) >= max_hits:
                            return "\n".join(hits) + "\n... truncated; narrow the pattern"
        return "\n".join(hits) if hits else f"no match for {pattern!r} in the repository"

    def _repo_path(self, rel: str) -> "Path | str":
        if self.plan is None:
            return "this contract was audited standalone; there is no repository"
        root = self.plan.repo_root
        candidate = (root / rel.lstrip("/")).resolve()
        try:
            candidate.relative_to(root)
        except ValueError:
            return f"{rel!r} is outside the repository"
        if not candidate.is_file():
            return f"{rel!r} does not exist; use list_repo_files to see what does"
        return candidate

    def contains_verbatim(self, fragment: str) -> bool:
        """Whitespace-insensitive verbatim containment check.

        Free, deterministic, and it removes a whole class of hallucination before any
        model is asked to adjudicate: an expression that is not in the file cannot be
        the expression that makes the file exploitable.
        """
        if not fragment or not fragment.strip():
            return False
        squash = lambda s: re.sub(r"\s+", " ", s).strip()  # noqa: E731
        return squash(fragment) in squash(self.source)

    # -- toolchain -----------------------------------------------------------

    def compose_exploit(
        self,
        *,
        deploy_code: str,
        attacker_code: str = "",
        predicate: str,
        observed_getter: str = "",
        token_expr: str = "",
        liveness_call: str = "",
        attack_body: str = "",
        honest_body: str = "",
        mode: str = "contract",
        require_honest: bool = True,
        funding_wei: int = 10**19,
        extra_imports: list[str] | None = None,
    ) -> str:
        """Build the exploit test file. The agent never writes the success check.

        This is the load-bearing detail of ARBITER. An earlier revision let the agent
        write the whole test and accepted "the test passed" as proof, and the agent
        promptly defeated it: on a *patched* sample it under-funded the vault, proved
        that `withdraw()` reverts, asserted that the revert happened, and submitted a
        passing test as evidence of a vulnerability. A reverting withdraw is the
        contract working. The test was true and the finding was false.

        The lesson is that "a test passed" is not a proof of anything unless someone
        other than the claimant chose what the test asserts. So the agent now supplies
        only the deployment, the attacker contract, and which predicate to use; the
        success condition is written here, is identical for every sample, and measures
        an outcome the agent cannot restate: did the attacker end up richer, or did
        privileged state move when a non-privileged account acted.
        """
        if mode not in ("contract", "eoa"):
            raise ValueError(f"unknown mode {mode!r}")
        _eoa = draw_identity()
        deploy_code = strip_preamble(deploy_code)
        attacker_code = strip_preamble(attacker_code)
        attack_body = strip_preamble(attack_body)
        honest_body = strip_preamble(honest_body)
        _frags, self.renamed = deconflict(self.source, {
            "deploy_code": deploy_code,
            "attacker_code": attacker_code,
            "attack_body": attack_body,
            "honest_body": honest_body,
        })
        deploy_code = _frags["deploy_code"]
        attacker_code = _frags["attacker_code"]
        attack_body = _frags["attack_body"]
        honest_body = _frags["honest_body"]
        _reject_halting(deploy_code, "deploy_code")
        _reject_halting(attack_body, "attack_body")
        _reject_halting(honest_body, "honest_body")
        _reject_forgery(attack_body, "attack_body")
        _reject_forgery(attacker_code, "attacker_code")
        if not honest_body.strip():
            if require_honest:
                raise ValueError(
                    "profit predicates need honest_body: the statements an ordinary, "
                    "non-attacking user would run. The exploit must beat that baseline."
                )
            # Benchmark admission is the one place this is relaxed. There the
            # discriminator is the PAIR -- the same exploit must pass on the vulnerable
            # half and fail on the patched one -- which is a stronger test than beating
            # an honest baseline, and it is available because admission can see both
            # halves. An auditing agent cannot: it sees one contract and has no patched
            # twin to compare against, which is exactly why it owes a baseline instead.
            # An empty BLOCK, not a bare semicolon: Solidity has no empty statement,
            # and ";" made 17 of 20 reference exploits fail to compile.
            honest_body = "{}"

        # How the attacker's holdings are read. Same expression before and after, so the
        # predicate is a strict increase in whatever the attacker actually walks away
        # with -- ether, or a token balance.
        if predicate == "eth_profit":
            measure = "{who}.balance"
            drained = "address(target).balance"
        elif predicate == "token_profit":
            if not token_expr.strip():
                raise ValueError("token_profit predicate needs token_expr")
            measure = f"_ArbiterToken({token_expr.strip()}).balanceOf({{who}})"
            drained = f"_ArbiterToken({token_expr.strip()}).balanceOf(address(target))"
        elif predicate == "state_change":
            if not observed_getter.strip():
                raise ValueError("state_change predicate needs observed_getter")
            measure = ""
        elif predicate == "liveness_broken":
            if not liveness_call.strip():
                raise ValueError("liveness_broken predicate needs liveness_call")
            measure = ""
        else:
            raise ValueError(f"unknown predicate {predicate!r}")

        if predicate == "liveness_broken":
            action = (
                _CONTRACT_ATTACK
                if mode == "contract"
                else _EOA_ACTION.format(attack_body=_indent(attack_body, 8))
            )
            check = _LIVENESS_BODY.replace("__CALL__", liveness_call.strip()).replace(
                "__ACTION__", action
            )
        elif predicate == "state_change":
            action = (
                _CONTRACT_ATTACK
                if mode == "contract"
                else _EOA_ACTION.format(attack_body=_indent(attack_body, 8))
            )
            check = (
                _STATE_CHANGE_BODY.replace("__GETTER__", observed_getter.strip())
                .replace("__ACTION__", action)
                .replace("__HONEST__", _indent(honest_body, 8))
            )
        else:
            # Profit alone does not mean a vulnerability. The reentrancy pair proves it:
            # UtopiaVault pays every caller a 1 ether airdrop by design, so
            # claim()+withdraw() leaves an EOA richer on the PATCHED contract too. An
            # earlier revision accepted exactly that and reported S1, a patched sample,
            # as "proven".
            #
            # So the bar is no longer "did the attacker profit" but "did the attacker do
            # better than an honest user of the same contract". The harness runs the
            # honest path first, as a separate account under identical funding, and
            # requires the attack to strictly beat it. On S1 both paths yield 1 ether and
            # the exploit is refused; on V1 the honest path yields 1 and the reentrant
            # one yields several, so it passes.
            attacker_expr = "address(atk)" if mode == "contract" else "eoa"
            attack_action = (
                _CONTRACT_ATTACK
                if mode == "contract"
                else _EOA_ACTION.format(attack_body=_indent(attack_body, 8))
            )
            check = _PROFIT_BODY.format(
                honest_body=_indent(honest_body, 8),
                measure_ctrl=measure.format(who="ctrl"),
                measure_atk=measure.format(who=attacker_expr),
                measure_drained=drained,
                setup=_ATTACKER_SETUP.format(funding_wei=int(funding_wei))
                if mode == "contract"
                else "",
                attack_action=attack_action,
                fail_report=_FAIL_CUSTOM_ERROR if self.custom_errors else _FAIL_REQUIRE,
                drain_report=(
                    _NOT_DRAINED_CUSTOM_ERROR if self.custom_errors
                    else _NOT_DRAINED_REQUIRE
                ),
            )

        if mode == "contract":
            if "contract Attacker" not in attacker_code:
                raise ValueError("contract mode needs an Attacker contract")
            setup = (
                ""
                if predicate not in ("state_change", "liveness_broken")
                else _ATTACKER_SETUP.format(funding_wei=int(funding_wei))
            )
        else:
            # attacker_code is still emitted in EOA mode. It is no longer required to
            # contain an `Attacker`, but a realistic scenario usually needs helper
            # contracts declared -- a mock ERC20 to be the stolen asset, for instance --
            # and there is nowhere else to put them.
            setup = _EOA_SETUP.format(funding_wei=int(funding_wei), eoa_addr=_eoa)

        # Named imports do not re-export, so a token or interface the target imported
        # that way is not in scope here. The agent asks for what it needs by the same
        # path the repository's own files use, which resolves through the same
        # remappings; `arbiter-repo/<path from the repo root>` reaches anything else.
        extras = "\n".join(
            f'import "{spec.strip()}";'
            for spec in (extra_imports or [])
            if spec and spec.strip()
        )

        return _EXPLOIT_TEMPLATE.format(
            pragma=self.pragma,
            target_import=self.target_import,
            extra_imports=("\n" + extras if extras else ""),
            error_decl=(_ERROR_DECLS if self.custom_errors else ""),
            attacker_code=attacker_code.strip(),
            deploy_code=deploy_code.strip(),
            setup=setup,
            check=check,
        )

    def compose_victim_loss(
        self,
        *,
        deploy_code: str,
        victim_enter: str,
        victim_exit: str,
        attacker_code: str = "",
        attack_body: str = "",
        mode: str = "contract",
        token_expr: str = "",
        extra_imports: list[str] | None = None,
        funding_wei: int = 10**19,
    ) -> str:
        """A predicate the agent cannot satisfy by choosing a weak baseline.

        Auditing this project's own 68 claimed proofs found 25 of them on the PATCHED
        half of an authored pair. The gate had not been bypassed; it had been satisfied
        without a vulnerability being present. The reason is structural and none of the
        gates added since touches it: `honest_body` is written by the same agent that
        writes the attack, so a weak baseline beside a strong attack clears the
        differential on any contract at all. The recurring shape was ether donated into
        the target during setup and then extracted -- real profit, real drain, no defect.

        What that comparison is missing is the thing that actually defines a
        vulnerability: SOMEONE ELSE LOSES. So the harness stops asking whether the
        attacker did better than a baseline, and asks whether a third party was harmed:

          Trial A   setup -> victim enters -> (no attack) -> victim exits
          Trial B   setup -> victim enters ->    attack    -> victim exits

        Same setup, same victim code, same account, one difference. The exploit is
        admitted only if the victim recovers strictly LESS in B than in A, and the
        attacker ends up ahead. The agent still writes the victim's two fragments,
        because only it knows the ABI -- but it cannot fake harm, since trial A is its own
        code with the attack removed. Extracting a donation leaves every depositor whole
        and is refused; draining a vault does not, and is not.

        Both trials run inside one test on a state snapshot, so setup happens once and
        the two worlds are identical up to the attack.
        """
        _eoa = draw_identity()
        _victim = draw_identity()
        deploy_code = strip_preamble(deploy_code)
        attacker_code = strip_preamble(attacker_code)
        attack_body = strip_preamble(attack_body)
        victim_enter = strip_preamble(victim_enter)
        victim_exit = strip_preamble(victim_exit)
        # The target is imported unnamed, so its top-level symbols are already in scope.
        # In repo mode this sees the contract under audit and not its import closure, so a
        # collision with a dependency's IERC20 still gets through -- partial, and better
        # than the eighty-two failures it removes outright.
        _frags, self.renamed = deconflict(self.source, {
            "deploy_code": deploy_code,
            "attacker_code": attacker_code,
            "attack_body": attack_body,
            "victim_enter": victim_enter,
            "victim_exit": victim_exit,
        })
        deploy_code = _frags["deploy_code"]
        attacker_code = _frags["attacker_code"]
        attack_body = _frags["attack_body"]
        victim_enter = _frags["victim_enter"]
        victim_exit = _frags["victim_exit"]
        if not victim_enter.strip() or not victim_exit.strip():
            raise ValueError(
                "victim_loss needs victim_enter and victim_exit: what an ordinary user "
                "does to take a position in this contract, and what they do to get it "
                "back. The harness runs both twice -- once with your attack in between "
                "and once without -- and admits the finding only if your attack is what "
                "stopped them getting their money out."
            )
        if mode == "contract" and "contract Attacker" not in attacker_code:
            raise ValueError("contract mode needs an Attacker contract")
        _reject_halting(deploy_code, "deploy_code")
        _reject_halting(attack_body, "attack_body")
        _reject_halting(victim_enter, "victim_enter")
        _reject_halting(victim_exit, "victim_exit")
        _reject_forgery(attack_body, "attack_body")
        _reject_forgery(attacker_code, "attacker_code")
        _reject_standing(deploy_code, "deploy_code")
        # The victim is an ordinary user, so their fragments may not forge anything
        # either -- a "victim" who pranks the owner is not a victim.
        _reject_forgery(victim_enter, "victim_enter")
        _reject_forgery(victim_exit, "victim_exit")

        if token_expr.strip():
            measure_victim = f"_ArbiterToken({token_expr.strip()}).balanceOf(arbVictim)"
            _tok = f"_ArbiterToken({token_expr.strip()})"
            measure_atk = (
                f"{_tok}.balanceOf(address(atk)) + {_tok}.balanceOf(arbAtkEoa)"
                if mode == "contract" else f"{_tok}.balanceOf(arbEoa)"
            )
        else:
            measure_victim = "arbVictim.balance"
            measure_atk = (
                "address(atk).balance + arbAtkEoa.balance"
                if mode == "contract" else "arbEoa.balance"
            )

        # Victim-mode variants: they assign the contract-level `atk` and prank the
        # contract-level `arbEoa`, because deployment and attack are now separate
        # functions and a local would not survive between them.
        setup = (
            _VICTIM_ATTACKER_SETUP.format(funding_wei=int(funding_wei))
            if mode == "contract"
            else _VICTIM_EOA_SETUP.format(funding_wei=int(funding_wei))
        )
        action = (
            _CONTRACT_ATTACK
            if mode == "contract"
            else _VICTIM_EOA_ACTION.format(attack_body=_indent(attack_body, 8))
        )
        extras = "\n".join(
            f'import "{spec.strip()}";'
            for spec in (extra_imports or []) if spec and spec.strip()
        )
        _state_decls, _hoisted = hoist_declarations(deploy_code)
        _hoisted = _indent(_hoisted, 8)
        # The victim's handle on their own position has to outlive arbEnter.
        _victim_decls, victim_enter, victim_exit = hoist_victim_locals(
            victim_enter, victim_exit)
        if _victim_decls:
            _state_decls = _state_decls + "\n" + _victim_decls
        env = VICTIM_ENVIRONMENTS
        return _VICTIM_TEMPLATE.format(
            n_env=len(env),
            endows=", ".join(
                (f"uint256({e[0]})" if i == 0 else str(e[0]))
                for i, e in enumerate(env)
            ),
            warps=", ".join(
                (f"uint256({e[1]})" if i == 0 else str(e[1]))
                for i, e in enumerate(env)
            ),
            rounds=", ".join(
                (f"uint256({e[2]})" if i == 0 else str(e[2]))
                for i, e in enumerate(env)
            ),
            victim_addr=_victim,
            eoa_addr=_eoa,
            pragma=self.pragma,
            target_import=self.target_import,
            extra_imports=("\n" + extras if extras else ""),
            error_decl=(_VICTIM_ERROR if self.custom_errors else ""),
            attacker_code=attacker_code.strip(),
            state_decls=_state_decls,
            # Only in contract mode, and it is worth saying why this line existed at
            # all. It was emitted unconditionally while `compose_victim_loss` only
            # requires an Attacker contract when mode == "contract" -- so every EOA-mode
            # composition named a type nothing declared and died at solc with
            # "Identifier not found or not unique". victim_loss is the only strict
            # predicate, which made the whole EOA quadrant unreachable: the one route to
            # a contract guarded by require(msg.sender == tx.origin), and the shape an
            # agent reaches for first when the attack needs no contract at all.
            #
            # It is dead weight in contract mode too -- _ATTACKER_SETUP declares a local
            # `Attacker atk` inside arbAttack() that shadows it -- but removing it there
            # as well is a separate change with its own probe.
            attacker_decl=("    Attacker internal atk;" if mode == "contract" else ""),
            deploy_code=_hoisted,
            victim_enter=_indent(victim_enter, 8),
            victim_exit=_indent(victim_exit, 8),
            setup=setup,
            attack_action=action,
            measure_victim=measure_victim,
            measure_atk=measure_atk,
            funding_wei=int(funding_wei),
            fail_report=(_VICTIM_FAIL if self.custom_errors else _VICTIM_FAIL_REQUIRE),
        )

    def compose_sweep(
        self,
        *,
        deploy_code: str,
        attacker_code: str = "",
        predicate: str,
        token_expr: str = "",
        attack_body: str = "",
        honest_body: str = "",
        mode: str = "contract",
        extra_imports: list[str] | None = None,
        variants: list[tuple[int, int, int]] | None = None,
    ) -> tuple[str, list[tuple[int, int, int]]]:
        """Re-run the agent's own exploit across an environment the agent never chose.

        The dominant failure of a proof gate is not a wrong idea and not a syntax error.
        It is an attack that compiles, runs, and extracts nothing -- right mechanism,
        wrong magnitude. A rounding bias of one wei per round is invisible in a single
        trip and obvious after thirty-two; a stake above 2**128 wei is unreachable with a
        ten-ether endowment; a time-locked withdrawal is unreachable without warping.
        None of those are things the model can fix by thinking harder, because the
        endowment and the clock were never in its hands.

        So the harness sweeps them. The knobs -- endowment, repetition, elapsed time --
        are applied IDENTICALLY to the honest baseline and to the attack, so a sweep can
        only ever discover an asymmetry that was already there; it cannot mint one. And
        every variant is a separate test function in a single file, so the whole family
        costs one compile and zero gateway requests.

        A variant whose honest baseline cannot survive repetition simply reverts and
        produces no evidence, which is the correct outcome rather than a special case.
        """
        if predicate not in ("eth_profit", "token_profit"):
            raise ValueError("the sweep only applies to profit predicates")
        if predicate == "token_profit" and not token_expr.strip():
            raise ValueError("token_profit needs token_expr")
        if not honest_body.strip():
            raise ValueError("the sweep needs honest_body; both sides get the same knobs")

        _frags, self.renamed = deconflict(self.source, {
            "deploy_code": deploy_code,
            "attacker_code": attacker_code,
            "attack_body": attack_body,
            "honest_body": honest_body,
        })
        deploy_code = _frags["deploy_code"]
        attacker_code = _frags["attacker_code"]
        attack_body = _frags["attack_body"]
        honest_body = _frags["honest_body"]

        grid = variants or DEFAULT_SWEEP
        _eoa = draw_identity()
        attacker_expr = "address(atk)" if mode == "contract" else "eoa"
        if predicate == "eth_profit":
            m_ctrl, m_atk = "ctrl.balance", f"{attacker_expr}.balance"
            m_drained = "address(target).balance"
        else:
            t = token_expr.strip()
            m_ctrl = f"_ArbiterToken({t}).balanceOf(ctrl)"
            m_atk = f"_ArbiterToken({t}).balanceOf({attacker_expr})"
            m_drained = f"_ArbiterToken({t}).balanceOf(address(target))"

        trials = []
        for i, (endow, repeats, warp) in enumerate(grid):
            if mode == "contract":
                setup = _SWEEP_ATTACKER_SETUP.format(endow=endow)
                action = "            atk.attack();"
            else:
                setup = _SWEEP_EOA_SETUP.format(endow=endow, eoa_addr=_eoa)
                action = _indent(attack_body, 12)
            trials.append(
                _SWEEP_TRIAL.format(
                    i=i, endow=endow, repeats=repeats, warp=warp,
                    deploy_code=_indent(deploy_code, 8),
                    honest_body=_indent(honest_body, 12),
                    setup=setup,
                    attack_action=action,
                    measure_ctrl=m_ctrl,
                    measure_atk=m_atk,
                    measure_drained=m_drained,
                    fail_report=(
                        _FAIL_CUSTOM_ERROR if self.custom_errors else _FAIL_REQUIRE
                    ),
                    drain_report=(
                        _NOT_DRAINED_CUSTOM_ERROR if self.custom_errors
                        else _NOT_DRAINED_REQUIRE
                    ),
                    prank_attacker=(
                        "" if mode == "contract"
                        else "        vm.startPrank(eoa, eoa);"
                    ),
                    unprank_attacker=(
                        "" if mode == "contract" else "        vm.stopPrank();"
                    ),
                )
            )

        extras = "\n".join(
            f'import "{spec.strip()}";'
            for spec in (extra_imports or []) if spec and spec.strip()
        )
        return (
            _SWEEP_TEMPLATE.format(
                pragma=self.pragma,
                target_import=self.target_import,
                extra_imports=("\n" + extras if extras else ""),
                error_decl=(_ERROR_DECLS if self.custom_errors else ""),
                attacker_code=attacker_code.strip(),
                trials="\n".join(trials),
            ),
            grid,
        )

    def write_poc(self, name: str, solidity: str) -> str:
        safe = re.sub(r"[^A-Za-z0-9_]", "", name) or "Poc"
        if not safe.endswith("Poc"):
            safe = f"{safe}Poc"

        # Retire every earlier PoC before writing this one. `forge build` compiles the
        # whole test directory, so a single malformed exploratory PoC left on disk makes
        # every LATER build fail with ITS errors -- and the agent, reading a compiler
        # error about a file it has moved on from, cannot fix the file it is actually
        # working on. This was the dominant cause of compile failures: 72 "Undeclared
        # identifier" errors, most of them belonging to abandoned probes rather than to
        # the exploit being compiled. Each PoC is independent, so only the current one
        # ever needs to build.
        for stale in (self.root / "test").glob("*.t.sol"):
            stale.unlink()

        path = self.root / "test" / f"{safe}.t.sol"
        path.write_text(solidity, encoding="utf-8")
        self.pocs[safe] = solidity
        return safe

    @property
    def _force(self) -> list[str]:
        """Whether this workspace must recompile everything rather than incrementally.

        In project mode the contract only resolves when the project's own files are
        compilation roots -- that is the whole reason the mode exists. forge's cache
        defeats it: with only the test file changed it recompiles that file alone, the
        repository drops out of the unit, and a build that passed a moment earlier fails
        with the same cycle error. Costly and unavoidable, so it is paid only in the mode
        that needs it.
        """
        return ["--force"] if self.plan is not None and self.plan.chosen_src != "src" else []

    def build(self, timeout: int = 240) -> CommandResult:
        result = self._forge(["build", *self._force], timeout=timeout)
        # "Stack too deep" is the harness's own fault, not the agent's. Every gate added
        # to the profit template put another local in the same function, and Solidity has
        # sixteen stack slots -- so six of this project's own reference exploits stopped
        # compiling the moment the drain invariant landed, and every one of them was a
        # recall loss charged to the wrong party. The IR pipeline has no such limit; it is
        # slower, so it is a fallback rather than the default.
        if not result.ok and "Stack too deep" in result.combined and not self._via_ir:
            self._via_ir = True
            self._write_toml(*self._toml_args, via_ir=True)
            result = self._forge(["build", "--force"], timeout=timeout)
        self.build_ok = result.ok
        return result

    def context_ok(self, timeout: int = 300) -> CommandResult:
        """Does the contract under audit compile at all, before any exploit is written?

        Reported separately from the exploit build because the two failures mean opposite
        things. An exploit that does not compile is the agent's problem and it can be
        told to fix it. A *context* that does not compile is the harness's problem, and
        answering "safe" there is not a verdict -- it is a missing measurement. Keeping
        them apart is what turned "0 of 24 vulnerable" into a diagnosable defect instead
        of a plausible-looking result.
        """
        probe = _CONTEXT_PROBE.format(
            pragma=self.pragma, target_import=self.target_import
        )
        self.write_poc("ArbiterContext", probe)
        result = self._forge(["build"], timeout=timeout)
        for stale in (self.root / "test").glob("*.t.sol"):
            stale.unlink()
        self.pocs.pop("ArbiterContextPoc", None)
        return result

    def _write_toml(self, src: str, solc: str = "", via_ir: bool = False) -> None:
        # Pinning beats auto-detection here: auto_detect_solc picks the HIGHEST version
        # satisfying every pragma, so a repository written for 0.8.9 and pinned ^0.8.0
        # compiles under 0.8.35 and fails on constructs that were legal when it was
        # written. The plan reads the version out of the project's own configuration.
        line = f'solc = "{solc}"' if solc else "auto_detect_solc = true"
        self._toml_args = (src, solc)
        (self.root / "foundry.toml").write_text(
            FOUNDRY_TOML.format(src=src, solc=line,
                                via_ir="true" if via_ir else "false"),
            encoding="utf-8",
        )

    def prepare_context(self, rounds: int = 3, timeout: int = 300) -> dict[str, object]:
        """Compile the contract under audit, repairing until it does.

        Two escalating compilation sets, cheapest first, because they fail for different
        reasons and the cheap one is right most of the time:

          1. **minimal** -- only the test is a compilation root, so forge builds exactly
             the target's import closure. Fast, and unaffected by a broken sibling.
          2. **project** -- the project's own source root becomes `src`, reproducing the
             compilation set its toolchain used. Needed for projects that rely on
             Solidity's transitive re-export through an import cycle, which resolves only
             when the files involved are roots. Measured on defiprotocol: minimal fails
             with "Identifier not found or not unique", project succeeds.

        Each set gets its own repair loop, which feeds the exact source names the
        compiler asked for back into the remappings. Bounded and recorded: "it still does
        not build" is a result the run must carry, not round down to a clean bill.
        """
        if self.plan is None:
            result = self.context_ok(timeout=timeout)
            return {"ok": result.ok, "mode": "hermetic", "rounds": 0,
                    "error": _first_error(result.combined)}

        from .repo import plan_for, repair

        result = self._prepare_one(rounds, timeout)
        if result.get("ok"):
            return result

        # Neither import-resolution order is right everywhere, and which one a repository
        # needs is not predictable from its layout -- so the other one is tried rather
        # than guessed at. Pure CPU to re-resolve, under a second to rebuild.
        try:
            other = plan_for(
                self.plan.target,
                repo_root=self.plan.repo_root,
                long_tail_first=not self.plan.long_tail_first,
            )
        except Exception:  # noqa: BLE001
            return result
        self.plan = other
        self.target_import = other.target_import
        (self.root / "remappings.txt").write_text(
            "\n".join(other.remappings) + "\n", encoding="utf-8"
        )
        second = self._prepare_one(rounds, timeout)
        second["first_order_failed"] = result.get("failed_modes")
        second["resolution_order"] = (
            "long_tail" if other.long_tail_first else "long_prefix"
        )
        return second

    def _prepare_one(self, rounds: int, timeout: int) -> dict[str, object]:
        """One resolution order, across the four compilation configurations."""
        from .repo import repair

        assert self.plan is not None
        attempts: list[dict[str, object]] = []
        root = self.plan.source_root.as_posix()
        pinned = self.plan.solc_version
        # Four configurations, cheapest first. The compilation SET decides whether a
        # cyclic re-export resolves; the compiler VERSION decides whether constructs that
        # were legal when the repository was written still compile. They fail
        # independently, so both are tried rather than guessed at.
        modes = [
            ("minimal", "src", pinned),
            ("project", root, pinned),
            ("minimal", "src", ""),
            ("project", root, ""),
        ]
        if self.plan.chosen_src != "src":  # a plan that already knows starts there
            modes.sort(key=lambda m: m[1] == "src")

        for mode, src, solc in modes:
            self._write_toml(src, solc)
            # Set before probing, not after: `_force` reads it, and the project-mode
            # probe is exactly the build that must not come from cache.
            self.plan.chosen_src = src
            self.plan.chosen_solc = solc
            result = None
            for attempt in range(rounds + 1):
                result = self.context_ok(timeout=timeout)
                if result.ok:
                    return {
                        "ok": True, "mode": mode, "rounds": attempt,
                        "solc": solc or "auto",
                        "remappings": len(self.plan.remappings),
                        "external": list(self.plan.external_used),
                        "failed_modes": attempts,
                    }
                if attempt == rounds or not repair(self.plan, result.combined):
                    break
                (self.root / "remappings.txt").write_text(
                    "\n".join(self.plan.remappings) + "\n", encoding="utf-8"
                )
            attempts.append({
                "mode": mode, "solc": solc or "auto",
                "error": _first_error(result.combined if result else ""),
            })

        # Leave the workspace in the cheaper configuration: a failed project-wide build
        # usually means an unrelated sibling is broken, and the agent's own PoCs should
        # not be charged for that.
        self.plan.chosen_src = "src"
        self.plan.chosen_solc = pinned
        self._write_toml("src", pinned)
        return {
            "ok": False, "mode": "none", "rounds": rounds,
            "remappings": len(self.plan.remappings),
            "error": attempts[-1]["error"] if attempts else "",
            "failed_modes": attempts,
        }

    @staticmethod
    def neuter(solidity: str) -> tuple[str, bool]:
        """Remove the attack, leaving setup, baseline and predicate exactly as they were.

        The audit of this project's own accepted proofs found two that still passed with
        the attack deleted -- the predicate had been satisfied by something else entirely,
        and nothing at the time could tell. Returns (text, whether the attack was found),
        because a proof that cannot be neutered cannot be checked and should say so rather
        than quietly count as verified.
        """
        if _CONTRACT_ATTACK.strip() in solidity:
            return solidity.replace(
                _CONTRACT_ATTACK.strip(), "/* attack removed by the harness */"
            ), True
        match = _EOA_PRANK_RE.search(solidity)
        if match and match.group(1).strip():
            return (
                solidity[: match.start(1)]
                + "\n/* attack removed by the harness */\n"
                + solidity[match.end(1):],
                True,
            )
        return solidity, False

    @staticmethod
    def passing_sweep_variants(output: str) -> list[int]:
        """Which variants of a sweep the EVM accepted, by index."""
        found: list[int] = []
        for match in re.finditer(r"\[PASS\]\s*test_arbSweep(\d+)", output):
            found.append(int(match.group(1)))
        return sorted(set(found))

    def run_poc(self, name: str, timeout: int = 240) -> CommandResult:
        return self._forge(
            ["test", "--match-path", f"test/{name}.t.sol", "-vvv", *self._force],
            timeout=timeout,
        )

    def _forge(self, args: list[str], timeout: int) -> CommandResult:
        forge = shutil.which("forge")
        if forge is None:
            raise BuildUnavailable("forge not found on PATH")
        try:
            proc = subprocess.run(  # noqa: S603
                [forge, *args],
                cwd=self.root,
                capture_output=True,
                text=True,
                timeout=timeout,
            )
        except subprocess.TimeoutExpired:
            return CommandResult(False, "", f"timed out after {timeout}s", 124)
        return CommandResult(
            proc.returncode == 0, proc.stdout or "", proc.stderr or "", proc.returncode
        )

    def cleanup(self) -> None:
        shutil.rmtree(self.root, ignore_errors=True)


# A dependency-free stand-in for forge-std. `forge test` discovers any contract whose
# name starts with `Test` and runs its `test*` functions, so no base class is needed;
# and the cheatcode precompile sits at a fixed address, so declaring the interface by
# hand gives a PoC prank/deal/warp/expectRevert without vendoring anything.
VM_SOL = """// SPDX-License-Identifier: Apache-2.0
pragma solidity __PRAGMA__;

/// Subset of the Foundry cheatcode interface, declared by hand so that a proof of
/// concept needs no external dependency and the workspace stays hermetic.
interface Vm {
    function prank(address) external;
    // Two-argument forms set msg.sender AND tx.origin, which is the only way to satisfy
    // a require(msg.sender == tx.origin) guard from inside a test.
    function prank(address, address) external;
    function startPrank(address) external;
    function startPrank(address, address) external;
    function stopPrank() external;
    function deal(address, uint256) external;
    function warp(uint256) external;
    function roll(uint256) external;
    function expectRevert() external;
    function expectRevert(bytes4) external;
    function label(address, string calldata) external;
    function store(address, bytes32, bytes32) external;
    function load(address, bytes32) external returns (bytes32);
    // Two worlds from one setup: the victim-loss predicate runs the same scenario with
    // and without the attack and compares what the victim gets back, which is only
    // meaningful if both start from byte-identical state.
    function snapshotState() external returns (uint256);
    function revertToState(uint256) external returns (bool);
    // Measured additions. Across two full runs 33 exploits failed to compile on
    // `vm.sign` alone, and a further handful on addr/assume/fee/difficulty -- every one
    // of them a recall loss caused by this interface being short, not by the attack
    // being wrong. Signature forgery is still refused by the attack-side lint; what is
    // restored here is the ability to write a legitimate signed message.
    function sign(uint256, bytes32) external pure returns (uint8, bytes32, bytes32);
    function addr(uint256) external pure returns (address);
    function assume(bool) external pure;
    function fee(uint256) external;
    function difficulty(uint256) external;
    function prevrandao(bytes32) external;
    function getNonce(address) external returns (uint64);
    function expectEmit(bool, bool, bool, bool) external;
    function recordLogs() external;
}

// File scope, so a contract the agent writes can reach it too. 13 exploits failed to
// compile because `vm` is a member of Harness and an Attacker does not inherit it.
// A plain comment, not a doc comment: solc rejects @notice on a file-level variable.
// Reaching a cheatcode from an attack is still refused by the lint, which is where that
// decision belongs, rather than by an accident of scope.
// Named `vm`, and it used to be `vm_`. The underscore was the whole defect: an agent
// writing an Attacker -- which inherits nothing -- reaches for `vm.warp` the way everyone
// writing Foundry does, and got `Undeclared identifier. Did you mean "Vm"?`. 42 of those
// in one 40-sample run, the largest named error class left after the assert repair, and
// every one of them a turn spent on the harness's spelling rather than on the attack.
// `Harness` no longer declares its own, so there is exactly one `vm` in scope everywhere
// and nothing shadows anything. Reaching a cheatcode FROM an attack is still refused by
// the lint, which is where that decision belongs rather than in an accident of scope.
Vm constant vm = Vm(0x7109709ECfa91a80626fF3989D68f67F5b1DD12D);

// The assertion family, at FILE scope. These decide nothing: the verdict is computed by
// the harness from balances the EVM reported, and no assertion an agent writes is
// consulted anywhere in it. They exist because an agent reaching for forge-std out of
// habit lost the whole attempt to `Undeclared identifier. Did you mean "assert"?` -- 54
// of those in one census, every one a recall loss with nothing wrong with the attack.
//
// They revert rather than no-op deliberately. The agent wrote them as control flow, and
// continuing silently past a failed check would run the rest of the attack in a state it
// did not intend. Reverting cannot manufacture a finding in either direction, because a
// reverted attack is measured as an attack that did nothing.
//
// File scope rather than a member of `Harness`, because a contract member shadows the
// whole overload set: a Harness declaring assertTrue(bool,string) makes assertTrue(cond)
// fail to resolve from inside it, and an Attacker -- which inherits nothing -- could not
// reach either. One set at file scope resolves identically everywhere.
//
// int256 overloads are deliberately absent: `assertEq(1, 2)` would then match both
// uint256 and int256 and fail with "No unique declaration found", trading one compile
// error for another.
function assertTrue(bool c) pure { require(c, "assertTrue"); }
function assertTrue(bool c, string memory why) pure { require(c, why); }
function assertFalse(bool c) pure { require(!c, "assertFalse"); }
function assertFalse(bool c, string memory why) pure { require(!c, why); }
function assertEq(uint256 a, uint256 b) pure { require(a == b, "assertEq"); }
function assertEq(uint256 a, uint256 b, string memory why) pure { require(a == b, why); }
function assertEq(address a, address b) pure { require(a == b, "assertEq"); }
function assertEq(address a, address b, string memory why) pure { require(a == b, why); }
function assertEq(bool a, bool b) pure { require(a == b, "assertEq"); }
function assertEq(bytes32 a, bytes32 b) pure { require(a == b, "assertEq"); }
function assertGt(uint256 a, uint256 b) pure { require(a > b, "assertGt"); }
function assertGt(uint256 a, uint256 b, string memory why) pure { require(a > b, why); }
function assertGe(uint256 a, uint256 b) pure { require(a >= b, "assertGe"); }
function assertLt(uint256 a, uint256 b) pure { require(a < b, "assertLt"); }
function assertLt(uint256 a, uint256 b, string memory why) pure { require(a < b, why); }
function assertLe(uint256 a, uint256 b) pure { require(a <= b, "assertLe"); }
function assertApproxEqAbs(uint256 a, uint256 b, uint256 d) pure {
    require(a > b ? a - b <= d : b - a <= d, "assertApproxEqAbs");
}

/// Inherit this in a PoC to get `vm`. The assertion family above is at file scope and
/// needs no inheritance at all.
/// The exploit template below is written by the harness, never by the auditor.
/// forge runs `test*` functions on contracts whose name starts with `Test`;
/// a function that reverts is a failing test, one that returns is a passing test.
contract Harness {

    /// Render a uint so the harness can tell the auditor HOW MUCH it fell short by.
    /// A bare "you did not profit" is a dead end; "you gained 1000000000000000000,
    /// honest gained 1000000000000000000" says the attack merely reproduced the
    /// intended behaviour, which points at what to change.
    function _u(uint256 v) internal pure returns (string memory) {
        if (v == 0) return "0";
        uint256 n = v;
        uint256 digits;
        while (n != 0) { digits++; n /= 10; }
        bytes memory buf = new bytes(digits);
        while (v != 0) { digits--; buf[digits] = bytes1(uint8(48 + v % 10)); v /= 10; }
        return string(buf);
    }
}
"""


# The smallest file that proves the contract under audit and its whole import closure
# resolve and compile. It asserts nothing; it exists so a failure to build can be
# attributed to the harness rather than charged to the contract as a clean bill of health.
_CONTEXT_PROBE = """// SPDX-License-Identifier: Apache-2.0
pragma solidity {pragma};

import "{target_import}";
import "./Vm.sol";

contract TestArbiterContextPoc is Harness {{
    function testArbiterContext() public pure {{ }}
}}
"""


def _indent(text: str, spaces: int) -> str:
    pad = " " * spaces
    return "\n".join(pad + line for line in text.strip().splitlines())


# (endowment in wei, repetitions, seconds warped). Chosen to span the three axes a model
# cannot reach on its own, at the coarsest granularity that still separates them: a
# thousand-fold endowment gap, a thirty-two-fold repetition gap, and a week of elapsed
# time. Twelve variants, one compile.
_VICTIM_ERROR = (
    "error ArbiterNoHarm(uint256 recoveredWithoutAttack, uint256 recoveredWithAttack,\n"
    "                    uint256 attackerGain);\n"
)

# Three conditions, and the third is the one measurement forced. Harm alone is not
# enough: a victim recovers less whenever anyone else competes for the same pool, and
# three of arm B's four surviving false positives were exactly that -- a fixed-size
# redemption that reverted because an attacker had legitimately consumed liquidity.
# What separates a drain from contention is CONSERVATION: in a drain, what the victim
# lost is in the attacker's hands. In contention it is not, because the attacker took
# value they had a claim to. So the attacker's gain must cover the victim's shortfall.
_VICTIM_FAIL = """        uint256 shortfall = recoveredA > recoveredB ? recoveredA - recoveredB : 0;
        if (recoveredB >= recoveredA || attackGain == 0 || attackGain < shortfall) {
            revert ArbiterNoHarm(recoveredA, recoveredB, attackGain);
        }"""

_VICTIM_FAIL_REQUIRE = """        uint256 shortfall = recoveredA > recoveredB ? recoveredA - recoveredB : 0;
        if (recoveredB >= recoveredA || attackGain == 0 || attackGain < shortfall) {
            revert(string(abi.encodePacked(
                "ArbiterNoHarm(withoutAttack=", _u(recoveredA),
                ", withAttack=", _u(recoveredB),
                ", attackerGain=", _u(attackGain), ")"
            )));
        }"""

# Both of these now capture the data location, and both drop it on the way up, because a
# state variable is written `uint256[]` where a local is `uint256[] memory`. The victim
# path learned that first; deploy_code was left behind and kept failing the same way --
# `address[] memory users = new address[](2);` matched nothing here, stayed a local inside
# arbSetup(), and every later reference to `users` came back as an Undeclared identifier
# at a line number in a file the agent never wrote.
#
# The type slot admits a dot. `Vault.Conf memory c = target.conf();` is the ordinary way
# to read a struct-returning getter and neither pattern could see it, so the declaration
# stayed a local and every later stage came back as an Undeclared identifier. A member
# WRITE is still not a declaration: `c.cap = 7;` has nothing after the dotted name where
# a variable would be, so it never matches.
_TYPE = r"[A-Za-z_]\w*(?:\.[A-Za-z_]\w*)?(?:\[\])?"

DECL_RE = re.compile(
    rf"^[ \t]*({_TYPE})[ \t]+"
    r"(?:(memory|storage|calldata)[ \t]+)?"
    r"(?:payable[ \t]+)?"
    r"([A-Za-z_]\w*)[ \t]*=",
    re.MULTILINE,
)


# The two patterns had drifted apart. `DECL_RE` learned `payable` and this one never did,
# so `address payable sink = payable(...)` was lifted out of deploy_code and left a local
# in victim_enter -- the same declaration, hoisted or not depending on which stage the
# agent happened to put it in.
VICTIM_DECL_RE = re.compile(
    rf"^([ \t]*)({_TYPE})[ \t]+"
    r"(?:(memory|storage|calldata)[ \t]+)?"
    r"(?:payable[ \t]+)?"
    r"([A-Za-z_]\w*)[ \t]*=",
    re.MULTILINE,
)


# Tokens that can stand where a type would and are not one. Both hoisters used to consult
# a list like this when deciding what to LIFT and then rewrite every match regardless, so
# a line the scan had refused still had its first token deleted. Two ways that showed up:
#
#   uint n = 1;          ->  n = 1;              // nothing declares n
#   else flag = false;   ->  flag = false;       // the branch is now unconditional
#
# The first is a compile error at a line the agent did not write. The second is worse --
# it compiles, and the harness runs code the agent did not send. `uint`, `int` and `bool`
# used to be on this list, which is why `uint256 n = 1` was hoisted and `uint n = 1` was
# corrupted; they are types, and a state variable of one of them is perfectly ordinary.
_NOT_A_TYPE = frozenset({
    "return", "if", "else", "for", "while", "do", "try", "catch",
    "emit", "delete", "new", "revert", "throw", "assembly", "unchecked",
    "break", "continue",
})


# A tuple's LHS holds no nested parentheses, so this stops at the first `)` and the call
# on the right-hand side -- `address(t).call{value: v}(...)` -- is never touched.
TUPLE_DECL_RE = re.compile(r"^([ \t]*)\(([^()=;\n]*)\)[ \t]*=(?!=)", re.MULTILINE)

# Elementary value types only. A state variable of one of these can be assigned from a
# tuple with no data location anywhere in sight; `bytes`, `string` and every array cannot.
_VALUE_TYPE_RE = re.compile(
    r"^(?:bool|address|address\s+payable"
    r"|u?int(?:8|16|24|32|40|48|56|64|72|80|88|96|104|112|120|128|136|144"
    r"|152|160|168|176|184|192|200|208|216|224|232|240|248|256)?"
    r"|bytes(?:[1-9]|1\d|2\d|3[0-2]))$"
)


def hoist_tuple_locals(fragment: str) -> tuple[dict[str, str], str]:
    """Lift `(bool ok, ) = address(t).call{value: v}("")` so a later stage can read `ok`.

    That line is not an exotic shape. It is how Solidity sends ether, so it turns up in
    any victim whose exit is a low-level call -- and `VICTIM_DECL_RE` only ever matched
    `Type name =` at the start of a line, so every name declared inside a tuple stayed a
    local. The `require(ok, "...")` one stage later then came back as an Undeclared
    identifier pointing into a file the agent never wrote. One of the benchmark's own
    thirty-five reference exploits is unbuildable for exactly this and nothing else.

    All-or-nothing per statement, because Solidity dropped mixed tuple declaration and
    assignment in 0.5.0: `(arbv_ok, bytes memory ret) = ...` does not compile. A tuple
    with a reference-typed component is therefore left exactly as it was, which is
    today's behaviour and cannot regress anything.

    Returns (name -> type for what was lifted, the rewritten fragment).
    """
    seen: dict[str, str] = {}

    def rewrite(m: re.Match[str]) -> str:
        indent, inside = m.group(1), m.group(2)
        parts = [p.strip() for p in inside.split(",")]
        names: list[str] = []
        found: dict[str, str] = {}
        for part in parts:
            if not part:
                names.append("")
                continue
            bits = part.split()
            if len(bits) < 2:
                return m.group(0)          # already a plain assignment; nothing to lift
            type_name, var = " ".join(bits[:-1]), bits[-1]
            if not _VALUE_TYPE_RE.match(type_name):
                return m.group(0)          # a data location in the tuple: leave it alone
            found[var] = "address" if type_name.startswith("address") else type_name
            names.append(var)
        if not found:
            return m.group(0)
        seen.update(found)
        return f"{indent}({', '.join(names)}) ="

    return seen, TUPLE_DECL_RE.sub(rewrite, fragment)


def _reject_storage_hoist(location: str, line: str, field: str) -> None:
    """A `storage` local cannot be lifted, and pretending otherwise is worse than a refusal.

    Dropping the location off `memory` is a copy from memory into storage, which is what
    the assignment already meant. Dropping it off `storage` is a DEEP COPY of whatever the
    pointer aimed at -- silently different semantics when the struct is copyable, and a
    compile error the agent cannot map back to its own text when it holds a mapping.

    So refuse at composition and quote the line. A refusal costs one turn; a compile error
    in generated code costs the rest of the audit.
    """
    if location != "storage":
        return
    raise ValueError(
        f"{field} declares a storage pointer that the harness would have to lift to a "
        f"state variable, and lifting it would deep-copy what it points at:\n"
        f"    {line.strip()}\n"
        "Every stage of the trial is a separate call, so locals do not survive between "
        "them. Read through the handle instead of holding a pointer to it -- keep the key "
        "or the index in a local, and index again where you need it."
    )


def hoist_victim_locals(enter: str, exit_: str) -> tuple[str, str, str]:
    """Lift the victim's entry locals to storage so their exit can still see them.

    Measured, not anticipated. `arbEnter` and `arbExit` are separate external calls --
    they have to be, so that a victim whose withdrawal REVERTS is a result rather than
    an abort -- and a local declared in one is gone by the other. Any position
    identified by a handle the contract hands back was therefore inexpressible:

        enter:  uint256 shares = target.deposit{value: 1 ether}();
        exit:   target.redeem(shares);            // Undeclared identifier

    Nine of the benchmark's thirty-five reference exploits died exactly there. Every one
    of them looked like a modelling limit of the predicate and was a frame-scoping bug
    in the harness.

    Two details the first version got wrong, both found by the remaining failures. The
    name is renamed everywhere it appears and not only where it is declared -- a
    fragment that declares `MockPool p` and uses `p` on the next line broke otherwise.
    And the data location is dropped on the way up, because `uint256[] memory` is a
    local type while a state variable has to be `uint256[]`.

    Returns (state declarations, rewritten entry, rewritten exit).
    """
    seen, enter = hoist_tuple_locals(enter)
    for m in VICTIM_DECL_RE.finditer(enter):
        _, type_name, location, var = m.groups()
        if type_name in _NOT_A_TYPE or var in seen:
            continue
        _reject_storage_hoist(location or "", m.group(0), "victim_enter")
        seen[var] = type_name
    if not seen:
        return "", enter, exit_

    # Prefixed so a victim's local can never collide with one the setup hoisted.
    decls = "\n".join(f"    {t} internal arbv_{v};" for v, t in seen.items())
    # One decision, consulted twice. The scan above and this rewrite used to disagree,
    # and every line they disagreed about was a line the harness broke.
    body = VICTIM_DECL_RE.sub(
        lambda m: m.group(0) if m.group(2) in _NOT_A_TYPE
        else f"{m.group(1)}{m.group(4)} =",
        enter,
    )
    names = list(seen)
    return decls, rename_victim_locals(body, names), rename_victim_locals(exit_, names)


def rename_victim_locals(fragment: str, names: list[str]) -> str:
    """Point the exit at the hoisted names."""
    out = fragment
    for name in names:
        out = re.sub(rf"(?<![A-Za-z0-9_]){re.escape(name)}(?![A-Za-z0-9_])",
                     f"arbv_{name}", out)
    return out


_NONCODE_RE = re.compile(
    r"//[^\n]*|/\*.*?\*/|\"(?:\\.|[^\"\\\n])*\"|'(?:\\.|[^'\\\n])*'", re.S)

# Order matters: `abstract contract` has to be tried before `contract`.
_DECLARER_RE = re.compile(
    r"[{}]|\b(?:abstract\s+)?(?:contract|interface|library|struct|enum)\s+[A-Za-z_]\w*"
    r"|\bfunction\s+[A-Za-z_]\w*")

# Never renamed, whatever the target declares. `_VICTIM_ATTACKER_SETUP` writes
# `new Attacker(...)` verbatim, so renaming the agent's Attacker would compose a file
# that instantiates a type nothing declares -- the exact defect D1 was.
_NEVER_RENAME = frozenset({"Attacker"})

# Declared by the harness itself in Vm.sol. An agent that writes its own `assertEq` or
# its own `Vm` collides with these the same way it collides with the target's symbols,
# and the same rename fixes it.
HARNESS_RESERVED = frozenset({
    "Vm", "vm", "Harness",
    "assertTrue", "assertFalse", "assertEq", "assertGt", "assertGe",
    "assertLt", "assertLe", "assertApproxEqAbs",
})


def _blank_noncode(src: str) -> str:
    """Comments and string literals replaced by spaces, with every offset preserved.

    Offsets have to survive so a match found in the blanked copy can be spliced out of the
    original. Newlines are kept so a line number still means what it says.
    """
    return _NONCODE_RE.sub(lambda m: re.sub(r"[^\n]", " ", m.group(0)), src)


def top_level_names(src: str) -> set[str]:
    """Every name the source declares at FILE scope.

    Depth-aware on purpose. A `struct Position` inside a contract is not in file scope, so
    an agent declaring its own `Position` is not colliding with it, and renaming against it
    would be a rename nobody asked for.
    """
    code = _blank_noncode(src)
    names: set[str] = set()
    depth = 0
    for m in _DECLARER_RE.finditer(code):
        tok = m.group(0)
        if tok == "{":
            depth += 1
        elif tok == "}":
            depth = max(0, depth - 1)
        elif depth == 0:
            names.add(tok.split()[-1])
    return names


def _rename_symbols(src: str, names: list[str]) -> str:
    """Rename whole identifiers, and not the ones inside comments or string literals."""
    if not names:
        return src
    code = _blank_noncode(src)
    pat = re.compile(
        r"(?<![A-Za-z0-9_$])(" + "|".join(re.escape(n) for n in names) + r")(?![A-Za-z0-9_$])")
    out: list[str] = []
    last = 0
    for m in pat.finditer(code):
        out.append(src[last:m.start()])
        out.append(m.group(1) + "_arb")
        last = m.end()
    out.append(src[last:])
    return "".join(out)


def deconflict(target_source: str, fragments: dict[str, str]) -> tuple[dict[str, str], list[str]]:
    """Rename the agent's own top-level declarations where they collide with the target's.

    `import "../src/Target.sol"` is unnamed, so every top-level declaration in the target
    is in scope. Nine of the thirty-five vulnerable samples declare `IERC20` themselves.
    An agent that writes one to cast with got `Identifier already declared` -- 41 in one
    census -- and an agent that skipped it and cast against the target's own got
    `Explicit type conversion from "contract IERC20"`, 41 more across two rows. Eighty-two
    compile failures, none of them about the attack.

    Renaming, not refusing, and the reason is that renaming is free: an interface is
    structural, so `IERC20_arb` and `IERC20` describe the same calls and a cast through
    either means the same thing. A refusal would cost a turn to say so.

    Only names the agent DECLARES are renamed. A fragment that merely references the
    target's `IERC20` is left alone, which is what makes this safe -- the rename moves an
    agent's reference onto the agent's own declaration, where it already pointed.

    Returns (rewritten fragments, the names that were renamed).
    """
    reserved = (top_level_names(target_source) | HARNESS_RESERVED) - _NEVER_RENAME
    mine = top_level_names("\n\n".join(fragments.values())) - _NEVER_RENAME
    clash = sorted(mine & reserved)
    if not clash:
        return dict(fragments), []
    return {k: _rename_symbols(v, clash) for k, v in fragments.items()}, clash


def hoist_declarations(deploy_code: str) -> tuple[str, str]:
    """Lift the setup's locals to storage so the trial can be run in stages.

    The victim-loss predicate has to survive a victim whose withdrawal REVERTS -- that is
    the strongest evidence of harm there is, and inline it takes the whole test down with
    it. Tolerating it means each stage has to be its own external call, and locals do not
    survive that. Since the agent is already required to name the contract under audit
    `target`, every top-level declaration in its setup can be lifted mechanically.

    Returns (state variable declarations, rewritten setup).
    """
    seen, deploy_code = hoist_tuple_locals(deploy_code)
    for m in DECL_RE.finditer(deploy_code):
        type_name, location, var = m.groups()
        if type_name in _NOT_A_TYPE or var in seen:
            continue
        _reject_storage_hoist(location or "", m.group(0), "deploy_code")
        seen[var] = type_name
    if "target" not in seen:
        raise ValueError(
            "deploy_code must declare the contract under audit as a local named exactly "
            "'target', for example 'MyVault target = new MyVault{value: 10 ether}();'"
        )
    decls = "\n".join(f"    {t} internal {v};" for v, t in seen.items())
    # Same decision as the scan. When they disagreed, the type was deleted off a line
    # nothing then declared, and the agent was shown an Undeclared identifier for a name
    # it had declared perfectly well.
    body = DECL_RE.sub(
        lambda m: m.group(0) if m.group(1) in _NOT_A_TYPE else f"        {m.group(3)} =",
        deploy_code,
    )
    return decls, body


# Two worlds, one code path. Each trial builds its own copy of the scenario and differs
# only in whether the attack runs, so any difference in what the victim recovers is
# attributable to the attack and to nothing else. Every stage is a separate external call
# so that a stage which reverts is a RESULT rather than an abort -- a victim who cannot
# withdraw at all is the strongest evidence of harm, and inline it would just kill the run.
_VICTIM_TEMPLATE = """// SPDX-License-Identifier: Apache-2.0
pragma solidity {pragma};

import "{target_import}";{extra_imports}
import "./Vm.sol";

interface _ArbiterToken {{ function balanceOf(address) external view returns (uint256); }}

/// How an attacker finds out who the victim is. A real attacker can read the chain, so
/// withholding the victim's address would make whole classes of attack inexpressible --
/// but that address is drawn per run precisely so SETUP cannot name it. Both hold at once
/// if the address is discoverable at RUN time and unknowable at WRITE time: your Attacker
/// asks its own deployer for it.
interface _ArbiterHarness {{ function arbiterVictim() external view returns (address); }}

{error_decl}
{attacker_code}

contract TestArbiterVictim is Harness {{
    function arbiterVictim() external pure returns (address) {{ return arbVictim; }}

    bytes32 internal constant ARB_COMPLETED = keccak256("arbiter.predicate.reached");
    address internal constant arbVictim = address(uint160({victim_addr}));

{state_decls}
{attacker_decl}
    // The attacker's two identities, at contract level so they outlive arbDeploy.
    // Both are measured, because profit parked in the EOA rather than in the contract
    // is still profit and used to read as zero.
    address internal constant arbAtkEoa =
        address(uint160(uint256(keccak256("arbiter.attacker"))));
    address internal constant arbEoa = address(uint160({eoa_addr}));

    function testArbiterVictimLoss() public {{
        require(
            this.arbiterRun() == ARB_COMPLETED,
            "ARBITER: execution halted before the harness predicate ran"
        );
    }}

    // ---- agent-supplied fragments, each in its own frame ----

    function arbSetup() external {{
{deploy_code}
    }}

    function arbEnter() external {{
        vm.startPrank(arbVictim, arbVictim);
{victim_enter}
        vm.stopPrank();
    }}

    function arbExit() external {{
        vm.startPrank(arbVictim, arbVictim);
{victim_exit}
        vm.stopPrank();
    }}

    /// The attacker is built ONCE per trial, not once per round.
    ///
    /// It used to live at the top of arbAttack, which the round loop calls `rounds`
    /// times -- so at rounds=8 the attacker was redeployed and re-funded eight times
    /// and nothing it accumulated survived into the next round. Two consequences, and
    /// the second is the serious one. Per-round rounding bias, which is the only reason
    /// the eight-round environment exists, was structurally unprovable. And each
    /// round's contribution was floored at zero before being summed, so an attack that
    /// gained one ether and lost one ether each round reported four ether of profit
    /// against a true net of zero -- while `gain` is the left-hand side of the
    /// conservation check that makes victim_loss mean *the attacker is holding what the
    /// victim lost*. That is a constructible false positive, not a missed finding.
    function arbDeploy() external {{
{setup}
    }}

    function arbAttack() external {{
{attack_action}
    }}

    /// One world. `withAttack` is the only thing that differs between the two runs of
    /// a pair; the other three arguments are the environment, which is swept.
    function arbTrial(bool withAttack, uint256 endow, uint256 warpBy, uint256 rounds)
        external
        returns (uint256 recovered, uint256 gain, bool attackRan)
    {{
        this.arbSetup();
        if (warpBy > 0) {{ vm.warp(block.timestamp + warpBy); vm.roll(block.number + 1); }}
        vm.deal(arbVictim, endow);
        this.arbEnter();
        uint256 mid = {measure_victim};

        attackRan = true;
        if (withAttack) {{
            // A fresh attacker per round, and a SIGNED delta per round.
            //
            // Both halves are load-bearing and they were confused with each other. The
            // fresh identity is not a bug: an attacker really can deploy a second
            // contract, and against a contract that keys state by address -- a queue
            // nonce, a claim marker -- repeating from a new address is the attack.
            // Removing it was measured to cost a real finding: the reentrancy the
            // gateway had just proven stopped reproducing, because rounds two onward
            // reverted on the first attacker's own spent nonce.
            //
            // The bug was the flooring. Each round's contribution used to be clamped at
            // zero before being summed, so an attacker that took one ether and gave one
            // back reported four ether of profit over eight rounds against a true net of
            // nothing -- and `gain` is the left-hand side of the conservation check. A
            // signed sum keeps repetition and prices it honestly: a round that loses
            // money now subtracts.
            int256 net;
            for (uint256 r = 0; r < rounds; r++) {{
                this.arbDeploy();
                // After the funding, so a handout can never be counted as profit.
                int256 pre = int256({measure_atk});
                (bool ok, ) =
                    address(this).call(abi.encodeWithSignature("arbAttack()"));
                if (r == 0) {{ attackRan = ok; }}
                if (!ok) {{ break; }}
                net += int256({measure_atk}) - pre;
            }}
            gain = net > 0 ? uint256(net) : 0;
        }}

        // A victim who cannot get out AT ALL has recovered nothing. That is the harm,
        // not an error, so the revert is caught rather than propagated.
        (bool exited, ) = address(this).call(abi.encodeWithSignature("arbExit()"));
        recovered = exited && {measure_victim} > mid ? {measure_victim} - mid : 0;
    }}

    /// The endowment, the clock and the number of rounds were never the agent's to
    /// choose -- they are the harness's constants -- so an attack that is right in
    /// mechanism and short of scale is being failed for the harness's decision. Each
    /// environment is tried as a matched PAIR, so the comparison inside a pair is always
    /// like for like and a sweep can only ever surface an asymmetry, never invent one.
    function arbiterRun() external returns (bytes32) {{
        uint256[{n_env}] memory endow = [{endows}];
        uint256[{n_env}] memory warps = [{warps}];
        uint256[{n_env}] memory rounds = [{rounds}];

        uint256 bestA;
        uint256 bestB;
        uint256 bestGain;
        bool anyRan;

        for (uint256 i = 0; i < {n_env}; i++) {{
            (bool okA, bytes memory ra) = address(this).call(
                abi.encodeWithSignature(
                    "arbTrial(bool,uint256,uint256,uint256)",
                    false, endow[i], warps[i], rounds[i]));
            if (!okA) {{ continue; }}
            (uint256 recA, , ) = abi.decode(ra, (uint256, uint256, bool));
            if (recA == 0) {{ continue; }}   // no baseline, so no harm can be shown

            (bool okB, bytes memory rb) = address(this).call(
                abi.encodeWithSignature(
                    "arbTrial(bool,uint256,uint256,uint256)",
                    true, endow[i], warps[i], rounds[i]));
            if (!okB) {{ continue; }}
            (uint256 recB, uint256 g, bool ran) = abi.decode(rb, (uint256, uint256, bool));
            if (!ran) {{ continue; }}
            anyRan = true;

            // Not `shortfall`. The report block below declares one at function scope, so
            // this used to shadow it and solc said so on EVERY compile of a victim_loss
            // exploit -- a nine-line warning quoting two template lines the agent did not
            // write and cannot change, spent out of the six thousand characters it gets.
            uint256 gap = recA > recB ? recA - recB : 0;
            if (gap > 0 && g >= gap) {{
                bestA = recA; bestB = recB; bestGain = g;
                break;                        // one environment is enough
            }}
            if (bestA == 0) {{ bestA = recA; bestB = recB; bestGain = g; }}
        }}

        require(anyRan, "ARBITER: the attack reverted in every environment, or the "
                        "victim's own path never worked -- fix victim_enter/victim_exit");

        uint256 recoveredA = bestA;
        uint256 recoveredB = bestB;
        uint256 attackGain = bestGain;

        // The definition of the vulnerability, and the one thing the agent cannot
        // arrange for itself: the victim got less back BECAUSE the attack happened, and
        // the attacker is holding more than they started with.
{fail_report}
        return ARB_COMPLETED;
    }}
}}
"""


# (endowment in wei, seconds warped, attack rounds) for the victim-loss predicate. Four
# environments rather than twelve: each one costs a matched PAIR of trials, so the budget
# is doubled relative to the profit sweep, and these four span the three axes an agent
# cannot reach -- a thousand-fold endowment, a week of elapsed time, and repetition.
VICTIM_ENVIRONMENTS: list[tuple[int, int, int]] = [
    (10**19, 0, 1),                  # the default, so environment 0 reproduces today
    (10**22, 0, 1),                  # a thousand times the stake
    (10**19, 7 * 24 * 3600, 1),      # a week later
    (10**19, 0, 8),                  # eight rounds, for a per-round bias
]


DEFAULT_SWEEP: list[tuple[int, int, int]] = [
    (10**19, 1, 0),          # the current default, so variant 0 reproduces today's result
    (10**19, 4, 0),
    (10**19, 32, 0),
    (10**19, 1, 7 * 24 * 3600),
    (10**22, 1, 0),
    (10**22, 4, 0),
    (10**22, 32, 0),
    (10**22, 1, 7 * 24 * 3600),
    (10**25, 1, 0),
    (10**25, 4, 0),
    (10**25, 32, 0),
    (10**25, 1, 7 * 24 * 3600),
]

_SWEEP_TEMPLATE = """// SPDX-License-Identifier: Apache-2.0
pragma solidity {pragma};

import "{target_import}";{extra_imports}
import "./Vm.sol";

interface _ArbiterToken {{ function balanceOf(address) external view returns (uint256); }}

{error_decl}
{attacker_code}

contract TestArbiterSweep is Harness {{
    bytes32 internal constant ARB_COMPLETED = keccak256("arbiter.predicate.reached");

{trials}
}}
"""

# Each variant is its own test function, so forge gives it a fresh EVM state and one
# variant's failure cannot contaminate another's.
_SWEEP_TRIAL = """    /// endowment={endow} wei, repetitions={repeats}, warp={warp}s
    function test_arbSweep{i}() public {{
        require(
            this.arbSweepRun{i}() == ARB_COMPLETED,
            "ARBITER: execution halted before the harness predicate ran"
        );
    }}

    function arbSweepRun{i}() external returns (bytes32) {{
{deploy_code}
        vm.warp(block.timestamp + {warp});
        vm.roll(block.number + 1 + {warp} / 12);

        address ctrl = address(uint160(uint256(keccak256("arbiter.control"))));
        vm.deal(ctrl, {endow});
        uint256 ctrlPre = {measure_ctrl};
        vm.startPrank(ctrl, ctrl);
        for (uint256 _r = 0; _r < {repeats}; _r++) {{
{honest_body}
        }}
        vm.stopPrank();
        uint256 honestGain = {measure_ctrl} > ctrlPre ? {measure_ctrl} - ctrlPre : 0;

{setup}
        uint256 atkPre = {measure_atk};
        uint256 tgtPre = {measure_drained};
{prank_attacker}
        for (uint256 _r = 0; _r < {repeats}; _r++) {{
{attack_action}
        }}
{unprank_attacker}
        uint256 attackGain = {measure_atk} > atkPre ? {measure_atk} - atkPre : 0;
        uint256 tgtPost = {measure_drained};

{drain_report}

{fail_report}
        return ARB_COMPLETED;
    }}
"""

_VICTIM_ATTACKER_SETUP = """        atk = new Attacker(address(target));
        vm.deal(address(atk), {funding_wei});
        vm.deal(arbAtkEoa, {funding_wei});"""

_VICTIM_EOA_SETUP = """        vm.deal(arbEoa, {funding_wei});"""

_VICTIM_EOA_ACTION = """        vm.startPrank(arbEoa, arbEoa);
{attack_body}
        vm.stopPrank();"""

_SWEEP_ATTACKER_SETUP = """        Attacker atk = new Attacker(address(target));
        vm.deal(address(atk), {endow});"""

_SWEEP_EOA_SETUP = """        address eoa = address(uint160({eoa_addr}));
        vm.deal(eoa, {endow});"""


SP = chr(92) + "s"
NL = chr(92) + "n"

_HALTING_RE = re.compile(r"\b(selfdestruct|suicide)\s*\(")

# Cheatcodes that manufacture authority or assets out of nothing. Setup may use them --
# building a world is what setup is for -- but the ATTACK may not, because an attacker in
# front of a deployed contract cannot become its owner, cannot write its storage and
# cannot mint themselves a balance.
#
# This was the largest hole in the whole harness and it defeated every predicate,
# victim_loss included. Measured on a patched sample: the agent wrote
#   vm.startPrank(owner); target.emergencyWithdraw(attacker); vm.stopPrank();
# against an onlyOwner function, and the depositor really did lose their money, so the
# harm was real and the finding was still false. The contract was working exactly as
# designed; the cheatcode was doing the attacking.
# Two tiers, because the receiver cannot be relied on: an attacker contract can declare
# its own `Vm v = Vm(0x7109...)` and call `v.prank(...)`, so anchoring on the name `vm`
# misses it -- measured, that is exactly what slipped through.
#
# These names belong to nothing but the cheatcode interface, so any receiver counts.
def draw_identity() -> str:
    """A Solidity literal for an address that setup could not have named.

    Confirmed by execution rather than argument: with the attacker fixed at
    `keccak256("arbiter.attacker")`, setup can compute that address and hand it a role --
    `vm.store(target, slot 0, attacker)`, or a plain `transferOwnership(attacker)` -- and
    the attack is then an ordinary call that no lint on the attack can object to. Both
    paths were open and both were accepted. Banning cheatcodes in the attack had moved
    the boundary, not closed it.

    Drawing the identity at compose time closes it. The agent writes its setup before
    this value exists, so setup can neither contain the literal nor derive it. The "0x00"
    prefix makes the literal 42 hex digits, which stops solc demanding an EIP-55 checksum
    the harness has no keccak to compute.
    """
    return "0x00" + secrets.token_bytes(20).hex()


_CHEATS_UNAMBIGUOUS = (
    "prank|startPrank|stopPrank|etch|mockCall|mockCallRevert|setNonce|"
    "startBroadcast|resetNonce"
)
# These are plausible method names on a real contract, so they only count on `vm` itself.
_CHEATS_AMBIGUOUS = "store|deal|sign|broadcast|coinbase|chainId"
_FORGERY_RE = re.compile(
    rf"\.\s*({_CHEATS_UNAMBIGUOUS})\s*\(|\bvm\s*\.\s*({_CHEATS_AMBIGUOUS})\s*\("
)
# And the address itself, which is the only way to reach cheatcodes at all, so a fragment
# carrying it is reaching for them however it dresses the call up.
_CHEAT_ADDRESS_RE = re.compile(r"7109709ecfa91a80626ff3989d68f67f5b1dd12d", re.IGNORECASE)


# A contract the agent authored, handed standing during setup, is authority the public
# does not have. Drawing the attacker's identity late stops setup naming the ATTACKER, but
# not setup deploying a deputy and endowing that instead -- the attacker then calls the
# deputy and the privilege check passes on the deputy's address. Deploying the same
# contract inside the attack is fine, because anybody may deploy a contract.
#
# Name-based and therefore partial: an agent that calls its deputy `MockRouter` is not
# caught. It is defence in depth behind the identity draw, not a replacement for it.
_STANDING_RE = re.compile(
    "(?<![A-Za-z0-9_])new" + chr(92) + "s+"
    "(Attacker|Adversary|Bomb|Helper|Exploiter|Malicious" + chr(92) + "w*)"
)


def _reject_standing(fragment: str, field: str) -> None:
    match = _STANDING_RE.search(fragment or "")
    if not match:
        return
    raise ValueError(
        f"{field} deploys {match.group(1)!r} during setup. A contract you wrote, which "
        "the world already trusts before the attack begins, is a capability the public "
        "does not have -- and the privilege check will pass on ITS address rather than "
        "yours. Deploy it inside the attack instead, where deploying a contract is "
        "something anybody can do."
    )


def _reject_forgery(fragment: str, field: str) -> None:
    """Refuse a cheatcode that fabricates what the attacker would have to earn."""
    match = _FORGERY_RE.search(fragment or "")
    if not match and _CHEAT_ADDRESS_RE.search(fragment or ""):
        raise ValueError(
            f"{field} contains the Foundry cheatcode address. Reaching the cheatcode "
            "precompile from an attack means the attack is not something a real attacker "
            "could perform. Build the world in deploy_code instead."
        )
    if not match:
        return
    raise ValueError(
        f"{field} calls vm.{match.group(1) or match.group(2)}, which forges something "
        "a real attacker "
        "cannot have. An attacker standing in front of a deployed contract cannot become "
        "its owner, cannot write its storage and cannot mint themselves a balance -- so "
        "an attack that does is not an attack, and a harm it produces is not a "
        "vulnerability. Set the world up in deploy_code, where cheatcodes ARE allowed, "
        "and then attack it with nothing but calls anybody could make. "
        "vm.warp and vm.roll stay available everywhere, because waiting is something "
        "an attacker really can do."
    )


_PREAMBLE_RE = re.compile(
    "^" + SP + "*(?://" + SP + "*SPDX-License-Identifier:[^" + NL + "]*"
    "|pragma" + SP + "+[^;]*;|import" + SP + "+[^;]*;)" + SP + "*$",
    re.MULTILINE,
)


def strip_preamble(fragment: str) -> str:
    """Remove a file header the agent added to a fragment that is not a file.

    The harness owns the pragma, the licence line and the imports; a fragment that
    repeats them produces "Multiple SPDX license identifiers" or a duplicate pragma and
    the exploit never runs. Nine failures across two runs, every one of them a recall
    loss for a reason that has nothing to do with the attack.
    """
    return _PREAMBLE_RE.sub("", fragment or "")


def _reject_halting(fragment: str, field: str) -> None:
    """Refuse an instruction that ends the test before the harness can measure anything.

    The sentinel return already catches this -- a halted body returns no data and the
    decode reverts -- but the compiler error that produces says nothing useful. Naming it
    here turns a mysterious failure into a fixable one, and points at the technique that
    does work, since forcing ether into a contract is a legitimate attack.
    """
    if _HALTING_RE.search(fragment or ""):
        raise ValueError(
            f"{field} calls selfdestruct directly. That halts the test at that line, so "
            "every harness check below it is skipped -- it does not satisfy the "
            "predicate, it escapes it. To force ether into the target, do it from a "
            "helper contract declared in attacker_code:\n"
            "  contract Bomb { constructor(address t) payable { "
            "selfdestruct(payable(t)); } }\n"
            "then in deploy_code:  new Bomb{value: 1 ether}(address(target));"
        )


def _first_error(output: str) -> str:
    """The first compiler diagnostic that says something, for the run record.

    `Error: Compiler run failed:` is forge's banner, not a diagnostic -- it was 79 of the
    111 recorded failures and told us nothing about any of them. The numbered solc error
    underneath is the one worth keeping.
    """
    lines = [ln.strip() for ln in output.splitlines()]
    for line in lines:
        if re.match(r"Error \(\d+\)", line):
            return line[:200]
    for line in lines:
        if line.startswith("Error") and "Compiler run failed" not in line:
            return line[:200]
    return next((ln for ln in reversed(lines) if ln), "")[:200]


# The exploit test. Everything outside the agent-supplied holes is fixed, so the success
# condition is the same sentence for every sample, every predicate and every model.
_EXPLOIT_TEMPLATE = """// SPDX-License-Identifier: Apache-2.0
pragma solidity {pragma};

import "{target_import}";{extra_imports}
import "./Vm.sol";

interface _ArbiterToken {{ function balanceOf(address) external view returns (uint256); }}

{error_decl}
{attacker_code}

contract TestArbiterExploit is Harness {{
    bytes32 internal constant ARB_COMPLETED = keccak256("arbiter.predicate.reached");

    /// The exploit runs one call deeper than the test, and the test only passes if that
    /// call RETURNS the sentinel. forge reports a test as passing whenever it does not
    /// revert, and several EVM instructions -- selfdestruct above all -- halt execution
    /// and return success. Measured on a real repository: an "exploit" put
    /// `selfdestruct(payable(address(target)))` in its setup, execution stopped there,
    /// every harness check below it was skipped, and forge printed [PASS]. The predicate
    /// had not been satisfied; it had never run. A halted body returns no data, so the
    /// decode below reverts and the test fails, which is the correct outcome.
    function testArbiterExploit() public {{
        require(
            this.arbiterRun() == ARB_COMPLETED,
            "ARBITER: execution halted before the harness predicate ran"
        );
    }}

    function arbiterRun() external returns (bytes32) {{
        // ---- agent-supplied deployment and scenario setup ----
        {deploy_code}
{setup}
{check}
        return ARB_COMPLETED;
    }}
}}
"""

# Contract-driven attacker: funded first, so spending its own money cannot pass.
_ATTACKER_SETUP = """        Attacker atk = new Attacker(address(target));
        vm.deal(address(atk), {funding_wei});
        address atkEoa = address(uint160(uint256(keccak256("arbiter.attacker"))));
        vm.deal(atkEoa, {funding_wei});"""

# EOA-driven attacker. Needed because a great many real guards are written as
# `require(msg.sender == tx.origin)`, which makes a contract attacker structurally
# impossible -- V2 of the evaluation set is exactly that, and no contract-based harness
# could ever prove it. vm.startPrank with two arguments sets msg.sender AND tx.origin,
# so the calls arrive exactly as they would from a real externally owned account.
_EOA_SETUP = """        address eoa = address(uint160({eoa_addr}));
        vm.deal(eoa, {funding_wei});"""

_PROFIT_CONTRACT_BODY = """        uint256 pre = {measure_pre};
        atk.attack();
        uint256 post = {measure_post};
        require(post > pre, "ARBITER: attacker did not profit");"""

_PROFIT_EOA_BODY = """        uint256 pre = {measure_pre};
        vm.startPrank(eoa, eoa);
{attack_body}
        vm.stopPrank();
        uint256 post = {measure_post};
        require(post > pre, "ARBITER: attacker did not profit");"""

_EOA_ACTION = """        vm.startPrank(eoa, eoa);
{attack_body}
        vm.stopPrank();"""

# Did privileged state move when an unprivileged account acted? Read through a
# staticcall before and after, so any public view function works and the harness never
# needs to know the contract's type.
_STATE_CHANGE_BODY = """        (bool ok0, bytes memory v0) =
            address(target).staticcall(abi.encodeWithSignature("__GETTER__"));
        require(ok0, "ARBITER: observed_getter did not execute");

        // First establish that the state named really is privileged: an ordinary user
        // running the intended happy path must NOT be able to move it. Without this the
        // predicate accepts any mutation at all, which is how a patched sample was
        // reported as vulnerable for "changing" coverageRatio() -- a view over the
        // contract balance that ordinary staking moves too.
        address ctrl = address(uint160(uint256(keccak256("arbiter.control"))));
        vm.deal(ctrl, 10000000000000000000);
        vm.startPrank(ctrl, ctrl);
__HONEST__
        vm.stopPrank();
        (bool ok1, bytes memory v1) =
            address(target).staticcall(abi.encodeWithSignature("__GETTER__"));
        require(ok1, "ARBITER: observed_getter did not execute after the honest path");
        require(
            keccak256(v0) == keccak256(v1),
            "ARBITER: ordinary use already moves this state, so it is not privileged"
        );

__ACTION__
        (bool ok2, bytes memory v2) =
            address(target).staticcall(abi.encodeWithSignature("__GETTER__"));
        require(ok2, "ARBITER: observed_getter did not execute after the attack");
        require(
            keccak256(v1) != keccak256(v2),
            "ARBITER: privileged state did not change"
        );"""


# Honest baseline first, attack second, and the attack has to win. `ctrl` and the
# attacker get the same funding, so the comparison is between what the contract gives an
# ordinary user and what it gives someone trying to break it. Gains are computed with a
# guard against underflow, because an honest path that loses money is legitimate.
_PROFIT_BODY = """        address ctrl = address(uint160(uint256(keccak256("arbiter.control"))));
        vm.deal(ctrl, 10000000000000000000);
        uint256 ctrlPre = {measure_ctrl};
        vm.startPrank(ctrl, ctrl);
{honest_body}
        vm.stopPrank();
        uint256 ctrlPost = {measure_ctrl};
        uint256 honestGain = ctrlPost > ctrlPre ? ctrlPost - ctrlPre : 0;

{setup}
        uint256 atkPre = {measure_atk};
        // What the contract under audit is holding, immediately before the attack.
        uint256 tgtPre = {measure_drained};
{attack_action}
        uint256 atkPost = {measure_atk};
        uint256 attackGain = atkPost > atkPre ? atkPost - atkPre : 0;
        uint256 tgtPost = {measure_drained};

        // The value must have come OUT OF the contract under audit. Without this, an
        // agent can satisfy a profit predicate entirely inside scenery it wrote itself:
        // measured on a real repository, an "exploit" deployed a mock redeemer whose
        // only behaviour was to transfer tokens on request, funded it, and then drained
        // it -- the contract under audit was never touched, and the differential passed
        // because the honest baseline had been pointed at a third address and gained
        // nothing. A finding about a contract has to be a finding about that contract.
        //
        // It applies only when the contract did not end up HOLDING MORE. A stale-oracle
        // attack deposits overvalued collateral and borrows real value against it: the
        // target's holdings of the measured asset rise while it is being robbed. Treating
        // that as "no drain" cost a real finding, and the honest reading is that this
        // test cannot speak there rather than that it failed. Equal holdings still fail,
        // which is what catches profit drawn from scenery.
{drain_report}

        // Both quantities reach the agent, not just a verdict. "did not satisfy the
        // predicate" told it nothing it could act on; the actual pair of numbers tells
        // it whether the attack extracted nothing at all, or extracted something and was
        // outrun by an over-generous honest baseline.
{fail_report}"""

# Custom errors arrived in 0.8.4. Above it the two quantities travel in the revert data
# and forge decodes them; below it they are rendered into the revert string instead, so a
# contract pinned to 0.6 or 0.7 gets the same feedback rather than no harness at all.
_FAIL_CUSTOM_ERROR = """        if (attackGain <= honestGain) {
            revert ArbiterNoGain(honestGain, attackGain);
        }"""

_FAIL_REQUIRE = """        if (attackGain <= honestGain) {
            revert(string(abi.encodePacked(
                "ArbiterNoGain(honestGain=", _u(honestGain),
                ", attackGain=", _u(attackGain), ")"
            )));
        }"""

_ERROR_DECLS = (
    "error ArbiterNoGain(uint256 honestGain, uint256 attackGain);\n"
    "error ArbiterNotDrained(uint256 targetBefore, uint256 targetAfter, "
    "uint256 attackGain);\n"
)

_NOT_DRAINED_CUSTOM_ERROR = """        if (attackGain > 0 && tgtPost <= tgtPre && tgtPre - tgtPost < attackGain) {
            revert ArbiterNotDrained(tgtPre, tgtPost, attackGain);
        }"""

# Pre-0.8.4 has no custom errors, so the same two quantities travel in the revert string.
_NOT_DRAINED_REQUIRE = """        if (attackGain > 0 && tgtPost <= tgtPre && tgtPre - tgtPost < attackGain) {
            revert(string(abi.encodePacked(
                "ArbiterNotDrained(targetBefore=", _u(tgtPre),
                ", targetAfter=", _u(tgtPost),
                ", attackGain=", _u(attackGain), ")"
            )));
        }"""


# Denial of service is a real vulnerability class that no profit predicate can express:
# the attacker gains nothing, the protocol simply stops working. The benchmark contains
# such a pair, and admission had certified it under a relaxed baseline while the agent
# was being held to a stricter one -- so the harness, not the contract, was refusing a
# provable finding. The differential form is the definition of the bug: an operation
# that an ordinary user could complete before the attack must fail after it.
_LIVENESS_BODY = """        address live = address(uint160(uint256(keccak256("arbiter.liveness"))));
        vm.deal(live, 10000000000000000000);
        vm.prank(live, live);
        (bool okBefore, ) = address(target).call(__CALL__);
        require(
            okBefore,
            "ARBITER: the honest operation already fails before the attack"
        );

__ACTION__

        vm.prank(live, live);
        (bool okAfter, ) = address(target).call(__CALL__);
        require(
            !okAfter,
            "ARBITER: the honest operation still succeeds after the attack, so "
            "availability was not broken"
        );"""
