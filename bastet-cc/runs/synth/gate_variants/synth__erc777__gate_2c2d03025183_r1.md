# ERC777-Callback-Reentrancy-and-CEI-Violation

## Detection prompt

You are a smart contract auditor. After reading the following vulnerability knowledge and detection checks, examine the contract code for this specific class of issue.

### Vulnerability Knowledge

**ERC777-Callback-Reentrancy-and-CEI-Violation**
ERC777 tokens implement `tokensToSend` and `tokensReceived` hooks that execute arbitrary external code during `transfer`, `send`, or `operatorSend` operations. These hooks fire *before* state changes in the token contract (for `tokensToSend`) or *after* the transfer but *before* the caller regains control (for `tokensReceived`). A contract that performs sensitive calculations (e.g., balance-delta accounting) or state updates *before* the external call, or that makes external calls (transfers, hook invocations) *before* completing all internal state changes (storage cleanup, debt accounting, access-control updates), violates the Checks-Effects-Interactions pattern. An attacker controlling the ERC777 token or the recipient can reenter the vulnerable contract (cross-function reentrancy) or revert inside the hook to block cleanup, permanently locking assets. The presence of `nonReentrant` on the entry function does not protect against cross-function reentrancy via a different entry point (e.g., `withdrawReserves`), nor does it prevent a hook revert from halting subsequent state updates.

### Detection Checks

1. Balance-delta accounting: code reads `token.balanceOf(address(this))` before and after a `safeTransferFrom`/`transfer`/`send` call and uses the difference for accounting (debt reduction, credit minting, fee calculation) without ensuring the token is non-ERC777 or using a reentrancy guard that covers all entry points.
2. External call before state cleanup: a function calls an external contract (e.g., `ESCRW.settlePayment`, `IHook(target).onStop`, `token.safeTransferFrom`) that can trigger ERC777 hooks *before* critical storage updates such as `STORE.removeRentals`, debt ledger writes, or access-control flag flips.
3. Hook invocation without disable mechanism: code iterates over user-supplied hooks and calls `IHook(target).onStop` (or similar) after checking `STORE.hookOnStop(target)`, but there is no way to disable or remove hooks after rental/order creation, so a previously approved hook that later returns `false` causes a revert that blocks the entire flow.
4. Missing `nonReentrant` on cross-function entry points: the function uses `nonReentrant` but another public/external function in the same contract (e.g., `withdrawReserves`, `swap`) modifies the same state (token balances, debt mappings) without the same guard, enabling cross-function reentrancy via ERC777 `tokensToSend`.
5. Revert in hook handler bubbles up: a `try/catch` around a hook call catches errors but re-reverts with a custom error, allowing a malicious hook to revert and prevent subsequent state changes (e.g., `STORE.removeRentals` never executes).
6. State update after external call with no compensation: the function updates storage (e.g., `reserveDebt[token][msg.sender] -= received`) *after* the external transfer, so a reentrant call sees stale state and can manipulate the delta calculation.
7. Use of `safeTransferFrom`/`_safeTransfer` on unverified token: the code calls OpenZeppelin `SafeERC20.safeTransferFrom` or internal `_safeTransfer` on a token address that may implement ERC777, without checking `ERC1820_REGISTRY` for `tokensToSend`/`tokensReceived` implementers or using a pull-payment pattern.
8. Callback-sensitive operation in loop: a loop performs external calls (hook invocations, transfers) per iteration and relies on all iterations completing for final cleanup; a single revert in any iteration halts the entire batch.

### Examples

#### Example 1: Incorrect Example

```solidity
function repayLoan(ERC20 token_, uint256 amount_) external nonReentrant {
    if (reserveDebt[token_][msg.sender] == 0) revert NoDebt();
    uint256 prevBalance = token_.balanceOf(address(this));
    token_.safeTransferFrom(msg.sender, address(this), amount_);
    uint256 received = token_.balanceOf(address(this)) - prevBalance;
    reserveDebt[token_][msg.sender] -= received;
    totalDebt[token_] -= received;
    emit DebtRepaid(token_, msg.sender, received);
}
```

Balance-delta accounting after `safeTransferFrom` allows an ERC777 `tokensToSend` hook to reenter `withdrawReserves` (different function, no `nonReentrant`), altering the contract's token balance and inflating `received`, so the borrower repays less than owed.

#### Example 2: Correct Example

```solidity
function repayLoan(ERC20 token_, uint256 amount_) external nonReentrant {
    if (reserveDebt[token_][msg.sender] == 0) revert NoDebt();
    uint256 before = token_.balanceOf(address(this));
    token_.safeTransferFrom(msg.sender, address(this), amount_);
    uint256 after = token_.balanceOf(address(this));
    uint256 received = after - before;
    // Reentrancy guard covers all entry points; alternatively use pull pattern:
    // escrowTokens[msg.sender][token_] += received;
    reserveDebt[token_][msg.sender] -= received;
    totalDebt[token_] -= received;
    emit DebtRepaid(token_, msg.sender, received);
}
```

The `nonReentrant` modifier is applied to *all* functions that touch `reserveDebt`/`totalDebt`/`balanceOf` (e.g., `withdrawReserves` also has `nonReentrant`), preventing cross-function reentrancy; a pull-payment pattern would eliminate balance-delta entirely.

### Task to Perform
Apply each detection check above to every contract function provided. Report only concrete instances of this vulnerability class, citing the specific check that failed and the offending lines.

### Output Format
If NO concrete vulnerability found, output a empty array
