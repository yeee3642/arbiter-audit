# ERC777-Reentrancy-and-Callback-Hazards

## Detection prompt

You are a smart contract auditor. After reading the following vulnerability knowledge and detection checks, examine the contract code for this specific class of issue.

### Vulnerability Knowledge

**ERC777-Reentrancy-and-Callback-Hazards**
ERC777 tokens implement `tokensToSend` and `tokensReceived` hooks that execute arbitrary external code during `transfer`, `send`, and `operatorSend` operations. These hooks fire *before* state changes inside the token contract are finalized, enabling reentrancy into the calling contract. A vulnerable pattern measures received amounts by snapshotting `balanceOf(this)` before and after `safeTransferFrom`; an ERC777 `tokensToSend` hook can reenter a different function (e.g., `swap` → `withdrawReserves`) that alters the contract's token balance, inflating the calculated `received` value. Another pattern violates Checks-Effects-Interactions by performing external transfers (via `settlePayment`, `_safeTransfer`, or hook calls like `onStop`) *before* updating critical storage (e.g., `removeRentals`, debt accounting). If the recipient is an ERC777 token, its `tokensReceived` hook can revert, causing a permanent DoS that locks assets because the cleanup state change never occurs. A third pattern validates hook permissions (e.g., `STORE.hookOnStop(target)`) at execution time rather than at registration; if governance disables a hook after rental creation, `stopRent` reverts with `DisabledHook`, again preventing cleanup. All three patterns share the root cause: state mutations that must be atomic with the transfer are sequenced after the external call, or the transfer amount is derived from a balance delta that a callback can manipulate.

### Detection Checks

1. Function snapshots `balanceOf(address(this))` before an ERC20/ERC777 `transferFrom`/`safeTransferFrom` and computes received amount as `balanceOf(address(this)) - prevBalance` after the call, without a reentrancy guard that also covers cross-function entry points (e.g., missing `nonReentrant` on the reentered function or using a different mutex).
2. External token transfer (`safeTransfer`, `safeTransferFrom`, `transfer`, `send`, `operatorSend`, or a wrapper like `settlePayment`/`_safeTransfer`) occurs before storage updates that finalize the operation (e.g., `removeRentals`, debt decrement, rental removal, hook deregistration).
3. Hook or callback invocation (`IHook(target).onStop`, `IERC777Sender.tokensToSend`, `IERC777Recipient.tokensReceived`, or any low-level `call` to a user-supplied address) is performed before the corresponding state cleanup (removing rental records, clearing debt, marking hooks disabled).
4. Permission check for a hook (`STORE.hookOnStop`, `hookOnTransfer`, etc.) reads a mutable registry at execution time instead of using an immutable allowlist or a snapshot taken at rental/order creation; a governance change can flip the flag to false and cause a revert that blocks cleanup.
5. Function lacks `nonReentrant` modifier *or* the modifier uses a mutex that is not shared with the function reachable via the ERC777 callback (cross-function reentrancy).
6. Revert inside a `try/catch` block around a hook call bubbles up a custom error (e.g., `Errors.Shared_DisabledHook`, `Errors.Shared_HookFailString`) that halts the outer function before state cleanup runs.
7. Token transfer uses a generic `safeTransfer`/`_safeTransfer` helper that does not restrict to non-hooking ERC20 (e.g., no `IERC1820Registry` check for `ERC777TokensSender`/`ERC777TokensRecipient` interfaces) and the caller assumes no callback will occur.
8. State variable updated after external call is a mapping or array element critical for asset accounting (e.g., `reserveDebt[token][user]`, `totalDebt[token]`, rental storage), and the update is not idempotent or guarded against reentry.

### Examples

#### Example 1: Incorrect Example

```solidity
function repayLoan(IERC20 token, uint256 amount) external nonReentrant {
    uint256 prevBal = token.balanceOf(address(this));
    token.safeTransferFrom(msg.sender, address(this), amount);
    uint256 received = token.balanceOf(address(this)) - prevBal; // ERC777 tokensToSend can reenter swap() → withdrawReserves() and change balance
    reserveDebt[token][msg.sender] -= received;
    totalDebt[token] -= received;
}
```

Balance-delta accounting after `safeTransferFrom` is manipulated by an ERC777 `tokensToSend` hook that reenters a different function and withdraws reserves, inflating `received`.

#### Example 2: Correct Example

```solidity
function repayLoan(IERC20 token, uint256 amount) external nonReentrant {
    token.safeTransferFrom(msg.sender, address(this), amount);
    // Use the *requested* amount (or a minAmount parameter) instead of balance delta.
    // If exact accounting is needed, pull the exact amount via a trusted oracle or require token to be non-hooking.
    reserveDebt[token][msg.sender] -= amount;
    totalDebt[token] -= amount;
}
```

Accounting uses the caller-specified `amount` (validated upstream) rather than a post-transfer balance delta, eliminating the reentrancy surface.

### Task to Perform
Apply each detection check above to every contract function provided. Report only concrete instances of this vulnerability class, citing the specific check that failed and the offending lines.

### Output Format
If NO concrete vulnerability found, output a empty array
