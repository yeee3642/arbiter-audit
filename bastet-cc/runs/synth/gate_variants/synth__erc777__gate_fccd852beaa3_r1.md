# ERC777-Reentrancy-CEI-Violation

## Detection prompt

You are a smart contract auditor. After reading the following vulnerability knowledge and detection checks, examine the contract code for this specific class of issue.

### Vulnerability Knowledge

**ERC777-Reentrancy-CEI-Violation**
ERC777 tokens implement `tokensToSend` (sender-side) and `tokensReceived` (recipient-side) hooks that execute arbitrary external code during `transfer`, `send`, or `operatorSend`. If a contract performs sensitive state updates — such as debt accounting, flow limits, command-execution flags, or balance-delta calculations — *after* the token transfer but *before* the hook returns, a malicious recipient or sender can re-enter the same or a related function and manipulate the contract's state. The classic Checks-Effects-Interactions (CEI) pattern is violated when the external call (the transfer) precedes the effect (state update). Even a `nonReentrant` modifier on the entry function does not protect against cross-function reentrancy if the reentrant path enters through a different unprotected function (e.g., `withdrawReserves`, `swap`, or a virtual `_executeWithToken`). Balance-delta measurements (`balanceAfter - balanceBefore`) are especially fragile because the hook can call back into the protocol and change the contract's token balance before the delta is computed.

### Detection Checks

1. External ERC20/ERC777 transfer (`safeTransferFrom`, `transfer`, `transferFrom`, `send`, `operatorSend`, or low-level `call`) occurs before the function updates the primary accounting state (debt ledgers, flow limits, executed-command flags, executor mappings, etc.).
2. The function calculates a received or sent amount by reading the token balance before and after the transfer (`balanceOf(address(this)) - prevBalance`) without preventing intermediate balance changes via reentrancy.
3. A virtual or internal function (`_executeWithToken`, `_giveToken`, `_transferFromExecutor`, etc.) that can be overridden or called from elsewhere is invoked after the transfer, enabling cross-function reentrancy into an unprotected entry point.
4. The function lacks a `nonReentrant` guard *and* the state update that should prevent double-spending (e.g., `reserveDebt[token][msg.sender] -= received`, `_addFlowIn`, `_setExpressExecutorWithToken`, `isCommandExecuted` check) is placed after the external call.
5. An ERC777 hook (`tokensReceived` / `tokensToSend`) can trigger a callback into a different public/external function of the same contract that mutates the same state variables used in the current execution (cross-function reentrancy).
6. The contract uses `safeTransferFrom` or `safeTransfer` with an ERC20 interface but the underlying token may be ERC777; the detector must treat any `IERC20` transfer as a potential hook trigger.
7. State variables that act as reentrancy locks (e.g., `commandExecuted[commandId]`, `expressExecutorSet[commandId]`, `flowLimitReached`) are set *after* the token transfer instead of before.
8. The function performs a transfer to `address(this)` (deposit) or from `address(this)` (withdrawal) and subsequently relies on the post-transfer balance for accounting without snapshotting the balance *after* all possible reentrant paths have been sealed.

### Examples

#### Example 1: Incorrect Example

```solidity
function repayLoan(IERC20 token, uint256 amount) external nonReentrant {
    uint256 before = token.balanceOf(address(this));
    token.safeTransferFrom(msg.sender, address(this), amount);
    uint256 received = token.balanceOf(address(this)) - before; // ERC777 tokensToSend can re-enter
    debt[msg.sender] -= received; // state update after transfer
}
```

Balance-delta measurement wraps an unguarded `safeTransferFrom`; an ERC777 `tokensToSend` hook can re-enter `withdrawReserves` or `swap`, altering the contract's balance before `received` is computed, inflating the credited amount.

#### Example 2: Correct Example

```solidity
function repayLoan(IERC20 token, uint256 amount) external nonReentrant {
    uint256 before = token.balanceOf(address(this));
    token.safeTransferFrom(msg.sender, address(this), amount);
    uint256 received = token.balanceOf(address(this)) - before;
    // Reentrancy guard on *this* function is not enough; move state update before any external call
    // or use a mutex that covers all entry points (cross-function protection).
    // Correct pattern: update state *before* transfer when possible, or use pull-payment.
    debt[msg.sender] -= received;
    // If transfer must stay first, ensure no other function can mutate `debt` or `totalDebt`
    // while this frame is open (e.g., global `nonReentrant` on all entry points).
}
```

The fix either reorders to update state before the transfer (when business logic allows) or applies a contract-wide reentrancy guard so that no callback — even through a different function — can mutate the accounting state until the current execution finishes.

### Task to Perform
Apply each detection check above to every contract function provided. Report only concrete instances of this vulnerability class, citing the specific check that failed and the offending lines.

### Output Format
If NO concrete vulnerability found, output a empty array
