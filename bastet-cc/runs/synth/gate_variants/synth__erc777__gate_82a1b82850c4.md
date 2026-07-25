# ERC777-Callback-Reentrancy

## Detection prompt

You are a smart contract auditor. After reading the following vulnerability knowledge and detection checks, examine the contract code for this specific class of issue.

### Vulnerability Knowledge

**ERC777-Callback-Reentrancy**
ERC777 tokens implement `tokensReceived` and `tokensToSend` hooks that execute arbitrary recipient code during `transfer`, `send`, and `operatorSend`. If a contract performs sensitive state updates (accounting, flow limits, rental cleanup, escrow settlement) after the external call that moves ERC777 tokens, a malicious recipient can re-enter the same or a related function and observe stale state. This violates the Checks-Effects-Interactions pattern: the external call is the interaction, but the effect (state update) happens later. Common manifestations include recording flow limits after `_giveToken`, paying out an executor before calling an unprotected virtual `_executeWithToken`, settling escrow payments before removing rental records, or calling hooks that may revert and block cleanup. The fix is to complete all state changes before any external call that can transfer ERC777 tokens, or to guard the entry point with a `nonReentrant` modifier.

### Detection Checks

1. External call that transfers tokens (e.g., `_giveToken`, `_transferFromExecutor`, `safeTransfer`, `settlePayment`, `_reclaimRentedItems`) occurs before state updates that depend on the transfer outcome (flow accounting, executor registration, rental removal, hook disabling).
2. Function lacks `nonReentrant` modifier while performing token transfers followed by state changes or nested external calls.
3. State variable updated after low-level call or `safeTransfer`/`safeTransferFrom` to an address that may implement `IERC777Recipient`.
4. Virtual or internal function (`_executeWithToken`, `_removeHooks`, `_giveToken`) called after token transfer without reentrancy guard, allowing cross-function reentrancy into the same entry point.
5. Hook or callback invocation (`onStop`, `tokensReceived`) that can revert and prevent subsequent cleanup (`removeRentals`, `_addFlowIn`) from executing.
6. Accounting logic (`_addFlowIn`, `_setExpressExecutorWithToken`, `STORE.removeRentals`) placed after the interaction instead of before.
7. Use of `try/catch` around hook calls that swallows reverts but leaves state inconsistent if the hook was meant to gate further actions.
8. Token transfer amount derived from user input or external call return value and used in later accounting without re-validation after the callback.

### Examples

#### Example 1: Incorrect Example

```solidity
function giveToken(address destinationAddress, uint256 amount) external onlyService returns (uint256) {
    amount = _giveToken(destinationAddress, amount); // may trigger tokensReceived
    _addFlowIn(amount); // accounting after interaction
    return amount;
}

function _giveToken(address to, uint256 amount) internal returns (uint256) {
    IERC20(token).safeTransfer(to, amount);
    return amount;
}
```

Flow accounting `_addFlowIn` runs after `_giveToken`, which can trigger an ERC777 `tokensReceived` callback; the recipient can re-enter `giveToken` and manipulate its balance before the flow is recorded.

#### Example 2: Correct Example

```solidity
function giveToken(address destinationAddress, uint256 amount) external onlyService nonReentrant returns (uint256) {
    _addFlowIn(amount); // accounting first
    amount = _giveToken(destinationAddress, amount); // then transfer
    return amount;
}

function _giveToken(address to, uint256 amount) internal returns (uint256) {
    IERC20(token).safeTransfer(to, amount);
    return amount;
}
```

State update `_addFlowIn` executes before the external token transfer, and `nonReentrant` prevents reentrant calls from observing intermediate state.

### Task to Perform
Apply each detection check above to every contract function provided. Report only concrete instances of this vulnerability class, citing the specific check that failed and the offending lines.

### Output Format
If NO concrete vulnerability found, output a empty array
