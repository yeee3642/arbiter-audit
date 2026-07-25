# ERC777-Callback-Reentrancy

## Detection prompt

You are a smart contract auditor. After reading the following vulnerability knowledge and detection checks, examine the contract code for this specific class of issue.

### Vulnerability Knowledge

**ERC777-Callback-Reentrancy**
ERC777 tokens implement `tokensReceived` and `tokensToSend` hooks that execute arbitrary recipient code during `transfer`, `send`, or `operatorSend`. If a contract performs sensitive state updates (accounting, debt reduction, flow limits, command execution flags) *after* an external token transfer, a malicious ERC777 recipient can re-enter the same or a related function before those updates complete. This violates the Checks-Effects-Interactions pattern and enables cross-function reentrancy: the callback may call back into `swap`, `withdrawReserves`, `executeWithToken`, or `giveToken` while critical mappings (`reserveDebt`, `totalDebt`, flow accounting, `commandId` execution status) are still stale. Balance-delta accounting (`balanceAfter - balanceBefore`) is especially fragile because the callback can manipulate the contract's token balance mid-execution, inflating the calculated received amount. A `nonReentrant` guard on the entry function does not protect against cross-function reentrancy if the callback targets a different unprotected function that shares state.

### Detection Checks

1. External ERC20/ERC777 transfer (`safeTransferFrom`, `transfer`, `safeTransfer`, `_giveToken`, `_transferFromExecutor`) occurs before critical state updates (debt subtraction, flow accounting, command execution flags, executor mapping writes).
2. Received amount is calculated via post-transfer balance delta (`token.balanceOf(address(this)) - prevBalance`) instead of trusting the input `amount` parameter or using a pull-payment pattern.
3. Missing `nonReentrant` modifier on functions that share mutable state with the transfer entry point (e.g., `withdrawReserves`, `swap`, `_executeWithToken`, `_addFlowIn`).
4. Sensitive state variables (`reserveDebt`, `totalDebt`, flow limits, `commandId` executed flags, `expressExecutor` mappings) are written *after* the external call instead of before.
5. Virtual or internal function (`_executeWithToken`, `_giveToken`, `_addFlowIn`) called after transfer lacks its own reentrancy guard and mutates shared state.
6. Callback-susceptible token addresses are not validated against an allowlist or checked for ERC777 hook implementation (`IERC777Recipient`, `IERC777Sender`).
7. Revert statements inside the callback path (e.g., in `tokensReceived`) can cause DoS for the caller if the contract does not handle transfer failures gracefully.
8. Multiple sequential transfers in one function (e.g., `contractCallWithTokenValue` then `safeTransferFrom`) each open a callback window before any state is finalized.

### Examples

#### Example 1: Incorrect Example

```solidity
function repayLoan(IERC20 token, uint256 amount) external nonReentrant {
    if (reserveDebt[token][msg.sender] == 0) revert NoDebt();
    uint256 prevBal = token.balanceOf(address(this));
    token.safeTransferFrom(msg.sender, address(this), amount);
    uint256 received = token.balanceOf(address(this)) - prevBal;
    reserveDebt[token][msg.sender] -= received;
    totalDebt[token] -= received;
    emit DebtRepaid(token, msg.sender, received);
}
```

Balance-delta accounting after `safeTransferFrom` lets an ERC777 `tokensToSend` hook re-enter `swap`/`withdrawReserves`, altering the contract's balance and inflating `received` before debt is reduced.

#### Example 2: Correct Example

```solidity
function repayLoan(IERC20 token, uint256 amount) external nonReentrant {
    if (reserveDebt[token][msg.sender] == 0) revert NoDebt();
    uint256 debt = reserveDebt[token][msg.sender];
    uint256 repayAmount = amount > debt ? debt : amount;
    reserveDebt[token][msg.sender] -= repayAmount;
    totalDebt[token] -= repayAmount;
    token.safeTransferFrom(msg.sender, address(this), repayAmount);
    emit DebtRepaid(token, msg.sender, repayAmount);
}
```

State updates (debt reduction) happen before the external transfer; the trusted `repayAmount` is used instead of a post-transfer balance delta, eliminating reentrancy and inflation risks.

### Task to Perform
Apply each detection check above to every contract function provided. Report only concrete instances of this vulnerability class, citing the specific check that failed and the offending lines.

### Output Format
If NO concrete vulnerability found, output a empty array
