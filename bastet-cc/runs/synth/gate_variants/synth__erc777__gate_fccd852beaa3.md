# ERC777-Callback-Reentrancy

## Detection prompt

You are a smart contract auditor. After reading the following vulnerability knowledge and detection checks, examine the contract code for this specific class of issue.

### Vulnerability Knowledge

**ERC777-Callback-Reentrancy**
ERC777 tokens implement `tokensReceived` and `tokensToSend` hooks that execute arbitrary recipient code during `transfer`, `send`, and `operatorSend`. If a contract performs sensitive state updates (balance accounting, debt reduction, flow limits, command execution flags) after the external call that triggers the hook, a malicious recipient can re-enter the same or a related function and observe stale state. This violates the Checks-Effects-Interactions pattern. The vulnerability manifests in three common forms: (1) measuring received amounts by balance delta after `safeTransferFrom` -- an ERC777 `tokensToSend` hook can re-enter a withdrawal function that changes the contract's balance, inflating the calculated amount; (2) transferring tokens before updating internal accounting (`_addFlowIn`, debt ledgers, executed-command markers), allowing the callback to re-enter and manipulate the pre-update state; (3) calling an unprotected virtual/external function after the transfer, enabling cross-function reentrancy into payout or withdrawal logic. A `nonReentrant` modifier on the entry function does not protect against cross-function reentrancy if the reentrant target lacks the same guard.

### Detection Checks

1. External token transfer (`safeTransferFrom`, `transfer`, `send`, `operatorSend`, `_giveToken`, `_transferFromExecutor`) occurs before critical state updates (balance accounting, debt reduction, flow limits, executed-command markers).
2. Received amount is calculated as `balanceOf(address(this)) - prevBalance` after a `safeTransferFrom` call without protecting the balance measurement from intermediate changes via reentrancy.
3. A `nonReentrant` modifier is present on the entry function but the reentrancy target (e.g., `withdrawReserves`, `_executeWithToken`, payout function) does not share the same reentrancy guard.
4. Virtual or external function (`_executeWithToken`, `_giveToken`, callback) is invoked after the token transfer without ensuring state is fully settled.
5. Flow limit or debt accounting (`_addFlowIn`, `reserveDebt[token][msg.sender] -= received`, `totalDebt[token] -= received`) is performed after the external call that can trigger ERC777 hooks.
6. Command execution flag (`_setExpressExecutorWithToken`, `gateway.isCommandExecuted`) is set after the token transfer, allowing reentrant execution of the same command.
7. Token transfer uses a low-level call or `call`/`delegatecall` pattern that forwards gas to the recipient, enabling arbitrary callback logic.
8. Contract assumes ERC20 `transfer`/`transferFrom` cannot re-enter and omits `nonReentrant` on functions that handle ERC777-compatible tokens.

### Examples

#### Example 1: Incorrect Example

```solidity
function repayLoan(IERC20 token, uint256 amount) external nonReentrant {
    if (reserveDebt[token][msg.sender] == 0) revert NoDebt();
    uint256 prevBalance = token.balanceOf(address(this));
    token.safeTransferFrom(msg.sender, address(this), amount);
    uint256 received = token.balanceOf(address(this)) - prevBalance;
    reserveDebt[token][msg.sender] -= received;
    totalDebt[token] -= received;
    emit DebtRepaid(token, msg.sender, received);
}
```

Balance-delta measurement after `safeTransferFrom` lets an ERC777 `tokensToSend` hook re-enter `withdrawReserves` and alter the contract's balance, inflating `received` and understating debt.

#### Example 2: Correct Example

```solidity
function repayLoan(IERC20 token, uint256 amount) external nonReentrant {
    if (reserveDebt[token][msg.sender] == 0) revert NoDebt();
    token.safeTransferFrom(msg.sender, address(this), amount);
    uint256 received = amount; // trust the requested amount or use a pull pattern
    reserveDebt[token][msg.sender] -= received;
    totalDebt[token] -= received;
    emit DebtRepaid(token, msg.sender, received);
}
```

Remove balance-delta accounting; use the requested `amount` (or a pull-payment pattern) and update state before any external call, eliminating reentrancy surface.

### Task to Perform
Apply each detection check above to every contract function provided. Report only concrete instances of this vulnerability class, citing the specific check that failed and the offending lines.

### Output Format
If NO concrete vulnerability found, output a empty array
