# ERC777-Callback-Reentrancy

## Detection prompt

You are a smart contract auditor. After reading the following vulnerability knowledge and detection checks, examine the contract code for this specific class of issue.

### Vulnerability Knowledge

**ERC777-Callback-Reentrancy**
ERC777 tokens implement `tokensReceived` and `tokensToSend` hooks that execute arbitrary external code during `transfer`, `send`, or `operatorSend` calls. If a contract performs sensitive state updates (balance accounting, debt reduction, storage cleanup) after initiating an ERC777 transfer but before the hook returns, a malicious token or recipient can reenter the same or a related function, corrupting internal accounting. The Checks-Effects-Interactions pattern requires all state mutations to complete before any external call. Additionally, reverting inside a hook (e.g., to block a transfer) can permanently stall protocols that lack a fallback or timeout, causing denial-of-service for asset recovery or rental termination flows.

### Detection Checks

1. Token transfer (safeTransferFrom, transfer, send, operatorSend) occurs before state variables such as balances, debt, or rental mappings are updated.
2. Received amount is calculated by reading token.balanceOf(address(this)) after the transfer, which an ERC777 tokensToSend hook can manipulate via reentrancy into a withdrawal or mint function.
3. External calls to settlement or escrow contracts (e.g., settlePayment) that may transfer ERC777 tokens happen before storage cleanup (e.g., removeRentals), allowing a hook revert to block cleanup permanently.
4. Hook validation (e.g., STORE.hookOnStop) is performed immediately before the external hook call without a mechanism to disable or skip hooks after rental creation, so a governance change can brick existing rentals.
5. Missing nonReentrant modifier on functions that initiate ERC777 transfers while also reading mutable state after the transfer.
6. Use of try/catch around hook calls that catches reverts but does not guarantee subsequent state updates execute, leaving the protocol in an inconsistent state if the hook fails.
7. Callbacks are invoked while the contract still holds "dirty" state (e.g., rentalAssetUpdates accumulator in memory) that the reentrant call may also rely on.
8. No deadline or fallback mechanism for hook execution, so a single malicious hook can indefinitely lock assets.

### Examples

#### Example 1: Incorrect Example

```solidity
function repayLoan(ERC20 token, uint256 amount) external {
    uint256 prevBalance = token.balanceOf(address(this));
    token.safeTransferFrom(msg.sender, address(this), amount);
    uint256 received = token.balanceOf(address(this)) - prevBalance;
    reserveDebt[token][msg.sender] -= received;
    totalDebt[token] -= received;
}
```

The function measures received tokens by balance difference after safeTransferFrom, but an ERC777 tokensToSend hook can reenter a withdrawal function that alters the contract's token balance, inflating `received` and understating the borrower's debt.

#### Example 2: Correct Example

```solidity
function repayLoan(ERC20 token, uint256 amount) external nonReentrant {
    token.safeTransferFrom(msg.sender, address(this), amount);
    reserveDebt[token][msg.sender] -= amount;
    totalDebt[token] -= amount;
}
```

State updates use the trusted `amount` parameter instead of a post-transfer balance check, and the nonReentrant modifier prevents reentrancy during the external transfer.

### Task to Perform
Apply each detection check above to every contract function provided. Report only concrete instances of this vulnerability class, citing the specific check that failed and the offending lines.

### Output Format
If NO concrete vulnerability found, output a empty array
