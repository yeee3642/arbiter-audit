# ERC777-Reentrancy-CEI-Violation

## Detection prompt

You are a smart contract auditor. After reading the following vulnerability knowledge and detection checks, examine the contract code for this specific class of issue.

### Vulnerability Knowledge

**ERC777-Reentrancy-CEI-Violation**
ERC777 tokens implement `tokensToSend` (on the sender) and `tokensReceived` (on the recipient) hooks that execute arbitrary external code during `transfer`, `send`, or `operatorSend`. If a contract performs an ERC777 transfer before updating its own accounting state (violating Checks-Effects-Interactions), the hook can reenter the same or a related function and observe stale balances, double-count deposits, or bypass access controls. Balance-delta accounting (`balanceAfter - balanceBefore`) is especially dangerous because a `tokensToSend` hook can call back into the protocol and mutate the contract's token balance mid-execution, inflating the calculated amount. Even `nonReentrant` modifiers only protect the specific function they guard; cross-function reentrancy via a different entry point (e.g., `withdrawReserves`, `swap`, `executeWithToken`) remains possible. Safe patterns: (1) update all internal state (debt, flow limits, executor mappings) *before* any external token transfer, (2) use the `amount` parameter passed by the caller instead of measuring balance deltas, (3) guard all entry points that touch the same accounting with a shared reentrancy lock, and (4) prefer `IERC20.transfer`/`transferFrom` for non-hook tokens or implement a `ReentrancyGuard` that covers the entire call cluster.

### Detection Checks

1. External ERC777 transfer (safeTransferFrom, transfer, send, operatorSend, _giveToken, _transferFromExecutor) occurs before internal state updates (debt subtraction, flow accounting, executor mapping, command execution flag).
2. Received amount is calculated as `token.balanceOf(address(this)) - prevBalance` after a transfer from an untrusted sender, enabling inflation via tokensToSend hook reentrancy.
3. Virtual or unprotected function (_executeWithToken, _giveToken) is called after token transfers, allowing reentrant invocation through ERC777 hooks.
4. nonReentrant modifier is present on the entry function but the reentrancy path enters through a different public/external function that shares the same accounting state.
5. Token transfer uses safeTransferFrom/transferFrom on an address that may implement IERC777Sender/IERC777Recipient without a reentrancy guard covering all related state mutations.
6. Flow limit or debt accounting (_addFlowIn, reserveDebt update, totalDebt update) is performed after the external call that can trigger tokensReceived/tokensToSend.
7. Executor or caller receives value (via _transferFromExecutor or direct transfer) before the command/execution is marked as completed/processed.
8. Contract calls an external function (contractCallWithTokenValue, gateway interaction) that can transfer ERC777 tokens before setting a processed flag (isCommandExecuted, _setExpressExecutorWithToken).

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

Balance-delta measurement after safeTransferFrom lets an ERC777 tokensToSend hook reenter withdrawReserves, altering the contract's balance and inflating 'received'; debt accounting occurs after the transfer, violating CEI.

#### Example 2: Correct Example

```solidity
function repayLoan(ERC20 token_, uint256 amount_) external nonReentrant {
    if (reserveDebt[token_][msg.sender] == 0) revert NoDebt();
    uint256 received = amount_;
    reserveDebt[token_][msg.sender] -= received;
    totalDebt[token_] -= received;
    token_.safeTransferFrom(msg.sender, address(this), received);
    emit DebtRepaid(token_, msg.sender, received);
}
```

State updates (debt subtraction) happen before the external transfer; the caller-specified amount is used instead of a balance delta, eliminating reentrancy inflation.

### Task to Perform
Apply each detection check above to every contract function provided. Report only concrete instances of this vulnerability class, citing the specific check that failed and the offending lines.

### Output Format
If NO concrete vulnerability found, output a empty array
