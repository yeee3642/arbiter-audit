# ERC777-Callback-Reentrancy

## Detection prompt

You are a smart contract auditor. After reading the following vulnerability knowledge and detection checks, examine the contract code for this specific class of issue.

### Vulnerability Knowledge

**ERC777-Callback-Reentrancy**
ERC777 tokens implement `tokensReceived` and `tokensToSend` hooks that are invoked during `transfer`, `send`, and `operatorSend` calls. When a contract performs an ERC777 transfer before updating its own accounting state (balances, flow limits, rental records, command execution flags), the recipient contract can re-enter the vulnerable function or a related function via the hook. This violates the Checks-Effects-Interactions pattern: the external call (Interaction) happens before the state update (Effect). Attackers exploit this to double-spend, inflate balances, bypass flow limits, or lock assets by reverting inside the hook. The vulnerability is amplified when the callback can trigger the same entry point (direct reentrancy) or a different function that shares state (cross-function reentrancy). A `revert` inside `tokensReceived` can also cause a permanent DoS if the caller does not handle the failure gracefully and the state required for cleanup is updated only after the transfer.

### Detection Checks

1. External ERC777 transfer (`safeTransfer`, `safeTransferFrom`, `transfer`, `send`, `operatorSend`, or low-level `call` to an ERC777 address) occurs before the function updates critical storage variables (balances, flow counters, rental mappings, command execution flags).
2. The function lacks a `nonReentrant` modifier (e.g., OpenZeppelin `ReentrancyGuard`) on the entry point and on any other function that reads/writes the same state variables.
3. State variables that track inbound/outbound asset flows (`_addFlowIn`, `_addFlowOut`, balance increments/decrements, `settlePayment` accounting) are written after the external token transfer.
4. A `try/catch` or low-level `call` wraps a hook invocation (`onStop`, `onStart`, generic `ICallback`) but the surrounding function continues execution or reverts in a way that leaves storage inconsistent if the hook reverts.
5. The function calls an external contract (`ESCRW.settlePayment`, `_giveToken`, `_reclaimRentedItems`, `_executeWithToken`) that internally performs ERC777 transfers before the caller finishes its own state updates.
6. A `revert` or custom error is triggered based on a hook registry check (`STORE.hookOnStop`) after the hook was previously enabled, creating a DoS vector if the hook cannot be disabled.
7. The function returns a value derived from the transfer (`amount = _giveToken(...)`) and uses it for subsequent accounting (`_addFlowIn(amount)`), allowing the reentrant call to manipulate the returned amount.
8. Cross-function reentrancy: a virtual/internal function (`_executeWithToken`, `_removeHooks`) called after the transfer can be overridden or invoked directly to re-enter the protocol while the first invocation's state is still stale.

### Examples

#### Example 1: Incorrect Example

```solidity
function giveToken(address destinationAddress, uint256 amount) external onlyService returns (uint256) {
    amount = _giveToken(destinationAddress, amount); // ERC777 transfer -> tokensReceived hook
    _addFlowIn(amount); // state update AFTER interaction
    return amount;
}

function _giveToken(address to, uint256 amount) internal returns (uint256) {
    IERC20(token).safeTransfer(to, amount); // may be ERC777
    return amount;
}
```

The ERC777 transfer in `_giveToken` triggers `tokensReceived` before `_addFlowIn` records the flow, allowing the recipient to re-enter `giveToken` and manipulate its balance or flow accounting.

#### Example 2: Correct Example

```solidity
function giveToken(address destinationAddress, uint256 amount) external onlyService nonReentrant returns (uint256) {
    _addFlowIn(amount); // state update BEFORE interaction (CEI)
    _giveToken(destinationAddress, amount); // ERC777 transfer
    return amount;
}

function _giveToken(address to, uint256 amount) internal {
    IERC20(token).safeTransfer(to, amount);
}
```

Flow accounting (`_addFlowIn`) is performed before the external ERC777 transfer, and `nonReentrant` prevents reentrant calls from executing while state is inconsistent.

### Task to Perform
Apply each detection check above to every contract function provided. Report only concrete instances of this vulnerability class, citing the specific check that failed and the offending lines.

### Output Format
If NO concrete vulnerability found, output a empty array
