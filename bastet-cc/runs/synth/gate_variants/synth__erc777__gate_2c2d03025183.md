# ERC777-Callback-Reentrancy

## Detection prompt

You are a smart contract auditor. After reading the following vulnerability knowledge and detection checks, examine the contract code for this specific class of issue.

### Vulnerability Knowledge

**ERC777-Callback-Reentrancy**
ERC777 tokens implement `tokensReceived` and `tokensToSend` hooks that execute arbitrary external code during `transfer`, `send`, or `operatorSend` calls. If a contract performs sensitive state updates (balance accounting, debt reduction, storage cleanup) *before* the external call, a malicious hook can reenter the same or a related function and observe stale state, leading to inflated received amounts, double-spending, or permanent asset lockup. The Checks-Effects-Interactions pattern must be strictly followed: all state changes (effects) must complete before any external call (interaction) that can trigger an ERC777 hook. Additionally, reverts inside a hook (e.g., `tokensReceived`) can DoS the caller if the caller does not anticipate or handle the revert, such as when settling payments before removing rental records.

### Detection Checks

1. State variables (balances, debts, mappings) are updated *after* an external `safeTransferFrom`, `transfer`, `send`, `operatorSend`, or low-level `call` that may invoke an ERC777 hook.
2. Received amount is calculated as `balanceAfter - balanceBefore` around a token transfer that can trigger `tokensToSend`/`tokensReceived`, allowing reentrancy to manipulate the balance delta.
3. A `nonReentrant` modifier is missing on functions that perform token transfers and subsequent state updates, or the modifier does not cover cross-function reentrancy paths (e.g., `swap` -> `withdrawReserves`).
4. External calls that transfer ERC777 tokens (e.g., `ESCRW.settlePayment`, `_safeTransfer`, `_reclaimRentedItems`) occur *before* critical storage cleanup (`STORE.removeRentals`, debt clearing), so a hook revert prevents the cleanup and locks assets.
5. Hook validation (`STORE.hookOnStop`) is performed but there is no mechanism to disable or finalize hooks after rental creation, causing a revert if a previously approved hook is later disabled.
6. Try/catch around hook calls (`IHook(target).onStop`) catches reverts but the surrounding function still reverts on hook failure, propagating the DoS to the caller.
7. Token transfers use `safeTransferFrom`/`safeTransfer` without ensuring the recipient is not a malicious ERC777 contract that can reenter via hooks.
8. Balance snapshots for accounting are taken immediately before the transfer, but the transfer itself can reenter and change the balance before the snapshot delta is computed.

### Examples

#### Example 1: Incorrect Example

```solidity
function repayLoan(ERC20 token_, uint256 amount_) external {
    if (reserveDebt[token_][msg.sender] == 0) revert NoDebt();
    uint256 prevBalance = token_.balanceOf(address(this));
    token_.safeTransferFrom(msg.sender, address(this), amount_);
    uint256 received = token_.balanceOf(address(this)) - prevBalance;
    reserveDebt[token_][msg.sender] -= received;
    totalDebt[token_] -= received;
    emit DebtRepaid(token_, msg.sender, received);
}
```

Balance delta measured around `safeTransferFrom` lets an ERC777 `tokensToSend` hook reenter `swap` -> `withdrawReserves`, altering the contract's token balance and inflating `received`.

#### Example 2: Correct Example

```solidity
function repayLoan(ERC20 token_, uint256 amount_) external nonReentrant {
    if (reserveDebt[token_][msg.sender] == 0) revert NoDebt();
    token_.safeTransferFrom(msg.sender, address(this), amount_);
    uint256 received = amount_; // trust the requested amount or use a pull-payment pattern
    reserveDebt[token_][msg.sender] -= received;
    totalDebt[token_] -= received;
    emit DebtRepaid(token_, msg.sender, received);
}
```

State updates use the trusted `amount_` parameter instead of a post-transfer balance delta, and `nonReentrant` prevents cross-function reentrancy.

### Task to Perform
Apply each detection check above to every contract function provided. Report only concrete instances of this vulnerability class, citing the specific check that failed and the offending lines.

### Output Format
If NO concrete vulnerability found, output a empty array
