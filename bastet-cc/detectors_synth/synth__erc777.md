---
id: synth__erc777
name: "ERC777-Callback-Reentrancy"
source_workflow: synthesized
upstream_model: ais3/nemotron-3-ultra-550b
tags: ["ERC777"]
routing_hints: ["tokensReceived", "rentalWallet", "_giveToken", "commandId"]
required_hints: []
prompt_chars: 4335
synthesized: true
gated: true
synth_provenance: {"train_findings": ["190", "289", "286", "475", "287", "476"], "localization_rate": 1.0, "mode": "s2", "hint_candidates": 29, "hints_rejected": 29, "hint_coverage": 0.833, "single_repo_hints": false, "hint_fallback": false, "loro": {"hit": 0.0, "fp": 0.167, "folds": 3, "repaired": true}}
---

# ERC777-Callback-Reentrancy

## Detection prompt

You are a smart contract auditor. After reading the following vulnerability knowledge and detection checks, examine the contract code for this specific class of issue.

### Vulnerability Knowledge

**ERC777-Callback-Reentrancy**
ERC777 tokens implement `tokensReceived` and `tokensToSend` hooks that execute arbitrary recipient code during `transfer`, `send`, and `operatorSend`. If a contract performs sensitive state updates (accounting, debt reduction, flow recording, rental cleanup) *after* an external ERC777 transfer, a malicious recipient can re-enter the same or a related function and observe stale state, leading to inflated received amounts, double payouts, or permanent asset lockup. The Checks-Effects-Interactions pattern requires all state changes to complete *before* any external call that may trigger a hook. Additionally, reverts inside a hook (e.g., a disabled hook check) can DoS the caller if the protocol lacks a hook-disable mechanism or try/catch handling.

### Detection Checks

1. External ERC777 transfer (`safeTransferFrom`, `transfer`, `send`, `operatorSend`, or wrapper `_giveToken`/`_transferFromExecutor`) occurs before state updates such as balance accounting, debt reduction, flow addition, or rental removal.
2. Received amount is calculated by `balanceOf(address(this)) - prevBalance` after a transfer, which an ERC777 `tokensToSend` hook can manipulate by re-entering a withdrawal or swap that changes the contract balance mid-execution.
3. Virtual or unprotected internal function (`_executeWithToken`, `_removeHooks`, settlement logic) is called after token transfers, allowing cross-function reentrancy into the same entry point or a related function that pays out again.
4. Hook invocation (`onStop`, `tokensReceived` via transfer) lacks try/catch or a disable mechanism; a revert in the hook bubbles up and locks assets or prevents cleanup (e.g., `STORE.removeRentals` never reached).
5. Missing `nonReentrant` modifier on functions that perform external ERC777 transfers followed by state changes, or the modifier is present but the transfer precedes the state change (CEI violation).
6. Protocol uses `safeTransferFrom`/`_safeTransfer` on an address that may implement ERC777 without verifying `IERC777Recipient` support or guarding against reentrancy via a mutex/state flag.
7. Flow limit or rental accounting (`_addFlowIn`, `reserveDebt` decrement, `STORE.removeRentals`) is placed after the token transfer instead of before.
8. Escrow settlement (`ESCRW.settlePayment`) or similar payout occurs before rental/storage cleanup, enabling a malicious recipient to revert in `tokensReceived` and permanently block the cleanup.

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

Transfer precedes debt accounting; an ERC777 tokensToSend hook can re-enter a withdrawal that alters the contract balance, inflating `received` and understating the borrower's debt.

#### Example 2: Correct Example

```solidity
function repayLoan(ERC20 token_, uint256 amount_) external nonReentrant {
    if (reserveDebt[token_][msg.sender] == 0) revert NoDebt();
    token_.safeTransferFrom(msg.sender, address(this), amount_);
    uint256 received = amount_; // or use balance delta with reentrancy guard
    reserveDebt[token_][msg.sender] -= received;
    totalDebt[token_] -= received;
    emit DebtRepaid(token_, msg.sender, received);
}
```

State updates (debt reduction) use the trusted `amount_` parameter instead of a post-transfer balance delta, eliminating the reentrancy window; `nonReentrant` guards cross-function reentry.

### Task to Perform
Apply each detection check above to every contract function provided. Report only concrete instances of this vulnerability class, citing the specific check that failed and the offending lines.

### Output Format
If NO concrete vulnerability found, output a empty array
