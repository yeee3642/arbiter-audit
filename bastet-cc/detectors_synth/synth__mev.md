---
id: synth__mev
name: "MEV-FrontRunAndOrderingDependency"
source_workflow: synthesized
upstream_model: ais3/nemotron-3-ultra-550b
tags: ["MEV"]
routing_hints: ["deadline", "minAmountOut", "swap", "collect", "liquidity", "tokensOwed0", "tokensOwed1", "slot0", "tickLower", "tickUpper", "withdrawApproval", "b"]
required_hints: []
prompt_chars: 4887
synthesized: true
gated: false
synth_provenance: {"train_findings": ["37", "363", "171", "242", "57", "29"], "localization_rate": 1.0, "mode": "s2", "hint_candidates": 30, "hints_rejected": 20, "hint_coverage": 0.833, "single_repo_hints": false, "hint_fallback": false, "loro": {"hit": 0.6, "fp": 0.1, "folds": 5, "repaired": false}}
---

# MEV-FrontRunAndOrderingDependency

## Detection prompt

You are a smart contract auditor. After reading the following vulnerability knowledge and detection checks, examine the contract code for this specific class of issue.

### Vulnerability Knowledge

**MEV-FrontRunAndOrderingDependency**
MEV vulnerabilities arise when a contract's outcome depends on the relative ordering of transactions within a block, allowing block producers or searchers to extract value by front-running, back-running, or sandwiching user transactions. Common patterns include: (1) state checks and updates separated by external calls or non-atomic operations, creating a window where an attacker can observe the pending state and act first; (2) user-supplied parameters (output token, slippage, deadline) that are not validated against on-chain state at the moment of execution; (3) approval or limit decrements performed after the validation check, so a front-runner can consume the higher limit; (4) TVL or price calculations that omit components like uncollected fees, enabling manipulation of share pricing; (5) invariant boundaries that create sharp cliffs, incentivizing liquidity positioning just below the threshold. Auditors should look for read-then-write sequences without reentrancy guards, missing slippage/deadline enforcement, balance checks before rather than after external calls, and any logic where an attacker benefits from predicting the exact state transition.

### Detection Checks

1. Function reads a storage variable (e.g., approval limit, config flag, TVL component) and later writes a dependent state change without re-verifying the value immediately before the write.
2. External call (token transfer, controller withdraw, router swap) occurs between a balance/limit check and the corresponding state update, allowing the external contract to alter balances or state.
3. User-supplied output token or swap path is not validated against the contract's actual holdings or allowed list before funds are moved.
4. Slippage protection (amountOutMin, amountRemoveMin) or deadline parameter is missing, hardcoded to max, or not enforced against a fresh oracle/TWAP reading.
5. Approval or withdrawal limit is decremented after the amount check rather than atomically with it, enabling a front-run at the higher limit.
6. TVL, price, or invariant calculation omits uncollected fees, pending rewards, or strategy balances, creating a discrepancy between reported and realizable value.
7. Configuration flags (e.g., onlyFees) are read from storage at execution time without binding them to the user's signed parameters or a committed snapshot.
8. Contract silently accepts a shortfall from an external withdrawal or swap (reduces user amount instead of reverting), allowing the protocol to settle with less than owed.

### Examples

#### Example 1: Incorrect Example

```solidity
function withdraw(uint256 shares, address output) external {
    uint256 amount = (totalAssets() * shares) / totalSupply();
    _burn(msg.sender, shares);
    uint256 bal = IERC20(output).balanceOf(address(this));
    if (bal < amount) {
        IController(controller).withdraw(output, amount - bal);
        uint256 after = IERC20(output).balanceOf(address(this));
        if (after - bal < amount - bal) amount = after; // silent shortfall
    }
    IERC20(output).safeTransfer(msg.sender, amount);
}
```

The function burns shares before ensuring the output token is available, does not verify the controller actually sent the requested amount, and silently reduces the user's payout if the external withdrawal falls short, enabling front-running and value extraction.

#### Example 2: Correct Example

```solidity
function withdraw(uint256 shares, address output, uint256 minAmount, uint256 deadline) external {
    require(block.timestamp <= deadline, "expired");
    require(supportedOutputs[output], "unsupported token");
    uint256 amount = (totalAssets() * shares) / totalSupply();
    require(amount >= minAmount, "slippage");
    uint256 balBefore = IERC20(output).balanceOf(address(this));
    if (balBefore < amount) {
        IController(controller).withdraw(output, amount - balBefore);
        uint256 balAfter = IERC20(output).balanceOf(address(this));
        require(balAfter - balBefore >= amount - balBefore, "withdrawal failed");
    }
    _burn(msg.sender, shares);
    IERC20(output).safeTransfer(msg.sender, amount);
}
```

The fix enforces a deadline and slippage floor, validates the output token, verifies the external withdrawal delivers the exact shortfall before burning shares, and reverts on any shortfall instead of silently accepting less.

### Task to Perform
Apply each detection check above to every contract function provided. Report only concrete instances of this vulnerability class, citing the specific check that failed and the offending lines.

### Output Format
If NO concrete vulnerability found, output a empty array
