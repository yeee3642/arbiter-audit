# Accounting Error

## Detection prompt

You are a smart contract auditor. After reading the following vulnerability knowledge and detection checks, examine the contract code for this specific class of issue.

### Vulnerability Knowledge

**Accounting Error**
Accounting errors occur when a protocol's internal state diverges from the actual on-chain reality of asset balances, token mechanics, or cross-module invariants. Common root causes include: (1) assuming transfer amounts equal requested amounts without verifying post-transfer balances, which breaks for fee-on-transfer, rebasing, or burn-on-transfer tokens; (2) updating state variables before or without confirming external calls succeeded, creating state-update inconsistencies; (3) using stale or unvalidated parameters (e.g., prices, totalsupply, timestamps) in reward/fee/share calculations; (4) omitting synchronization steps when assets move across modules (vault-strategy, escrow-settlement, lock-execute); and (5) applying incorrect formulas that mint/burn shares based on total supply instead of profit deltas, or that ignore conversion rates between wrapped/base assets. These flaws let attackers drain value, brick accounting, or cause silent loss of funds.

### Detection Checks

1. Verify every ERC20 transferFrom/burnFrom/mint is followed by a balanceOf delta check (post - pre >= expected) instead of trusting the input amount.
2. Ensure state variables (totalSupply, balances, highWaterMarks, lastUpdated) are updated atomically with the external interaction that changes the underlying asset, not before or after in a separate transaction.
3. Confirm reward/fee accrual functions update timestamp/accumulator baselines (e.g., rewardsPerToken.lastUpdated) even on early returns when totalSupply == 0 or period not started.
4. Check that price oracles return values in the expected unit (e.g., WETH vs stETH) and that conversion hops (Curve, Uniswap) are applied before using the price in accounting.
5. Validate that performance/management fee formulas mint shares proportional to (newPrice - highWaterMark) * performanceFee / DENOMINATOR, not to totalSupply * priceFactor.
6. Ensure vault/strategy harvest functions credit only the profit portion (after - before - debtLimit) to the vault balance, not the full strategy balance delta.
7. Confirm burn/destroy functions decrement all supply trackers (totalSupply, circulatingSupply, shares) in the same execution context as the token burn.
8. Verify liquidity additions compute and enforce ideal token ratios matching the target pool (e.g., Curve 3pool proportions) instead of depositing raw contract balances.

### Examples

#### Example 1: Incorrect Example

```solidity
function _burnTokenFrom(address sender, string memory symbol, uint256 amount) internal {
    address token = tokenAddresses(symbol);
    bool ok = IERC20(token).transferFrom(sender, address(this), amount);
    require(ok, "BurnFailed");
    // No balance delta verification — fee-on-transfer tokens credit less than `amount`
}
```

The function trusts the requested `amount` was received, but fee-on-transfer tokens deliver less, causing the protocol's internal accounting to overstate holdings.

#### Example 2: Correct Example

```solidity
function _burnTokenFrom(address sender, string memory symbol, uint256 amount) internal {
    address token = tokenAddresses(symbol);
    uint256 before = IERC20(token).balanceOf(address(this));
    bool ok = IERC20(token).transferFrom(sender, address(this), amount);
    require(ok, "BurnFailed");
    uint256 received = IERC20(token).balanceOf(address(this)) - before;
    require(received >= amount, "FeeOnTransferNotSupported");
    // Or adjust accounting by `received` instead of `amount`
}
```

Measuring the actual balance increase after transfer ensures accounting matches on-chain reality for any token type.

### Task to Perform
Apply each detection check above to every contract function provided. Report only concrete instances of this vulnerability class, citing the specific check that failed and the offending lines.

### Output Format
If NO concrete vulnerability found, output a empty array
