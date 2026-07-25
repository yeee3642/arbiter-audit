# Accounting Error

## Detection prompt

You are a smart contract auditor. After reading the following vulnerability knowledge and detection checks, examine the contract code for this specific class of issue.

### Vulnerability Knowledge

**Accounting Error**
Accounting errors occur when on-chain state diverges from the real economic state of assets. Common root causes include: (1) trusting external token transfers without verifying the actual balance delta, which fails for fee-on-transfer, rebasing, or non-standard ERC20s; (2) updating internal ledgers before or after external calls in the wrong order, enabling reentrancy or double-counting; (3) using stale or uninitialized accumulators (e.g., reward per-token indexes) when totalSupply is zero, so the first depositor captures unearned rewards; (4) applying formulas that mix incompatible units (price vs. share scaling, missing conversion hops) or that omit the portion of a strategy gain that exceeds its debt limit; (5) forgetting to decrement counters such as totalSupply on burn, or skipping updates to lastUpdated timestamps, leaving baselines stale. These patterns produce share/fee/reward misallocations, asset theft via approval reuse, and invariant violations that can be exploited for profit.

### Detection Checks

1. Verify every external ERC20 transfer (transfer, transferFrom, safeTransfer, safeTransferFrom) is followed by a balanceOf delta check or uses a pull-payment pattern; flag direct calls that assume the requested amount equals the received amount.
2. Ensure reward/fee accumulators (rewardsPerToken, feeIndex, etc.) update their lastUpdated timestamp even when totalSupply == 0, or explicitly revert/skip distribution until after the first deposit initializes the baseline.
3. Confirm that burn/mint functions symmetrically update totalSupply and any per-account or global counters; look for _burn/_mint without matching totalSupply--/++.
4. Check that strategy harvest or vault sync functions credit only the net profit above the strategy's debt/limit, not the full balance delta (_after - _before).
5. Validate that price oracles return values in the expected unit (e.g., WETH not stETH) by tracing conversion hops (wstETH -> stETH -> WETH via Curve) and ensuring the final scaling matches the consumer's denominator.
6. Inspect performance-fee formulas for unit consistency: the fee should be (priceLossPerShare * totalShares) * feeRate, not (priceLoss * feeRate * totalShares) / scalingConstant where priceLoss is already scaled.
7. Detect deploy/factory functions that accept arbitrary token addresses without validating they are not fee-on-transfer or rebasing tokens (e.g., missing isFeeOnTransfer/ isRebasing checks or try/catch balance probes).
8. Flag liquidity-add routines that read raw contract balances (balanceOf(address(this))) and pass them directly to a pool's add_liquidity without proportionally scaling to the pool's target ratios or verifying minLPOut.

### Examples

#### Example 1: Incorrect Example

```solidity
function harvestStrategy(address _strategy) external {
    uint256 before = IStrategy(_strategy).balanceOf();
    IStrategy(_strategy).harvest();
    uint256 after = IStrategy(_strategy).balanceOf();
    // BUG: credits the entire balance increase, even the part that exceeds the strategy's debt limit
    vaultDetails[_vaultStrategies[_strategy]].balance += after - before;
}
```

The vault credits the full strategy balance delta instead of only the profit above the strategy's allocated debt, overstating vault assets when the strategy grows beyond its limit.

#### Example 2: Correct Example

```solidity
function harvestStrategy(address _strategy) external {
    uint256 before = IStrategy(_strategy).balanceOf();
    IStrategy(_strategy).harvest();
    uint256 after = IStrategy(_strategy).balanceOf();
    uint256 debt = strategyDebt[_strategy];
    uint256 profit = after > debt ? after - debt : 0;
    vaultDetails[_vaultStrategies[_strategy]].balance += profit;
    strategyDebt[_strategy] = after; // update debt to new balance
}
```

Only the excess over the strategy's recorded debt is credited to the vault, and the debt is updated to the new balance, keeping accounting consistent.

### Task to Perform
Apply each detection check above to every contract function provided. Report only concrete instances of this vulnerability class, citing the specific check that failed and the offending lines.

### Output Format
If NO concrete vulnerability found, output a empty array
